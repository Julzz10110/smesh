package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	boltstore "github.com/hashicorp/raft-boltdb"
)

// ServiceInfo contains service information
type ServiceInfo struct {
	Name     string            `json:"name"`
	Address  string            `json:"address"`
	Port     int               `json:"port"`
	Healthy  bool              `json:"healthy"`
	LastSeen time.Time         `json:"last_seen"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Discovery manages service discovery via Raft
type Discovery struct {
	raft      *raft.Raft
	services  map[string][]*ServiceInfo
	server    *http.Server
	mu        sync.RWMutex
	transport *raft.NetworkTransport
}

// NewDiscovery creates a new Discovery with Raft
func NewDiscovery(nodeID, bindAddr, raftDir string) (*Discovery, error) {
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(nodeID)

	// If bindAddr starts with ':', add localhost for advertisable address
	advertiseAddr := bindAddr
	if len(bindAddr) > 0 && bindAddr[0] == ':' {
		advertiseAddr = "localhost" + bindAddr
	}

	// Create transport
	advertiseTCPAddr, err := net.ResolveTCPAddr("tcp", advertiseAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve advertise address: %w", err)
	}

	transport, err := raft.NewTCPTransport(bindAddr, advertiseTCPAddr, 3, 10*time.Second, io.Discard)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}

	// Create log store
	logStore, err := boltstore.NewBoltStore(raftDir + "/raft.db")
	if err != nil {
		return nil, fmt.Errorf("failed to create log store: %w", err)
	}

	// Create stable store
	stableStore, err := boltstore.NewBoltStore(raftDir + "/stable.db")
	if err != nil {
		return nil, fmt.Errorf("failed to create stable store: %w", err)
	}

	// Create snapshot store
	snapshotStore, err := raft.NewFileSnapshotStore(raftDir, 2, io.Discard)
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot store: %w", err)
	}

	// Create FSM
	fsm := &discoveryFSM{
		services: make(map[string][]*ServiceInfo),
	}

	// Create Raft
	r, err := raft.NewRaft(config, fsm, logStore, stableStore, snapshotStore, transport)
	if err != nil {
		return nil, fmt.Errorf("failed to create raft: %w", err)
	}

	// If this is the first node, bootstrap the cluster
	if r.Leader() == "" {
		configuration := raft.Configuration{
			Servers: []raft.Server{
				{
					ID:      config.LocalID,
					Address: raft.ServerAddress(advertiseAddr),
				},
			},
		}
		r.BootstrapCluster(configuration)
	}

	d := &Discovery{
		raft:      r,
		services:  make(map[string][]*ServiceInfo),
		transport: transport,
	}

	// Save reference to FSM for data access
	fsm.discovery = d

	return d, nil
}

// Join joins a node to the cluster
func (d *Discovery) Join(nodeID, addr string) error {
	if d.raft.State() != raft.Leader {
		return fmt.Errorf("not the leader")
	}

	configFuture := d.raft.GetConfiguration()
	if err := configFuture.Error(); err != nil {
		return fmt.Errorf("failed to get raft configuration: %w", err)
	}

	for _, srv := range configFuture.Configuration().Servers {
		if srv.ID == raft.ServerID(nodeID) || srv.Address == raft.ServerAddress(addr) {
			return nil // already in cluster
		}
	}

	f := d.raft.AddVoter(raft.ServerID(nodeID), raft.ServerAddress(addr), 0, 0)
	if f.Error() != nil {
		return f.Error()
	}

	return nil
}

// Register registers a service
func (d *Discovery) Register(service *ServiceInfo) error {
	if d.raft.State() != raft.Leader {
		leader := d.raft.Leader()
		return fmt.Errorf("not the leader, leader is: %s", leader)
	}

	service.LastSeen = time.Now()
	cmd := &Command{
		Op:      OpRegister,
		Service: service,
	}

	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	f := d.raft.Apply(data, 10*time.Second)
	return f.Error()
}

// Deregister removes a service
func (d *Discovery) Deregister(serviceName, address string) error {
	if d.raft.State() != raft.Leader {
		leader := d.raft.Leader()
		return fmt.Errorf("not the leader, leader is: %s", leader)
	}

	cmd := &Command{
		Op:          OpDeregister,
		ServiceName: serviceName,
		Address:     address,
	}

	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	f := d.raft.Apply(data, 10*time.Second)
	return f.Error()
}

// UpdateHealth updates service health status
func (d *Discovery) UpdateHealth(serviceName, address string, healthy bool) error {
	if d.raft.State() != raft.Leader {
		leader := d.raft.Leader()
		return fmt.Errorf("not the leader, leader is: %s", leader)
	}

	cmd := &Command{
		Op:          OpUpdateHealth,
		ServiceName: serviceName,
		Address:     address,
		Healthy:     healthy,
	}

	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	f := d.raft.Apply(data, 10*time.Second)
	return f.Error()
}

// GetServices returns list of services by name
func (d *Discovery) GetServices(serviceName string) []*ServiceInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	services, exists := d.services[serviceName]
	if !exists {
		return []*ServiceInfo{}
	}

	// Filter only healthy services
	healthy := make([]*ServiceInfo, 0)
	for _, s := range services {
		if s.Healthy {
			healthy = append(healthy, s)
		}
	}

	return healthy
}

// GetAllServices returns all services
func (d *Discovery) GetAllServices() map[string][]*ServiceInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[string][]*ServiceInfo)
	for k, v := range d.services {
		result[k] = make([]*ServiceInfo, len(v))
		copy(result[k], v)
	}
	return result
}

// IsLeader checks if the node is the leader
func (d *Discovery) IsLeader() bool {
	return d.raft.State() == raft.Leader
}

// Leader returns the leader address
func (d *Discovery) Leader() string {
	return string(d.raft.Leader())
}

// Command represents a command for FSM
type Command struct {
	Op          Operation    `json:"op"`
	Service     *ServiceInfo `json:"service,omitempty"`
	ServiceName string       `json:"service_name,omitempty"`
	Address     string       `json:"address,omitempty"`
	Healthy     bool         `json:"healthy,omitempty"`
}

// Operation represents operation type
type Operation string

const (
	OpRegister     Operation = "register"
	OpDeregister   Operation = "deregister"
	OpUpdateHealth Operation = "update_health"
)

// discoveryFSM implements FSM for Raft
type discoveryFSM struct {
	services  map[string][]*ServiceInfo
	mu        sync.RWMutex
	discovery *Discovery
}

// Apply applies a command
func (f *discoveryFSM) Apply(l *raft.Log) interface{} {
	var cmd Command
	if err := json.Unmarshal(l.Data, &cmd); err != nil {
		return fmt.Errorf("failed to unmarshal command: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	switch cmd.Op {
	case OpRegister:
		// Remove existing service with the same address
		services := f.services[cmd.Service.Name]
		newServices := make([]*ServiceInfo, 0)
		for _, s := range services {
			if s.Address != cmd.Service.Address {
				newServices = append(newServices, s)
			}
		}
		newServices = append(newServices, cmd.Service)
		f.services[cmd.Service.Name] = newServices

		// Update in discovery
		if f.discovery != nil {
			f.discovery.mu.Lock()
			f.discovery.services[cmd.Service.Name] = newServices
			f.discovery.mu.Unlock()
		}

	case OpDeregister:
		services := f.services[cmd.ServiceName]
		newServices := make([]*ServiceInfo, 0)
		for _, s := range services {
			if s.Address != cmd.Address {
				newServices = append(newServices, s)
			}
		}
		f.services[cmd.ServiceName] = newServices

		if f.discovery != nil {
			f.discovery.mu.Lock()
			f.discovery.services[cmd.ServiceName] = newServices
			f.discovery.mu.Unlock()
		}

	case OpUpdateHealth:
		services := f.services[cmd.ServiceName]
		for _, s := range services {
			if s.Address == cmd.Address {
				s.Healthy = cmd.Healthy
				s.LastSeen = time.Now()
				break
			}
		}

		if f.discovery != nil {
			f.discovery.mu.Lock()
			f.discovery.services[cmd.ServiceName] = services
			f.discovery.mu.Unlock()
		}
	}

	return nil
}

// Snapshot creates a state snapshot
func (f *discoveryFSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	snapshot := make(map[string][]*ServiceInfo)
	for k, v := range f.services {
		snapshot[k] = make([]*ServiceInfo, len(v))
		copy(snapshot[k], v)
	}

	return &discoverySnapshot{services: snapshot}, nil
}

// Restore restores state from snapshot
func (f *discoveryFSM) Restore(rc io.ReadCloser) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var snapshot map[string][]*ServiceInfo
	if err := json.NewDecoder(rc).Decode(&snapshot); err != nil {
		return err
	}

	f.services = snapshot

	// Update in discovery
	if f.discovery != nil {
		f.discovery.mu.Lock()
		f.discovery.services = snapshot
		f.discovery.mu.Unlock()
	}

	return nil
}

// discoverySnapshot represents a state snapshot
type discoverySnapshot struct {
	services map[string][]*ServiceInfo
}

// Persist saves the snapshot
func (s *discoverySnapshot) Persist(sink raft.SnapshotSink) error {
	if err := json.NewEncoder(sink).Encode(s.services); err != nil {
		sink.Cancel()
		return err
	}
	return sink.Close()
}

// Release releases resources
func (s *discoverySnapshot) Release() {}

// StartHTTPServer starts HTTP API for discovery
func (d *Discovery) StartHTTPServer(port string) error {
	mux := http.NewServeMux()

	// Service registration
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var service ServiceInfo
		if err := json.NewDecoder(r.Body).Decode(&service); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := d.Register(&service); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
	})

	// Service removal
	mux.HandleFunc("/deregister", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ServiceName string `json:"service_name"`
			Address     string `json:"address"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := d.Deregister(req.ServiceName, req.Address); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "deregistered"})
	})

	// Health update
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ServiceName string `json:"service_name"`
			Address     string `json:"address"`
			Healthy     bool   `json:"healthy"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := d.UpdateHealth(req.ServiceName, req.Address, req.Healthy); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	})

	// Get services
	mux.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		serviceName := r.URL.Query().Get("name")
		if serviceName != "" {
			services := d.GetServices(serviceName)
			json.NewEncoder(w).Encode(services)
		} else {
			allServices := d.GetAllServices()
			json.NewEncoder(w).Encode(allServices)
		}
	})

	d.server = &http.Server{
		Addr:    port,
		Handler: mux,
	}

	log.Printf("Discovery HTTP server starting on %s", port)
	return d.server.ListenAndServe()
}

// Shutdown gracefully shuts down the Discovery server
func (d *Discovery) Shutdown() error {
	if d.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown HTTP server: %w", err)
		}
	}

	// Shutdown Raft
	if d.raft != nil {
		future := d.raft.Shutdown()
		if err := future.Error(); err != nil {
			return fmt.Errorf("failed to shutdown Raft: %w", err)
		}
	}

	return nil
}
