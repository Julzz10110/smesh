package discovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client represents a client for discovery API
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new discovery client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Register registers a service via HTTP API
func (c *Client) Register(service *ServiceInfo) error {
	data, err := json.Marshal(service)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(c.baseURL+"/register", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to register: status %d", resp.StatusCode)
	}

	return nil
}

// Deregister removes a service via HTTP API
func (c *Client) Deregister(serviceName, address string) error {
	req := map[string]string{
		"service_name": serviceName,
		"address":      address,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(c.baseURL+"/deregister", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to deregister: status %d", resp.StatusCode)
	}

	return nil
}

// UpdateHealth updates health status via HTTP API
func (c *Client) UpdateHealth(serviceName, address string, healthy bool) error {
	req := map[string]interface{}{
		"service_name": serviceName,
		"address":      address,
		"healthy":      healthy,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(c.baseURL+"/health", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update health: status %d", resp.StatusCode)
	}

	return nil
}

// GetServices gets list of services via HTTP API
func (c *Client) GetServices(serviceName string) ([]*ServiceInfo, error) {
	url := c.baseURL + "/services"
	if serviceName != "" {
		url += "?name=" + serviceName
	}

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get services: status %d", resp.StatusCode)
	}

	var services []*ServiceInfo
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		return nil, err
	}

	return services, nil
}

// GetAllServices gets all services via HTTP API
func (c *Client) GetAllServices() (map[string][]*ServiceInfo, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/services")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get services: status %d", resp.StatusCode)
	}

	var services map[string][]*ServiceInfo
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		return nil, err
	}

	return services, nil
}
