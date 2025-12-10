# SMesh Usage Examples

## Full Stack Startup

### 1. Start CA Server

```bash
go run cmd/ca/main.go --port :8443
```

### 2. Start Service Discovery (Raft)

**Node 1 (leader):**
```bash
go run cmd/discovery/main.go --node-id node1 --bind :12000 --raft-dir ./raft1 --http-port :12001
```

**Node 2 (joins cluster):**
```bash
go run cmd/discovery/main.go --node-id node2 --bind :12002 --raft-dir ./raft2 --http-port :12003 --join localhost:12000
```

### 3. Start Simple Services

**Service 1:**
```bash
go run examples/simple_service.go service1 9001 http://localhost:12001
```

**Service 2:**
```bash
go run examples/simple_service.go service1 9002 http://localhost:12001
```

**Service 3:**
```bash
go run examples/simple_service.go service2 9003 http://localhost:12001
```

### 4. Start Sidecar Proxy

**Proxy for service1:**
```bash
go run cmd/proxy/main.go --service-name service1 --port :8080 --ca-url http://localhost:8443 --discovery-addr http://localhost:12001
```

**Proxy for service2:**
```bash
go run cmd/proxy/main.go --service-name service2 --port :8081 --ca-url http://localhost:8443 --discovery-addr http://localhost:12001
```

## Testing

### Check Service Registration

```bash
curl http://localhost:12001/services
```

### Check Health Check

```bash
curl http://localhost:9001/health
curl http://localhost:9002/health
```

### Proxy Requests Through Proxy

```bash
# Request to service1 through proxy
curl -k https://localhost:8080/proxy/service1/

# Request to service2 through proxy
curl -k https://localhost:8080/proxy/service2/
```

## Architecture

```
┌─────────────┐
│  CA Server  │ (Certificate generation)
└─────────────┘
       │
       │ mTLS certificates
       │
┌─────────────┐
│  Discovery  │ (Raft consensus)
│   (Raft)    │
└─────────────┘
       │
       │ Service registry
       │
┌─────────────┐     ┌─────────────┐
│   Proxy 1   │────▶│  Service 1  │
│ (sidecar)   │     │  (port 9001)│
└─────────────┘     └─────────────┘
       │
       │ Load balancing
       │
┌─────────────┐     ┌─────────────┐
│   Proxy 2   │────▶│  Service 2  │
│ (sidecar)   │     │  (port 9002)│
└─────────────┘     └─────────────┘
```
