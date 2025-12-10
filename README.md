# SMesh - Service Mesh with mTLS

Lightweight service mesh for internal traffic with automatic mTLS.

## Features

- ✅ Automatic TLS certificate generation and rotation (built-in CA)
- ✅ Sidecar proxy based on net/http and crypto/tls
- ✅ Service Discovery via consensus (Raft)
- ✅ Load Balancing with health checks

## Quick Start

### 1. Start CA Server

```bash
go run cmd/ca/main.go --port :8443
```

### 2. Start Service Discovery (Raft)

```bash
# Node 1
go run cmd/discovery/main.go --node-id node1 --bind :12000 --raft-dir ./raft1 --http-port :12001

# Node 2
go run cmd/discovery/main.go --node-id node2 --bind :12002 --raft-dir ./raft2 --http-port :12003 --join localhost:12000
```

### 3. Start Sidecar Proxy

```bash
go run cmd/proxy/main.go --service-name service1 --port :8080 --ca-url http://localhost:8443 --discovery-addr http://localhost:12001
```