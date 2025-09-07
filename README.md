# Dozlab Terminal Sidecar

WebSocket-based terminal service that provides browser-accessible terminals for lab environments.

## Features

- **WebSocket Terminal**: Real-time terminal access through web browsers
- **SSH Integration**: Connects to lab VMs via SSH
- **PTY Support**: Full pseudo-terminal support with proper sizing
- **Session Management**: Handles multiple concurrent terminal sessions
- **Auto-discovery**: Automatically discovers VM IPs from shared configuration

## Tech Stack

- **Language**: Go 1.21
- **Web Framework**: Gin
- **WebSocket**: gorilla/websocket
- **SSH**: golang.org/x/crypto/ssh
- **PTY**: github.com/creack/pty

## Architecture

The sidecar acts as a bridge between web browsers and lab VMs:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │────│ Terminal Sidecar│────│    Lab VM       │
│                 │    │                 │    │                 │
│ • WebSocket     │    │ • WebSocket     │    │ • SSH Server    │
│ • Terminal UI   │    │ • SSH Client    │    │ • Shell/Bash    │
│ • Keyboard      │    │ • PTY Bridge    │    │ • User Session  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                        │                        │
        │                        │                        │
        ▼                        ▼                        ▼
   HTTP/WebSocket           Shared Volume              SSH Protocol
   (Port 8081)              Network Config              (Port 22)
```

## Configuration

Environment variables:

```bash
# Server settings
PORT=8081
GIN_MODE=release

# SSH configuration
SSH_USER=dozlab
SSH_PORT=22
SSH_TIMEOUT=30s

# Network discovery
NETWORK_CONFIG_PATH=/shared/network-config
VM_IP_FILE=/shared/vm-ip

# WebSocket settings
WS_READ_BUFFER_SIZE=1024
WS_WRITE_BUFFER_SIZE=1024
WS_HANDSHAKE_TIMEOUT=10s
```

## Getting Started

### Prerequisites

- Go 1.21+
- Access to target SSH server/VM

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd dozlab-terminal-sidecar
```

2. Install dependencies:
```bash
go mod tidy
```

3. Build the service:
```bash
go build -o terminal-sidecar main.go
```

4. Run the service:
```bash
./terminal-sidecar
```

The service will start on port 8081.

### Docker

```bash
# Build image
docker build -t dozlab-terminal-sidecar .

# Run container
docker run -p 8081:8081 \
  -v /shared/network-config:/shared/network-config:ro \
  dozlab-terminal-sidecar
```

## API Endpoints

### WebSocket Terminal

**Endpoint**: `GET /terminal/ws`

**Query Parameters**:
- `sessionId` - Lab session identifier
- `cols` - Terminal columns (default: 80)
- `rows` - Terminal rows (default: 24)

**Usage**:
```javascript
const ws = new WebSocket('ws://localhost:8081/terminal/ws?sessionId=123&cols=120&rows=30');

ws.onopen = function() {
    console.log('Terminal connected');
};

ws.onmessage = function(event) {
    // Display terminal output
    terminalElement.innerHTML += event.data;
};

// Send keyboard input
ws.send(JSON.stringify({
    type: 'input',
    data: 'ls -la\n'
}));

// Resize terminal
ws.send(JSON.stringify({
    type: 'resize',
    cols: 120,
    rows: 40
}));
```

### Health Check

**Endpoint**: `GET /health`

Returns service health status and SSH connectivity.

### Terminal Status

**Endpoint**: `GET /terminal/status`

Returns information about active terminal sessions.

## Message Protocol

### Client to Server

**Input Message**:
```json
{
    "type": "input",
    "data": "command\n"
}
```

**Resize Message**:
```json
{
    "type": "resize",
    "cols": 120,
    "rows": 40
}
```

### Server to Client

**Output Message**:
```json
{
    "type": "output",
    "data": "terminal output text"
}
```

**Error Message**:
```json
{
    "type": "error",
    "message": "Connection failed"
}
```

## Network Discovery

The sidecar automatically discovers VM connection details:

### Shared Volume Method
```bash
# Reads VM IP from shared file
cat /shared/network-config
```

### Environment Variables
```bash
# Direct VM IP configuration
VM_IP=192.168.1.100
VM_SSH_PORT=22
```

## Development

### Project Structure

```
├── main.go              # Service entry point
├── handlers/            # HTTP/WebSocket handlers
├── ssh/                # SSH client logic
├── terminal/           # PTY and terminal handling
├── config/             # Configuration management
├── Dockerfile          # Container build
└── go.mod             # Go modules
```

### Building

```bash
# Development build
go build -o terminal-sidecar main.go

# Production build with optimizations
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o terminal-sidecar main.go
```

### Testing

```bash
# Unit tests
go test ./...

# Integration tests (requires SSH server)
go test -tags=integration ./...

# Load testing
go test -bench=. ./...
```

## Deployment

### Kubernetes Sidecar

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: terminal-sidecar
    image: dozlab/terminal-sidecar:latest
    ports:
    - containerPort: 8081
    env:
    - name: SSH_USER
      value: "dozlab"
    - name: NETWORK_CONFIG_PATH
      value: "/shared/network-config"
    volumeMounts:
    - name: shared-config
      mountPath: /shared
      readOnly: true
  - name: lab-vm
    # Main lab container
  volumes:
  - name: shared-config
    emptyDir: {}
```

### Docker Compose

```yaml
version: '3.8'
services:
  terminal-sidecar:
    build: .
    ports:
      - "8081:8081"
    environment:
      - SSH_USER=dozlab
      - VM_IP=lab-vm
    depends_on:
      - lab-vm
    volumes:
      - shared-config:/shared

  lab-vm:
    # Lab VM container configuration

volumes:
  shared-config:
```

## Security

### SSH Authentication

The sidecar supports multiple SSH authentication methods:

1. **Key-based**: Uses SSH private keys
2. **Password**: Uses shared passwords
3. **Agent**: Uses SSH agent forwarding

### Configuration

```bash
# SSH key authentication
SSH_PRIVATE_KEY_PATH=/etc/ssh/id_rsa

# Password authentication
SSH_PASSWORD=secure-password

# SSH agent
SSH_AUTH_SOCK=/ssh-agent
```

## Performance

### Optimization Settings

```bash
# Buffer sizes
WS_READ_BUFFER_SIZE=4096
WS_WRITE_BUFFER_SIZE=4096

# Connection pooling
SSH_POOL_SIZE=10
SSH_POOL_TIMEOUT=5m

# Terminal settings
TERMINAL_BUFFER_SIZE=8192
```

### Monitoring

Key metrics exposed:

- Active WebSocket connections
- SSH connection status
- Terminal session count
- Data throughput
- Error rates

## Troubleshooting

### Common Issues

1. **WebSocket Connection Failed**:
```bash
# Check if service is running
curl http://localhost:8081/health

# Check WebSocket endpoint
wscat -c ws://localhost:8081/terminal/ws?sessionId=test
```

2. **SSH Connection Failed**:
```bash
# Test SSH connectivity
ssh dozlab@vm-ip

# Check SSH configuration
cat /shared/network-config
```

3. **Terminal Not Responsive**:
```bash
# Check PTY settings
stty -a

# Verify terminal size
echo $COLUMNS $LINES
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

[Add your license here]