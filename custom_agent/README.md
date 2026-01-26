# Wazuh Custom Agent (Go)

A lightweight custom agent written in Go that collects and sends log data to a Wazuh central management system. 

## Architecture

The agent:
1. Monitors specified log files for new entries
2. Collects system information and heartbeats
3. Formats events as JSON with metadata
4. Sends data to Wazuh manager via TCP (port 1514)

## Prerequisites

- Go 1.21 or higher (for building from source)
- Docker (optional, for containerized deployment)
- Network access to Wazuh manager on port 1514

## Configuration

Edit `config.json` to configure the agent:

```json
{
  "wazuh_manager": "your-wazuh-manager.example.com",
  "wazuh_port": 1514,
  "agent_name": "custom-go-agent",
  "poll_interval_seconds": 10,
  "log_paths": [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/apache2/*.log"
  ]
}
```

### Configuration Parameters

- **wazuh_manager**: Hostname or IP address of your Wazuh manager
- **wazuh_port**: Port number (default: 1514)
- **agent_name**: Unique identifier for this agent
- **poll_interval_seconds**: How often to check for new log entries
- **log_paths**: Array of log file paths (supports wildcards)

### Platform-Specific Log Paths

**Linux:**
```json
"log_paths": [
  "/var/log/syslog",
  "/var/log/auth.log",
  "/var/log/apache2/*.log",
  "/var/log/nginx/*.log"
]
```

**Windows:**
```json
"log_paths": [
  "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
  "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
  "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log"
]
```

## Building from Source

### Linux/macOS

```bash
# Clone or navigate to the custom_agent directory
cd custom_agent

# Build for current platform
go build -o wazuh-agent main.go

# Or use the build script for all platforms
chmod +x build.sh
./build.sh
```

### Windows

```batch
# Open PowerShell or Command Prompt
cd custom_agent

# Build for Windows
go build -o wazuh-agent.exe main.go

# Or use the build script for multiple platforms
build.bat
```

The build scripts create binaries in the `build/` directory for:
- Linux (amd64, arm64)
- Windows (amd64)
- macOS (amd64, arm64/M1)

## Deployment

### Method 1: Native Binary

1. **Build the agent** for your target OS
2. **Copy the binary** to the target system
3. **Create config.json** with your Wazuh manager details
4. **Run the agent**:

```bash
# Linux/macOS
./wazuh-agent config.json

# Windows
wazuh-agent.exe config.json
```

### Method 2: Docker Container

1. **Build the Docker image**:
```bash
docker build -t wazuh-custom-agent .
```

2. **Run with Docker Compose**:
```bash
# Edit config.json first
docker-compose up -d
```

3. **Or run with Docker directly**:
```bash
docker run -d \
  --name wazuh-agent \
  -v $(pwd)/config.json:/app/config.json:ro \
  -v /var/log:/host/var/log:ro \
  wazuh-custom-agent
```

### Method 3: Systemd Service (Linux)

1. **Copy binary to system location**:
```bash
sudo cp wazuh-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/wazuh-agent
```

2. **Create config directory**:
```bash
sudo mkdir -p /etc/wazuh-agent
sudo cp config.json /etc/wazuh-agent/
```

3. **Create systemd service file** `/etc/systemd/system/wazuh-agent.service`:
```ini
[Unit]
Description=Wazuh Custom Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/wazuh-agent /etc/wazuh-agent/config.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

4. **Enable and start the service**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```

### Method 4: Windows Service

Use a tool like [NSSM](https://nssm.cc/) to run as a Windows service:

```batch
# Download and install NSSM
nssm install WazuhAgent "C:\Program Files\WazuhAgent\wazuh-agent.exe" "C:\Program Files\WazuhAgent\config.json"
nssm start WazuhAgent
```

## Monitoring and Logs

The agent logs to stdout. View logs:

**Systemd (Linux):**
```bash
sudo journalctl -u wazuh-agent -f
```

**Docker:**
```bash
docker logs -f wazuh-agent
```

**Windows (if using NSSM):**
Check the log files in the NSSM service directory.

## Event Format

Events sent to Wazuh are JSON formatted:

```json
{
  "timestamp": "2026-01-20T10:30:45Z",
  "agent_name": "custom-go-agent",
  "hostname": "webserver-01",
  "log_file": "/var/log/auth.log",
  "message": "Failed password for invalid user admin from 192.168.1.100",
  "os": "linux",
  "metadata": {
    "num_goroutines": 10,
    "num_cpu": 4
  }
}
```

## Wazuh Manager Configuration

Ensure your Wazuh manager is configured to accept remote connections:

1. **Edit `/var/ossec/etc/ossec.conf`** on the Wazuh manager:
```xml
<ossec_config>
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>
</ossec_config>
```

2. **Restart Wazuh manager**:
```bash
sudo systemctl restart wazuh-manager
```

3. **Configure firewall** to allow port 1514:
```bash
# UFW (Ubuntu)
sudo ufw allow 1514/tcp

# Firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=1514/tcp
sudo firewall-cmd --reload
```

## Troubleshooting

### Connection Issues

**Problem**: Cannot connect to Wazuh manager

**Solutions**:
- Verify Wazuh manager hostname/IP in config.json
- Check network connectivity: `telnet <wazuh-manager> 1514`
- Ensure firewall allows port 1514
- Verify Wazuh manager is running: `systemctl status wazuh-manager`

### Log File Access

**Problem**: Permission denied when reading logs

**Solutions**:
- Run agent with appropriate permissions (root on Linux)
- Add agent user to required groups
- Adjust log file permissions if necessary

### No Data in Wazuh

**Problem**: Agent running but no data appears in Wazuh

**Solutions**:
- Check Wazuh manager logs: `/var/ossec/logs/ossec.log`
- Verify agent is sending data (check agent logs)
- Ensure Wazuh decoders are configured for custom JSON events

## Security Considerations

- **TLS/SSL**: This version uses TCP. For production, consider adding TLS encryption
- **Authentication**: Implement agent authentication if required
- **Permissions**: Run with minimum required permissions
- **Network**: Use firewall rules to restrict access to Wazuh manager

## Customization

To add custom log collection logic:

1. Edit `main.go`
2. Add new collection functions
3. Modify the `LogEvent` structure for additional fields
4. Rebuild the agent

## Performance

- Lightweight: ~10MB binary
- Low CPU usage: <1% on typical workloads
- Memory: ~20-50MB depending on number of monitored files
- Network: Minimal bandwidth (only new log entries)

## Version

Current version: **1.0.0**

## License

This custom agent is part of the AutoDR-2 project.

## Support

For issues or questions:
1. Check the logs for error messages
2. Verify configuration settings
3. Test network connectivity to Wazuh manager
4. Review Wazuh manager logs

## Roadmap

Future enhancements:
- [ ] TLS/SSL encryption
- [ ] Agent authentication
- [ ] Windows Event Log native support
- [ ] Syslog UDP support
- [ ] Log filtering and preprocessing
- [ ] Compression for network efficiency
- [ ] Health check endpoint
- [ ] Prometheus metrics

## Contributing

Contributions are welcome! Please ensure:
- Code is well-documented
- Changes are tested on multiple platforms
- Configuration remains backward compatible
