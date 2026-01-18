# NetProbe

**Multi-network discovery hub that maps your infrastructure, detects GPU compute resources, and intelligently identifies multi-homed systems across network boundaries.**

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## What Does It Do?

Ever wondered what's actually running on your network? This scanner doesn't just find devices - it **understands** them.

- **Multi-Network Scanning**: Discovers devices across all connected network interfaces simultaneously
- **GPU Discovery**: Automatically detects NVIDIA GPUs via SSH, showing VRAM, CUDA versions, and compute capabilities
- **Smart System Grouping**: Identifies when the same physical machine appears on multiple networks (multi-homed systems) and color-codes them together
- **SSH System Profiling**: Gathers detailed system information including CPU, memory, storage, and running services
- **Real-time Web UI**: Modern dark-themed interface with live scan progress and filtering

### The Multi-Interface Problem

In complex networks, a single server often has multiple NICs connecting to different subnets. Traditional scanners show these as separate devices. This scanner **correlates them** - when you scan a machine via SSH, it learns its hostname and automatically groups all its network interfaces together with matching colors.

---

## Screenshots

The web interface provides:
- Network interface overview
- Device cards with GPU information displayed inline
- Color-coded grouping for multi-homed systems
- Detailed system information modals

---

## Quick Start

### Prerequisites

- Python 3.8+
- Network access to target devices
- SSH credentials for system profiling (optional but recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/cronos3k/netprobe.git
cd netprobe

# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running

**Windows:**
```bash
run.bat
```

**Linux/Mac:**
```bash
python app.py
```

Then open http://localhost:5000 in your browser.

---

## Features in Detail

### Network Discovery

The scanner uses ARP table analysis combined with optional ping sweeps:

- **Quick Scan**: Reads the existing ARP cache - fast but only shows recently contacted devices
- **Full Scan**: Performs a ping sweep across all subnets first, then analyzes the ARP table - comprehensive but slower

### SSH System Profiling

For devices with SSH access, the scanner retrieves:

| Category | Information |
|----------|-------------|
| **System** | Hostname, OS version, kernel, uptime |
| **CPU** | Model, core count, usage, load average |
| **Memory** | Total, used, free, percentage |
| **Storage** | All mounted disks with usage |
| **Network** | All interfaces and IP addresses |
| **GPU** | NVIDIA GPUs with VRAM, utilization, temperature, power draw, CUDA compute capability |
| **Services** | Running systemd services (Linux) |

### GPU Detection

If `nvidia-smi` is available on the remote system, the scanner extracts:

- GPU model names
- Total and used VRAM
- GPU utilization percentage
- Temperature and power draw
- CUDA driver and compute capability versions

The web UI shows a summary directly on device cards: *"2x NVIDIA RTX 3090 - Total VRAM: 48.0 GB"*

### Multi-Interface Detection

When you click "Scan All SSH Systems", the scanner:

1. Connects to each SSH-accessible device
2. Retrieves system information including hostname
3. Correlates devices with the same hostname
4. Assigns matching colors to devices that are the same physical system
5. Groups them together in the sorted list

This solves the common problem of not knowing which IPs belong to the same machine.

---

## API Reference

The scanner exposes a REST API for automation and integration:

### Web UI Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface |
| `/api/interfaces` | GET | List server network interfaces |
| `/api/credentials` | GET/POST | Manage SSH credentials |
| `/api/scan` | POST | Start full scan (ping + ARP) |
| `/api/scan/quick` | POST | Start quick scan (ARP only) |
| `/api/scan/status` | GET | Get scan progress |
| `/api/devices` | GET | List discovered devices |
| `/api/devices/ssh` | GET | List SSH-accessible devices with cached info |
| `/api/device/<ip>/info` | POST | Get system info via SSH |

### Programmatic API (v1)

For CLI tools and automation:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/resources` | GET | Get all SSH resources with system info |
| `/api/v1/connect` | POST | Get connection details for a device |
| `/api/v1/execute` | POST | Execute command on remote host |

**Example:**
```bash
# Get all discovered resources
curl http://localhost:5000/api/v1/resources

# Execute a command
curl -X POST http://localhost:5000/api/v1/execute \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "command": "nvidia-smi"}'
```

---

## Configuration

### Global SSH Credentials

Set default credentials used for all devices via the web UI or API:

```bash
curl -X POST http://localhost:5000/api/credentials \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "yourpassword"}'
```

### Per-Device Credentials

Each device can have its own SSH credentials, overriding the global defaults. Click the "Settings" button on any device card to:

- Set custom username/password for that specific device
- Install an SSH key for passwordless authentication
- View current authentication method

**API:**
```bash
# Set per-device credentials
curl -X POST http://localhost:5000/api/device/192.168.1.100/credentials \
  -H "Content-Type: application/json" \
  -d '{"username": "specialuser", "password": "devicepass"}'

# Clear custom credentials (revert to global)
curl -X DELETE http://localhost:5000/api/device/192.168.1.100/credentials
```

### SSH Key Authentication

For passwordless authentication, NetProbe can generate and install SSH keys:

1. Open device settings by clicking "Settings" on a device card
2. Enter username/password (needed once for key installation)
3. Click "Install SSH Key"
4. Future connections will use key-based auth automatically

**API:**
```bash
# Generate SSH key pair (if not exists)
curl -X POST http://localhost:5000/api/ssh/key

# Get public key
curl http://localhost:5000/api/ssh/key

# Install key on a device
curl -X POST http://localhost:5000/api/device/192.168.1.100/install-key \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
```

Keys are stored in `ssh_keys/` directory (gitignored).

### Data Persistence

The scanner caches system information in `data.json` to avoid re-scanning known devices. This file is automatically created on first run.

---

## Architecture

```
netprobe/
├── app.py              # Flask web server and API endpoints
├── scanner.py          # Network scanning (ARP, ping sweep, SSH detection)
├── ssh_client.py       # SSH connection and system info gathering
├── templates/
│   └── index.html      # Single-page web application
├── ssh_keys/           # Generated SSH keys (gitignored)
├── requirements.txt    # Python dependencies
├── run.bat             # Windows launcher
└── data.json           # Credentials and cached data (gitignored)
```

### Technology Stack

- **Backend**: Python 3, Flask
- **SSH**: Paramiko
- **Frontend**: Vanilla JavaScript, CSS3 (no framework dependencies)
- **Scanning**: Native OS commands (`arp`, `ping`, `ipconfig`/`ip`)

---

## Security Considerations

- Credentials are stored in plaintext in `data.json` - secure this file appropriately
- The API has no authentication - run on trusted networks only
- SSH connections auto-accept host keys (convenience over security)
- Consider running behind a reverse proxy with authentication for production use

---

## Use Cases

- **Home Lab Management**: Track all your servers, VMs, and containers across VLANs
- **GPU Cluster Monitoring**: Quick overview of available compute resources
- **Network Auditing**: Discover what's actually connected to your network
- **Multi-Homed Server Tracking**: Finally understand which IPs belong to which physical machines
- **AI/ML Infrastructure**: Find available GPU resources for training jobs

---

## Contributing

Contributions welcome! Areas of interest:

- [ ] Authentication/authorization
- [ ] Support for other GPU vendors (AMD ROCm)
- [ ] Historical data and trends
- [ ] Alerting on device state changes
- [ ] Docker deployment
- [ ] SNMP support for network devices

---

## License

MIT License - see [LICENSE](LICENSE) file.
