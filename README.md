# <img width="512" height="512" alt="firelens-transparent-darkmode" src="https://github.com/user-attachments/assets/43f19d23-bd77-4cc7-93ee-bda89da918a1" />
A comprehensive real-time monitoring solution for **multiple firewall vendors** including Palo Alto Networks, Fortinet FortiGate, and Cisco Firepower. Features persistent data storage, enhanced web dashboard, intelligent timezone handling, and **per-second session sampling for accurate throughput metrics**.

## Version 1.0.30 (Initial Stable Release)

### **Core Features**
- **Multi-Vendor Firewall Support**: Monitor firewalls from multiple vendors
  - **Palo Alto Networks**: Full support (PAN-OS API)
  - **Fortinet FortiGate**: Full support (REST API with token authentication)
  - **Cisco Firepower**: Placeholder (coming soon)
  - Vendor-specific admin forms with dynamic field visibility
  - Vendor-specific metrics dashboards and charts
  - VDOM support for FortiGate multi-tenant deployments
- **Vendor-Agnostic Database Architecture**: Scalable multi-vendor design
  - Dedicated metrics tables per vendor (`palo_alto_metrics`, `fortinet_metrics`)
  - Schema version tracking with automatic migrations
  - Existing databases upgrade seamlessly on service restart
- **Enhanced Fortinet Visualization**: Dual-axis charts for better insights
  - FortiGate Metrics chart: Memory % (left axis) / NPU Sessions (right axis)
  - Session Statistics chart: Active Sessions (left axis) / Setup Rate (right axis)
  - Vendor-aware hover summary with all Fortinet metrics
- **Native SSL/TLS Support**: Secure HTTPS access out of the box
  - Auto-generated self-signed certificate on first startup (1-year validity)
  - HTTPS enabled by default on port 8443
  - HTTP to HTTPS redirect (port 8080 to 8443)
  - Admin UI for uploading custom SSL certificates
  - Certificate status monitoring with expiry warnings
- **Enhanced Security**: Comprehensive security hardening
  - Bcrypt password hashing (12 rounds)
  - CSRF protection on all state-changing operations
  - Rate limiting on login endpoints (5 requests/minute)
  - Security headers (X-Frame-Options, CSP, X-Content-Type-Options)
  - XXE protection with defusedxml
  - Secure session management with absolute timeout (8 hours)
- **Web-Based Admin Panel**: Full firewall management through the web interface
  - Form-based authentication with configurable credentials
  - Random secure password generated during installation
  - Add, edit, and remove firewalls without service restart
  - Test connection button validates credentials before saving
  - Hot-reload: Changes take effect immediately
  - Enable/disable monitoring per firewall
  - **Password change via web UI** with complexity requirements
  - **SAML/SSO authentication** for enterprise identity providers
  - **CA certificate management** for custom SSL verification
  - **SSL/TLS certificate management** for web dashboard
- **Multi-Firewall Support**: Monitor multiple firewalls simultaneously with individual configurations
- **Persistent Data Storage**: SQLite database ensures data survives application restarts
- **Per-Second Session Sampling**: Continuous background sampling of session info for accurate throughput and PPS capture
- **Production-Ready Performance**: Enterprise-grade optimizations for long-running deployments
- **Modern UI with Dark Mode**:
  - Professional color palette (Primary Blue, Light Blue, Charcoal, Cool Grey)
  - Dark mode toggle with localStorage persistence across pages
  - Theme-aware chart rendering with proper contrast
  - Smooth transitions and responsive design
  - CSS architecture consolidation for easy maintenance
- **Enhanced Web Dashboard**:
  - Overview page listing all monitored firewalls with hardware info badges
  - Detailed firewall views with customizable date/time ranges
  - Real-time CPU aggregation toggles (Mean/Max/P95)
  - CPU chart visibility controls (show/hide Management/Data Plane independently)
  - Enhanced throughput and PPS statistics (Mean/Max/Min/P95)
  - CSV download functionality for filtered data with comprehensive metrics
  - 30-second intelligent caching for reduced database load
  - Firewall hardware detection (model, version, series)
- **Critical Management CPU Fix**: Corrected CPU calculation for PA-3400/5400 series firewalls
- **Intelligent Timezone Handling**: Automatic detection and conversion between local and UTC times
- **Modular Architecture**: Clean separation across multiple Python modules and packages for better maintainability
  - Web dashboard refactored into `web_dashboard/` package with separate route modules
  - Each route module under 800 lines for easy navigation and maintenance
- **Automatic Schema Migration**: Database automatically adds new columns for enhanced statistics

### **Performance & Stability**
- **Memory Leak Prevention**: Fixed unbounded memory growth with bounded deques and queues
  - Stable ~200MB memory usage
  - Automatic cleanup of old in-memory samples (2 hours retention)
  - Proper session and connection cleanup on shutdown
- **Query Optimization**: Eliminated N+1 query problems with batch queries
  - Dashboard: 181 queries to 14 queries (92% reduction)
  - Interface API: 21 queries to 1 query (95% reduction)
  - Page load: <500ms
- **Database Performance**: Connection pooling and intelligent indexing
  - Connection pool (max 10 connections) reduces overhead by 90%+
  - Optimized indexes for time-series queries
  - CPU usage: <5% steady state
- **Resource Management**: Automatic garbage collection and memory monitoring
  - Periodic GC every 5 minutes prevents memory fragmentation
  - Memory monitoring with psutil for health tracking
  - Bounded queues (maxsize=1000) prevent overflow

### **Key Highlights**
- **All CPU Aggregation Methods**: Automatically collects Mean, Max, and P95 data plane CPU metrics
- **Per-Second Sampling**: Background threads sample session info every second for accurate metrics
- **Enhanced Throughput/PPS Metrics**: Automatically computes Mean, Max, Min, and P95 for both throughput and packets per second
- **Interactive Time Filtering**: Select specific date/time ranges with proper timezone conversion
- **Comprehensive Data Export**: Download filtered CSV data with all statistics (8+ metrics per data point)
- **Persistent Configuration**: YAML-based configuration with validation and hot-reload capabilities
- **Database-Driven**: All metrics stored in SQLite with automatic cleanup and retention management
- **Sampling Quality Metadata**: Track sample count, success rate, and sampling period for quality assessment
- **Comprehensive Testing**: 218 unit tests validate all critical functionality (100% pass rate)

## Project Structure
```
FireLens/
├── pyproject.toml               # Python packaging configuration (PEP 517/518)
├── MANIFEST.in                  # Package data inclusion rules
├── LICENSE                      # MIT License
├── README.md                    # This file
├── config.yaml                  # YAML configuration file
│
├── src/firelens/                # Main Python package
│   ├── __init__.py              # Package version and exports
│   ├── __main__.py              # python -m firelens support
│   ├── cli.py                   # CLI entry points (firelens, firelens-ctl)
│   ├── resources.py             # Asset path discovery for templates/static
│   ├── app.py                   # Main FireLensApp class
│   ├── config.py                # Configuration management with admin support
│   ├── database.py              # Data persistence with connection pooling
│   ├── collectors.py            # Multi-threaded collection with hardware detection
│   ├── interface_monitor.py     # Interface monitoring with bounded deques
│   ├── ssl_manager.py           # SSL/TLS certificate generation
│   ├── cert_manager.py          # CA certificate management
│   ├── saml_auth.py             # SAML/SSO authentication handler
│   │
│   ├── web_dashboard/           # Web dashboard package (FastAPI)
│   │   ├── __init__.py          # Package exports
│   │   ├── app.py               # EnhancedWebDashboard class
│   │   ├── cache.py             # SimpleCache with TTL
│   │   ├── session.py           # SessionManager for authentication
│   │   ├── helpers.py           # Auth helpers and password validation
│   │   ├── middleware.py        # Security headers middleware
│   │   └── routes/              # Route modules (FastAPI APIRouter)
│   │       ├── dashboard.py     # Dashboard & metrics API
│   │       ├── auth.py          # Login, logout, password
│   │       ├── saml.py          # SAML/SSO authentication
│   │       ├── admin.py         # Firewall management CRUD
│   │       ├── certificates.py  # CA certificate management
│   │       └── ssl.py           # SSL/TLS management
│   │
│   ├── vendors/                 # Multi-vendor support framework
│   │   ├── __init__.py          # Vendor registry
│   │   ├── base.py              # Abstract base classes
│   │   ├── palo_alto.py         # Palo Alto Networks adapter (full)
│   │   ├── fortinet.py          # Fortinet FortiGate adapter (full)
│   │   └── cisco_firepower.py   # Cisco Firepower adapter (placeholder)
│   │
│   ├── templates/               # Jinja2 HTML templates
│   │   ├── dashboard.html       # Main dashboard
│   │   ├── firewall_detail.html # Detailed metrics view
│   │   ├── admin_*.html         # Admin panel pages
│   │   └── ...
│   │
│   └── static/                  # Static web assets
│       ├── css/styles.css       # Consolidated stylesheet
│       ├── js/                  # JavaScript files
│       └── img/                 # Logo images
│
├── docker/                      # Docker deployment
│   ├── Dockerfile               # Multi-stage production build
│   ├── docker-compose.yml       # Container orchestration
│   └── config.yaml.template     # Default container config
│
├── packaging/                   # System packages
│   ├── debian/                  # Debian/Ubuntu .deb package
│   │   ├── control              # Package metadata
│   │   ├── rules                # Build rules
│   │   ├── firelens.service     # systemd service
│   │   ├── postinst             # Post-install script
│   │   └── prerm                # Pre-remove script
│   └── rpm/                     # RHEL/CentOS .rpm package
│       └── firelens-monitor.spec
│
├── .github/workflows/           # GitHub Actions CI/CD
│   ├── ci.yml                   # Test on PR/push (Python 3.9-3.13)
│   ├── release.yml              # Publish to PyPI, Docker, deb/rpm on tag
│   └── docker.yml               # Build dev image on push to main
│
├── scripts/                     # Build and utility scripts
│   └── build.sh                 # Local build script
│
├── tests/                       # Unit test suite (218 tests)
│   ├── test_certificates.py     # CA certificate tests
│   ├── test_collectors.py       # Hardware detection & CPU tests
│   ├── test_config.py           # Configuration tests
│   ├── test_database.py         # Database tests
│   ├── test_memory_leaks.py     # Memory leak tests
│   ├── test_vendors.py          # Multi-vendor tests
│   └── test_web_dashboard.py    # Web dashboard tests
│
├── run_tests.sh                 # Test runner script
└── check_python_version.py      # Python compatibility checker
```

## Installation

### Prerequisites
- **Python 3.9+** (tested on Python 3.9 through 3.13)
- Access to firewall API (API keys generated automatically)
- **For SAML support**: `libxmlsec1-dev` system package

### Installation Methods

FireLens can be installed via **pip**, **Docker**, or from **source**.

---

### Option 1: Install via pip (Recommended)

```bash
# Install from PyPI
pip install firelens-monitor

# Verify installation
firelens --version

# Create configuration file
firelens create-config --output config.yaml

# Edit configuration with your firewall details
nano config.yaml

# Start monitoring
firelens --config config.yaml
```

**System dependencies for SAML support:**
```bash
# Ubuntu/Debian
sudo apt-get install libxmlsec1-dev libxmlsec1-openssl pkg-config

# RHEL/CentOS/Fedora
sudo dnf install xmlsec1-openssl-devel pkg-config
```

---

### Option 2: Install via Docker

```bash
# Pull the image
docker pull ghcr.io/mancow2001/firelens:latest

# Or use docker-compose
cd docker/
cp config.yaml.template config.yaml
nano config.yaml  # Configure your firewalls

docker-compose up -d

# Access dashboard at https://localhost:8443
```

**docker-compose.yml features:**
- Persistent data volumes for database and logs
- Health checks with automatic restart
- Environment variable overrides
- Resource limits (512MB memory, 1 CPU)

---

### Option 3: Install from Source

```bash
# Clone the repository
git clone https://github.com/mancow2001/FireLens.git
cd FireLens

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests to verify
pytest tests/ -v

# Create configuration
firelens create-config --output config.yaml

# Start monitoring
firelens --config config.yaml
```

---

### CLI Commands

After installation, two commands are available:

**`firelens`** - Main application
```bash
firelens --version                    # Show version
firelens --help                       # Show help
firelens create-config -o config.yaml # Create example config
firelens --config config.yaml         # Start monitoring
firelens --port 9090                  # Override web port
firelens --log-level DEBUG            # Set log level
```

**`firelens-ctl`** - Service control (for systemd deployments)
```bash
firelens-ctl status    # Show service status
firelens-ctl start     # Start service
firelens-ctl stop      # Stop service
firelens-ctl restart   # Restart service
firelens-ctl logs      # Follow service logs
firelens-ctl config    # Show configuration
```

## Configuration

### Primary Configuration: config.yaml (Recommended)
```yaml
# Global settings
global:
  output_dir: "./output"
  database_path: "./data/metrics.db"
  web_dashboard: true
  web_port: 8080
  log_level: "INFO"

  # Admin panel configuration
  admin:
    enabled: true
    username: "fireAdmin"
    password_hash: "$2b$12$..."  # Bcrypt hashed password (auto-generated on install)
    password_reset_required: false
    session_timeout_minutes: 60
    secure_cookies: true  # Set to false if not using HTTPS

  # SSL/TLS configuration (enabled by default)
  web_ssl:
    enabled: true
    auto_generate: true           # Auto-generate self-signed cert if none exists
    https_port: 8443              # HTTPS port (primary)
    http_port: 8080               # HTTP port (redirects to HTTPS)
    redirect_http_to_https: true  # Redirect HTTP to HTTPS
    min_tls_version: "TLSv1.2"

  # Certificate storage directory
  certs_directory: "/opt/FireLens/certs"

# Multiple firewall configurations
firewalls:
  datacenter_fw:
    host: "https://10.100.192.3"
    username: "admin"
    password: "YourPassword"
    type: "palo_alto"           # Vendor type (palo_alto, fortinet, cisco_firepower)
    verify_ssl: false
    enabled: true
    poll_interval: 60           # Recommended: 15-30 seconds for accurate throughput
    interface_monitoring: true  # Enable interface bandwidth monitoring
    auto_discover_interfaces: true

  branch_fw:
    host: "https://192.168.1.1"
    username: "admin"
    password: "BranchPassword"
    type: "palo_alto"
    verify_ssl: false
    enabled: true
    poll_interval: 30           # Shorter interval captures traffic bursts better

  fortigate_fw:
    host: "https://10.100.192.111"
    username: ""                # Optional for Fortinet (ignored with API token)
    password: "your_api_token"  # FortiGate REST API token
    type: "fortinet"
    vdom: "root"                # FortiGate VDOM (default: root)
    verify_ssl: false
    enabled: true
    poll_interval: 60
    interface_monitoring: true
    auto_discover_interfaces: true
```

### Configuration Options

#### Global Settings
- `output_dir`: Directory for data storage
- `database_path`: SQLite database location
- `web_dashboard`: Enable/disable web interface
- `web_port`: Web dashboard port
- `log_level`: Logging verbosity (DEBUG, INFO, WARNING, ERROR)

#### Firewall Settings
- `host`: Firewall management URL (include https://)
- `username`/`password`: API credentials
- `verify_ssl`: SSL certificate verification
- `enabled`: Enable/disable monitoring for this firewall
- `poll_interval`: Polling frequency in seconds (recommended: 15-30 for throughput capture)

**Performance Tip**: Use `poll_interval: 15-30` seconds to capture traffic bursts and transient events accurately. The per-second sampling will then aggregate these periods into meaningful statistics.

## Usage

### Running FireLens
```bash
# Start with default configuration search
firelens

# Use specific configuration file
firelens --config /etc/firelens/config.yaml

# Override web port
firelens --port 9090

# Set log level
firelens --log-level DEBUG

# Run as Python module
python -m firelens --config config.yaml
```

### Access Points
```
Dashboard:       https://localhost:8443
Firewall detail: https://localhost:8443/firewall/{name}
Admin panel:     https://localhost:8443/admin
Health API:      https://localhost:8443/api/health
```

## Enhanced Features

### **Per-Second Session Sampling**

The monitor continuously samples session info every second in background threads:
- **Automatic Collection**: No configuration needed
- **Background Processing**: Samples collected asynchronously
- **Aggregation**: Samples aggregated into statistics at each poll interval
- **Quality Metrics**: Track sample count, success rate, and sampling period
- **Minimal Overhead**: Uses short timeouts (5s) for fast responses

### **Multi-Firewall Monitoring**
- **Independent Configuration**: Each firewall has its own polling interval and settings
- **Centralized Dashboard**: View all firewalls from one interface
- **Individual Detail Pages**: Deep dive into specific firewall metrics
- **Status Indicators**: Real-time online/offline status with color coding

### **Intelligent Timezone Handling**
- **Automatic Detection**: Uses browser timezone for input and display
- **Seamless Conversion**: Enter times in your local timezone, stored as UTC
- **Dual Timestamps**: CSV exports include both local and UTC timestamps
- **Smart Defaults**: Time ranges default to last 6 hours in user's local timezone

## Collected Metrics

### Firewall Hardware Detection (Auto-Detected)
- **Model**: Firewall model number (e.g., PA-3430, PA-5420)
- **Software Version**: PAN-OS version running on firewall
- **Family**: Firewall series (e.g., 3400, 5400)
- **Serial Number**: Device serial number
- **Hostname**: Configured firewall hostname

### Management Plane
- **CPU Components**: User, System, Idle percentages
- **Total Management CPU**: Combined user + system percentage

### Data Plane (Enhanced)
- **CPU Mean**: Average across all cores (overall health)
- **CPU Max**: Highest loaded core (bottleneck detection)
- **CPU P95**: 95th percentile (capacity planning)

### Network Performance (Enhanced with Per-Second Sampling)
- **Throughput Mean/Max/Min/P95**: Mbps statistics over polling interval
- **PPS Mean/Max/Min/P95**: Packets per second statistics
- **Packet Buffer**: Maximum buffer utilization across processors

## Security Considerations

### API Permissions
Create dedicated monitoring users with minimal permissions:
- `show system resources` (read-only)
- `show running resource-monitor` (read-only)
- `show session info` (read-only)

### Best Practices
- **Strong Passwords**: Use complex API credentials
- **SSL Verification**: Enable certificate verification in production (`verify_ssl: true`)
- **Network Restriction**: Limit access to management interfaces
- **Credential Management**: Store sensitive data in protected configuration files

## Testing

### Comprehensive Test Suite
The project includes 218 unit tests validating all critical functionality:

```bash
# Run all tests (recommended)
./run_tests.sh

# Run with coverage report
./run_tests.sh coverage

# Run specific test suites
./run_tests.sh database    # Database tests only
./run_tests.sh memory      # Memory leak tests only
./run_tests.sh web         # Web dashboard tests only
./run_tests.sh collectors  # Collector tests only

# Quick run without coverage
./run_tests.sh quick
```

## Performance and Scaling

### Resource Usage
- **Memory**: Stable ~200MB for multi-firewall deployments
- **Database Growth**: ~4KB per firewall per poll
- **CPU**: <5% steady state
- **Network**: 4 API calls per firewall per poll interval

### Scaling Guidelines
- **Small deployment**: 1-10 firewalls, 30-60 second poll intervals
- **Medium deployment**: 10-50 firewalls, 60-120 second poll intervals
- **Large deployment**: 50+ firewalls, consider multiple instances or longer intervals

## Quick Start

### Via pip (Recommended)
```bash
# 1. Install FireLens
pip install firelens-monitor

# 2. Create configuration
firelens create-config --output config.yaml

# 3. Edit config.yaml with your firewall details
nano config.yaml

# 4. Start monitoring
firelens --config config.yaml

# 5. Access dashboard at https://localhost:8443
```

### Via Docker
```bash
# 1. Get the docker files
git clone https://github.com/mancow2001/FireLens.git
cd FireLens/docker

# 2. Configure
cp config.yaml.template config.yaml
nano config.yaml

# 3. Start
docker-compose up -d

# 4. Access dashboard at https://localhost:8443
```
  ### Via DEB Package (Debian/Ubuntu)
  ```bash
  # 1. Download the latest .deb from GitHub Releases
  wget https://github.com/mancow2001/FireLens/releases/latest/download/firelens-monitor_<version>_all.deb

  # 2. Install the package
  sudo apt install ./firelens-monitor_<version>_all.deb

  # 3. Edit configuration
  sudo nano /etc/firelens/config.yaml

  # 4. Start and enable the service
  sudo systemctl enable --now firelens

  # 5. Access dashboard at https://localhost:8443
```

### Via RPM Package (RHEL/CentOS/Fedora)
```bash
# 1. Download the latest .rpm from GitHub Releases
wget https://github.com/mancow2001/FireLens/releases/latest/download/firelens-monitor-<version>.x86_64.rpm

# 2. Install the package (use yum for older systems)
sudo dnf install ./firelens-monitor-<version>.x86_64.rpm

# 3. Edit configuration
sudo nano /etc/firelens/config.yaml

# 4. Start and enable the service
sudo systemctl enable --now firelens

# 5. Access dashboard at https://localhost:8443
```

### From Source
```bash
# 1. Clone and install
git clone https://github.com/mancow2001/FireLens.git
cd FireLens
pip install -e ".[dev]"

# 2. Run tests
pytest tests/ -v
# Expected: 218 passed

# 3. Create config and start
firelens create-config --output config.yaml
nano config.yaml
firelens --config config.yaml
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
