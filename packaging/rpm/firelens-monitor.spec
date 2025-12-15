Name:           firelens-monitor
%{!?version: %define version 1.7.0}
%{!?release: %define release 1}
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        Multi-vendor firewall monitoring solution

License:        MIT
URL:            https://github.com/mancow2001/firelens
Source0:        %{name}-%{version}.tar.gz

# Architecture-specific due to compiled Python dependencies in venv
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  xmlsec1-devel
BuildRequires:  systemd-rpm-macros

# Disable automatic dependency scanning for bundled venv
AutoReqProv:    no

# Disable build-id requirements for bundled binaries (pre-compiled wheels)
%undefine _missing_build_ids_terminate_build
%define _build_id_links none
%define __brp_strip %{nil}
%define __brp_strip_comment_note %{nil}

# Disable debug package generation (no source to debug)
%define debug_package %{nil}

Requires:       python3 >= 3.9
Requires:       xmlsec1-openssl
Requires:       /usr/bin/bash

%description
FireLens Monitor is a production-ready, multi-vendor firewall monitoring
solution. The application collects real-time CPU, throughput, packet buffer,
interface bandwidth, and session statistics from multiple firewalls
simultaneously, storing them in a SQLite database with a web-based dashboard
for visualization.

Supported vendors:
- Palo Alto Networks (fully implemented)
- Fortinet FortiGate (fully implemented)
- Cisco Firepower (planned)

%prep
%autosetup

%build
# Build wheel using pip
python3 -m pip wheel --no-deps --wheel-dir=dist .

%install
# Create virtual environment in a temporary location first
python3 -m venv /tmp/firelens-venv
/tmp/firelens-venv/bin/pip install --upgrade pip
/tmp/firelens-venv/bin/pip install dist/*.whl

# Move venv to buildroot
mkdir -p %{buildroot}/opt/firelens
cp -a /tmp/firelens-venv %{buildroot}/opt/firelens/venv

# Fix shebang paths in venv scripts
find %{buildroot}/opt/firelens/venv/bin -type f -exec \
    sed -i 's|/tmp/firelens-venv|/opt/firelens/venv|g' {} \; 2>/dev/null || true

# Create wrapper scripts
mkdir -p %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/firelens << 'EOF'
#!/bin/bash
exec /opt/firelens/venv/bin/firelens "$@"
EOF
chmod +x %{buildroot}%{_bindir}/firelens

cat > %{buildroot}%{_bindir}/firelens-ctl << 'EOF'
#!/bin/bash
exec /opt/firelens/venv/bin/firelens-ctl "$@"
EOF
chmod +x %{buildroot}%{_bindir}/firelens-ctl

# Create directories
mkdir -p %{buildroot}%{_sysconfdir}/firelens
mkdir -p %{buildroot}%{_sharedstatedir}/firelens/data
mkdir -p %{buildroot}%{_localstatedir}/log/firelens
mkdir -p %{buildroot}/opt/firelens/certs

# Install systemd service
mkdir -p %{buildroot}%{_unitdir}
install -m 644 packaging/debian/firelens-monitor.firelens.service %{buildroot}%{_unitdir}/firelens.service

# Install config template
install -m 640 docker/config.yaml.template %{buildroot}%{_sysconfdir}/firelens/config.yaml.example

%pre
# Create system user
getent group firelens >/dev/null || groupadd -r firelens
getent passwd firelens >/dev/null || \
    useradd -r -g firelens -d %{_sharedstatedir}/firelens \
    -s /sbin/nologin -c "FireLens Monitor" firelens

%post
%systemd_post firelens.service

# Set ownership
chown -R firelens:firelens %{_sharedstatedir}/firelens
chown -R firelens:firelens %{_localstatedir}/log/firelens
chown -R firelens:firelens /opt/firelens
chown root:firelens %{_sysconfdir}/firelens
chmod 770 %{_sysconfdir}/firelens

# Create config if not exists
if [ ! -f %{_sysconfdir}/firelens/config.yaml ]; then
    cp %{_sysconfdir}/firelens/config.yaml.example %{_sysconfdir}/firelens/config.yaml
fi
# Ensure firelens user can write to config (for password storage, etc.)
chown firelens:firelens %{_sysconfdir}/firelens/config.yaml
chmod 660 %{_sysconfdir}/firelens/config.yaml

%preun
%systemd_preun firelens.service

%postun
%systemd_postun_with_restart firelens.service

%files
%license LICENSE
%doc README.md
/opt/firelens/venv/
/opt/firelens/certs/
%{_bindir}/firelens
%{_bindir}/firelens-ctl
%{_unitdir}/firelens.service
%dir %attr(770,root,firelens) %{_sysconfdir}/firelens
%config(noreplace) %attr(640,root,firelens) %{_sysconfdir}/firelens/config.yaml.example
%dir %attr(755,firelens,firelens) %{_sharedstatedir}/firelens
%dir %attr(755,firelens,firelens) %{_sharedstatedir}/firelens/data
%dir %attr(755,firelens,firelens) %{_localstatedir}/log/firelens

%changelog
* Sat Dec 14 2025 FireLens Team <mancow2001@gmail.com> - 1.7.0-1
- Stable release: Full Fortinet FortiGate support
- Vendor-agnostic database schema with dedicated metrics tables
- Vendor-aware dashboard, detail pages, and CSV export
- Dual-axis charts for FortiGate Metrics (Memory/NPU Sessions)
- Dual-axis charts for Session Statistics (Active Sessions/Setup Rate)
- Fix SSL verification handling for Fortinet API connections
- Fix config directory permissions for backup file creation
- Fix interface selection not preserving vendor metrics display
- Reduce log noise for expected API method fallbacks

* Sat Dec 14 2025 FireLens Team <mancow2001@gmail.com> - 1.6.18-1
- Fix config directory permissions for backup file creation
- Change /etc/firelens from 750 to 770 so firelens user can create backups

* Sat Dec 14 2025 FireLens Team <mancow2001@gmail.com> - 1.6.17-1
- Hide session utilization % for Fortinet on dashboard
- Fortinet max_sessions is 24h peak, not actual capacity

* Sat Dec 14 2025 FireLens Team <mancow2001@gmail.com> - 1.6.16-1
- Vendor-aware CSV export on firewall detail page
- Palo Alto: Export Mgmt CPU, DP CPU (Mean/Max/P95), Packet Buffer
- Fortinet: Export CPU, Memory, Setup Rate, NPU Sessions

* Sat Dec 14 2025 FireLens Team <mancow2001@gmail.com> - 1.6.15-1
- Fix dashboard landing page to show vendor-specific metrics
- Palo Alto: Show Mgmt CPU, DP CPU, Packet Buffer
- Fortinet: Show CPU, Memory, Setup Rate
- Remove obsolete throughput/pps from main display

* Sat Dec 14 2025 FireLens Team <mancow2001@gmail.com> - 1.6.14-1
- Fix migration to add cpu_usage column to existing fortinet_metrics tables
- Automatic schema migration on service restart

* Sat Dec 14 2025 FireLens Team <mancow2001@gmail.com> - 1.6.13-1
- Schema v2: Move vendor-specific metrics to dedicated tables
- Main metrics table now vendor-agnostic (timestamp, firewall_name only)
- Palo Alto CPU/pbuf metrics now stored in palo_alto_metrics table
- Fortinet metrics continue to use fortinet_metrics table
- Fix JavaScript to read CPU data from vendor-metrics endpoint
- Fix CPU display bug (was showing memory instead of CPU)

* Sat Dec 14 2025 FireLens Team <mancow2001@gmail.com> - 1.6.12-1
- Add cpu_usage column to fortinet_metrics table
- Fix Fortinet CPU not being stored (was missing from schema)

* Sat Dec 14 2025 FireLens Team <mancow2001@gmail.com> - 1.6.11-1
- Fix Fortinet memory_usage_percent not being collected
- Add memory_usage_percent to metrics dict in EnhancedFirewallCollector

* Fri Dec 13 2025 FireLens Team <mancow2001@gmail.com> - 1.6.10-1
- Fix JavaScript errors on Fortinet detail page
- Add null checks for Palo Alto-only elements (pbufChart, cpuAggregation)

* Fri Dec 13 2025 FireLens Team <mancow2001@gmail.com> - 1.6.9-1
- Vendor-aware Fortinet detail page display
- Fix current values to show Fortinet-specific metrics (CPU, Memory, Setup Rate)
- Fix CPU chart to display single CPU line for FortiGate (not Mgmt/DP split)
- Make hover summary vendor-aware for Fortinet metrics

* Fri Dec 13 2025 FireLens Team <mancow2001@gmail.com> - 1.6.8-1
- Fix Fortinet detail page blank data issues
- Add /api/firewall/{name}/vendor-metrics endpoint for Fortinet metrics
- Add JavaScript chart and summary for FortiGate Memory, Setup Rate, NPU Sessions
- Fix session stats API to use /monitor/system/resource/usage endpoint

* Fri Dec 13 2025 FireLens Team <mancow2001@gmail.com> - 1.6.5-1
- Fix Fortinet collector and session monitoring errors
- Fix SessionStatistics -> SessionStats class name in interface_monitor.py
- Fix vendor_metrics dict access for session_setup_rate and npu_sessions

* Fri Dec 13 2025 FireLens Team <mancow2001@gmail.com> - 1.6.4-1
- Packaging version sync and Fortinet config validation fix
- Fix config validation to only require API token for Fortinet firewalls
- Update all packaging artifacts to match release version

* Fri Dec 13 2025 FireLens Team <mancow2001@gmail.com> - 1.6.3-1
- Multi-vendor collector fixes and upgrade safety improvements
- Full Fortinet FortiGate support with REST API integration
- Vendor-aware InterfaceMonitor, collectors, and config validation
- Database schema version tracking for safe upgrades
- Config save backup/restore error handling
- Added docs/UPGRADING.md upgrade guide

* Thu Dec 12 2025 FireLens Team <mancow2001@gmail.com> - 1.5.0-1
- Version stabilization release
- Updated placeholder references with official project URLs
- Consolidated versioning across all packaging artifacts

* Wed Dec 11 2025 FireLens Team <mancow2001@gmail.com> - 1.0.0-1
- Initial RPM package release
- Multi-vendor firewall monitoring (Palo Alto, Fortinet stub, Cisco stub)
- Web dashboard with real-time metrics
- SQLite database for metrics storage
- SAML/SSO authentication support
- SSL/TLS support with auto-generation
