#!/usr/bin/env python3
"""
FireLens Monitor - Interface Monitoring Module
Optimized for PAN-OS 11 interface bandwidth and session monitoring
"""

import logging
import time
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event, Lock, Thread
from typing import Dict, List, Optional, Set

LOG = logging.getLogger("FireLens.interface_monitor")


@dataclass
class InterfaceConfig:
    """Configuration for monitoring a specific interface"""

    name: str
    display_name: str
    enabled: bool = True
    description: str = ""


@dataclass
class InterfaceSample:
    """Single interface statistics sample"""

    timestamp: datetime
    interface_name: str
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errors: int = 0
    tx_errors: int = 0
    success: bool = True
    error: Optional[str] = None


@dataclass
class InterfaceMetrics:
    """Calculated interface metrics between two samples"""

    interface_name: str
    interval_seconds: float
    rx_bps: float  # bits per second
    tx_bps: float  # bits per second
    rx_mbps: float  # Mbps
    tx_mbps: float  # Mbps
    rx_pps: float  # packets per second
    tx_pps: float  # packets per second
    utilization_percent: float = 0.0  # if interface speed is known
    total_mbps: float = 0.0  # combined rx + tx


@dataclass
class SessionStats:
    """Session statistics from firewall"""

    timestamp: datetime
    active_sessions: int
    max_sessions: int
    tcp_sessions: int = 0
    udp_sessions: int = 0
    icmp_sessions: int = 0
    session_rate: float = 0.0  # sessions/second
    success: bool = True
    error: Optional[str] = None


def discover_interfaces_panos11(xml_text: str) -> List[str]:
    """Stage 1: Discover interface names from 'all' command"""
    interfaces = []

    if not xml_text or not xml_text.strip():
        LOG.error("Empty XML response for interface discovery")
        return interfaces

    try:
        root = ET.fromstring(xml_text)
        status = root.get("status")
        if status == "error":
            error_msg = root.findtext(".//msg", "Unknown API error")
            LOG.error(f"API error in interface discovery: {error_msg}")
            return interfaces

        LOG.info("=== DISCOVERING INTERFACES ===")
        interface_paths = [".//entry/name", ".//hw/name", ".//ifnet/name", ".//interface/name"]
        found_names = set()

        for path in interface_paths:
            name_elements = root.findall(path)
            for name_elem in name_elements:
                if name_elem.text:
                    interface_name = name_elem.text.strip()
                    if not interface_name.lower().startswith(("mgmt", "loopback", "tunnel")):
                        found_names.add(interface_name)
                        LOG.info(f"Discovered interface: {interface_name}")

        return list(found_names)

    except Exception as e:
        LOG.error(f"Error in interface discovery: {e}")
        return []


def parse_individual_interface_panos11(
    xml_text: str, interface_name: str
) -> Optional[InterfaceSample]:
    """Stage 2: Parse individual interface response with detailed counters

    Prioritizes hardware port counters (rx-bytes/tx-bytes) as they are the most accurate.
    Falls back to ibytes/obytes if port counters are not available.
    """
    timestamp = datetime.now(timezone.utc)

    if not xml_text or not xml_text.strip():
        return None

    try:
        root = ET.fromstring(xml_text)
        status = root.get("status")
        if status == "error":
            return InterfaceSample(
                timestamp=timestamp,
                interface_name=interface_name,
                rx_bytes=0,
                tx_bytes=0,
                rx_packets=0,
                tx_packets=0,
                success=False,
            )

        # Locate counter sections
        hw_counters = root.find(".//counters/hw/entry")
        ifnet_counters = root.find(".//counters/ifnet/entry")

        def safe_int_extract(parent, field_name, default=0):
            if parent is None:
                return default
            elem = parent.find(field_name)
            if elem is not None and elem.text:
                try:
                    return int(elem.text.strip())
                except ValueError:
                    return default
            return default

        rx_bytes = tx_bytes = rx_packets = tx_packets = rx_errors = tx_errors = 0

        # PRIORITY 1: Try hardware port counters first (most accurate)
        if hw_counters is not None:
            port_section = hw_counters.find("port")
            if port_section is not None:
                rx_bytes = safe_int_extract(port_section, "rx-bytes")
                tx_bytes = safe_int_extract(port_section, "tx-bytes")
                rx_packets = (
                    safe_int_extract(port_section, "rx-unicast")
                    + safe_int_extract(port_section, "rx-multicast")
                    + safe_int_extract(port_section, "rx-broadcast")
                )
                tx_packets = (
                    safe_int_extract(port_section, "tx-unicast")
                    + safe_int_extract(port_section, "tx-multicast")
                    + safe_int_extract(port_section, "tx-broadcast")
                )
                rx_errors = safe_int_extract(port_section, "rx-error")
                tx_errors = safe_int_extract(port_section, "tx-error")

                LOG.debug(f"Interface {interface_name}: Using hardware port counters")

            # PRIORITY 2: If port counters are zero or unavailable, try hw ibytes/obytes
            if rx_bytes == 0 and tx_bytes == 0:
                rx_bytes = safe_int_extract(hw_counters, "ibytes")
                tx_bytes = safe_int_extract(hw_counters, "obytes")
                rx_packets = safe_int_extract(hw_counters, "ipackets")
                tx_packets = safe_int_extract(hw_counters, "opackets")
                rx_errors = safe_int_extract(hw_counters, "ierrors")
                tx_errors = safe_int_extract(hw_counters, "idrops")

                if rx_bytes > 0 or tx_bytes > 0:
                    LOG.debug(f"Interface {interface_name}: Using hardware ibytes/obytes counters")

        # PRIORITY 3: Fall back to ifnet counters if hw counters are not available or zero
        if (rx_bytes == 0 and tx_bytes == 0) and ifnet_counters is not None:
            rx_bytes = safe_int_extract(ifnet_counters, "ibytes")
            tx_bytes = safe_int_extract(ifnet_counters, "obytes")
            rx_packets = safe_int_extract(ifnet_counters, "ipackets")
            tx_packets = safe_int_extract(ifnet_counters, "opackets")
            rx_errors = safe_int_extract(ifnet_counters, "ierrors")
            tx_errors = safe_int_extract(ifnet_counters, "idrops")

            if rx_bytes > 0 or tx_bytes > 0:
                LOG.debug(f"Interface {interface_name}: Using ifnet counters")

        LOG.info(
            f"Interface {interface_name}: RX={rx_bytes} bytes, TX={tx_bytes} bytes, "
            f"RX_pkts={rx_packets}, TX_pkts={tx_packets}"
        )

        if rx_bytes > 0 or tx_bytes > 0 or rx_packets > 0 or tx_packets > 0:
            return InterfaceSample(
                timestamp=timestamp,
                interface_name=interface_name,
                rx_bytes=rx_bytes,
                tx_bytes=tx_bytes,
                rx_packets=rx_packets,
                tx_packets=tx_packets,
                rx_errors=rx_errors,
                tx_errors=tx_errors,
                success=True,
            )

        LOG.warning(f"Interface {interface_name}: No valid counter data found")
        return None

    except Exception as e:
        LOG.error(f"Error parsing interface {interface_name}: {e}")
        return None


def parse_interface_statistics_your_panos11(client) -> Dict[str, InterfaceSample]:
    """
    Two-stage interface collection for PAN-OS 11
    Stage 1: Discover interfaces, Stage 2: Query each individually for counters
    """
    interfaces = {}

    LOG.info("=== STARTING TWO-STAGE INTERFACE COLLECTION ===")

    # Stage 1: Discover interfaces
    try:
        LOG.info("Stage 1: Discovering interfaces...")
        xml = client.op("<show><interface>all</interface></show>")
        if not xml:
            LOG.error(f"Failed to discover interfaces: {client.last_error}")
            return interfaces

        interface_names = discover_interfaces_panos11(xml)
        if not interface_names:
            LOG.error("No interfaces discovered")
            return interfaces

        LOG.info(f"Stage 1 complete: Found {len(interface_names)} interfaces")

    except Exception as e:
        LOG.error(f"Stage 1 failed: {e}")
        return interfaces

    # Stage 2: Query each interface individually
    LOG.info("Stage 2: Collecting individual interface counters...")

    for interface_name in interface_names:
        try:
            LOG.debug(f"Querying interface: {interface_name}")
            interface_cmd = f"<show><interface>{interface_name}</interface></show>"
            xml = client.op(interface_cmd)

            if not xml:
                LOG.warning(f"Failed to get counters for {interface_name}: {client.last_error}")
                continue

            sample = parse_individual_interface_panos11(xml, interface_name)
            if sample and sample.success:
                interfaces[interface_name] = sample
                LOG.info(f"✅ Successfully collected counters for {interface_name}")
            else:
                LOG.warning(f"❌ Failed to parse counters for {interface_name}")

        except Exception as e:
            LOG.error(f"Error collecting {interface_name}: {e}")
            continue

    LOG.info(f"=== TWO-STAGE COLLECTION COMPLETE: {len(interfaces)} interfaces ===")
    return interfaces


def parse_session_statistics_your_panos11(xml_text: str) -> Optional[SessionStats]:
    """
    Parse session statistics for your specific PAN-OS 11 system
    Based on debug results showing session info works
    """
    timestamp = datetime.now(timezone.utc)

    if not xml_text or not xml_text.strip():
        LOG.error("Empty XML response for session statistics")
        return None

    try:
        root = ET.fromstring(xml_text)

        # Check for API response status
        status = root.get("status")
        if status == "error":
            error_msg = root.findtext(".//msg", "Unknown API error")
            LOG.error(f"API error in session response: {error_msg}")
            return SessionStats(
                timestamp=timestamp,
                active_sessions=0,
                max_sessions=0,
                success=False,
                error=error_msg,
            )

        # Based on debug results, session info works and has a result element
        result_elem = root.find(".//result")
        if result_elem is None:
            LOG.warning("No session result found in XML response")
            return None

        # Extract session counts with multiple field name attempts
        def safe_session_extract(elem, field_names, default=0):
            """Try multiple field names for session data"""
            if isinstance(field_names, str):
                field_names = [field_names]

            for field_name in field_names:
                value_elem = elem.find(field_name)
                if value_elem is not None and value_elem.text:
                    try:
                        return int(value_elem.text.strip())
                    except ValueError:
                        continue
            return default

        # Try multiple field names for session counts
        num_active = safe_session_extract(
            result_elem,
            ["num-active", "active-sessions", "num_active", "active", "sessions-active"],
        )

        num_max = safe_session_extract(
            result_elem, ["num-max", "max-sessions", "num_max", "maximum", "sessions-max"]
        )

        # Get detailed session counts if available
        tcp_sessions = safe_session_extract(
            result_elem, ["tcp-sessions", "tcp", "num-tcp", "sessions-tcp"]
        )

        udp_sessions = safe_session_extract(
            result_elem, ["udp-sessions", "udp", "num-udp", "sessions-udp"]
        )

        icmp_sessions = safe_session_extract(
            result_elem, ["icmp-sessions", "icmp", "num-icmp", "sessions-icmp"]
        )

        # Parse session rate
        session_rate = 0.0
        rate_fields = ["pps", "rate", "session-rate", "sessions-per-second"]
        for field in rate_fields:
            rate_elem = result_elem.find(field)
            if rate_elem is not None and rate_elem.text:
                try:
                    session_rate = float(rate_elem.text.strip())
                    break
                except ValueError:
                    continue

        # Log what we found for debugging
        LOG.debug(
            f"Sessions: active={num_active}, max={num_max}, "
            f"tcp={tcp_sessions}, udp={udp_sessions}, icmp={icmp_sessions}"
        )

        if num_active >= 0 and num_max >= 0:  # Allow zero values
            return SessionStats(
                timestamp=timestamp,
                active_sessions=num_active,
                max_sessions=num_max,
                tcp_sessions=tcp_sessions,
                udp_sessions=udp_sessions,
                icmp_sessions=icmp_sessions,
                session_rate=session_rate,
                success=True,
            )

        LOG.warning("Failed to extract valid session counts")
        return None

    except ET.ParseError as e:
        LOG.error(f"XML parse error in session statistics: {e}")
        return SessionStats(
            timestamp=timestamp,
            active_sessions=0,
            max_sessions=0,
            success=False,
            error=f"XML parse error: {e}",
        )
    except Exception as e:
        LOG.error(f"Unexpected error parsing session statistics: {e}")
        return SessionStats(
            timestamp=timestamp, active_sessions=0, max_sessions=0, success=False, error=str(e)
        )


def calculate_interface_metrics(
    prev_sample: InterfaceSample, curr_sample: InterfaceSample
) -> Optional[InterfaceMetrics]:
    """Calculate bandwidth metrics between two interface samples"""
    if prev_sample.interface_name != curr_sample.interface_name:
        return None

    # Calculate time interval
    interval = (curr_sample.timestamp - prev_sample.timestamp).total_seconds()
    if interval <= 0:
        LOG.warning(f"Invalid interval {interval}s for {curr_sample.interface_name}")
        return None

    # Calculate byte deltas (handle counter wraps)
    rx_delta = curr_sample.rx_bytes - prev_sample.rx_bytes
    tx_delta = curr_sample.tx_bytes - prev_sample.tx_bytes
    rx_pkt_delta = curr_sample.rx_packets - prev_sample.rx_packets
    tx_pkt_delta = curr_sample.tx_packets - prev_sample.tx_packets

    # Handle counter wraps (try 64-bit first for modern systems, then 32-bit)
    if rx_delta < 0:
        if abs(rx_delta) > 2**31:  # Likely 64-bit counter
            rx_delta += 2**64
        else:  # 32-bit counter
            rx_delta += 2**32

    if tx_delta < 0:
        if abs(tx_delta) > 2**31:
            tx_delta += 2**64
        else:
            tx_delta += 2**32

    if rx_pkt_delta < 0:
        if abs(rx_pkt_delta) > 2**31:
            rx_pkt_delta += 2**64
        else:
            rx_pkt_delta += 2**32

    if tx_pkt_delta < 0:
        if abs(tx_pkt_delta) > 2**31:
            tx_pkt_delta += 2**64
        else:
            tx_pkt_delta += 2**32

    # Calculate rates
    rx_bps = (rx_delta * 8) / interval  # Convert bytes to bits
    tx_bps = (tx_delta * 8) / interval
    rx_mbps = rx_bps / (1000 * 1000)  # Convert to Mbps
    tx_mbps = tx_bps / (1000 * 1000)
    rx_pps = rx_pkt_delta / interval
    tx_pps = tx_pkt_delta / interval

    total_mbps = rx_mbps + tx_mbps

    LOG.debug(
        f"Calculated metrics for {curr_sample.interface_name}: "
        f"RX={rx_mbps:.2f}Mbps, TX={tx_mbps:.2f}Mbps over {interval:.1f}s"
    )

    return InterfaceMetrics(
        interface_name=curr_sample.interface_name,
        interval_seconds=interval,
        rx_bps=rx_bps,
        tx_bps=tx_bps,
        rx_mbps=rx_mbps,
        tx_mbps=tx_mbps,
        rx_pps=rx_pps,
        tx_pps=tx_pps,
        total_mbps=total_mbps,
    )


class InterfaceMonitor:
    """Interface and session monitoring - supports multiple firewall vendors"""

    def __init__(self, name: str, client, firewall_config=None):
        self.name = name
        self.client = client
        self.firewall_config = firewall_config
        self.running = False
        self.thread: Optional[Thread] = None
        self.stop_event = Event()

        # Detect vendor type from config (default to palo_alto for backward compatibility)
        self.vendor_type = (
            getattr(firewall_config, "type", "palo_alto") if firewall_config else "palo_alto"
        )

        # Initialize interface configuration
        if firewall_config:
            self.interface_configs = {
                cfg.name: cfg
                for cfg in create_interface_configs_from_firewall_config(firewall_config)
            }
            self.auto_discover = getattr(firewall_config, "auto_discover_interfaces", False)
            self.exclude_patterns = getattr(
                firewall_config, "exclude_interfaces", ["mgmt", "loopback", "tunnel"]
            )
        else:
            # Fallback to default configs
            default_configs = self._create_default_interface_configs()
            self.interface_configs = {cfg.name: cfg for cfg in default_configs}
            self.auto_discover = True
            self.exclude_patterns = ["mgmt", "loopback", "tunnel"]

        # Data storage with locks - using deque with maxlen for automatic memory management
        # Reduced retention from 24h to 2h to prevent memory leaks
        # At 30s intervals: 2 hours = 240 samples per interface
        max_samples = 240
        self.interface_samples: Dict[str, deque] = {}
        self.interface_metrics: Dict[str, deque] = {}
        self.session_stats: deque = deque(maxlen=max_samples)  # 2 hours of session stats
        self.data_lock = Lock()
        self.max_samples = max_samples  # Store for interface-specific deques

        # Discovered interfaces (for auto-discovery)
        self.discovered_interfaces: Set[str] = set()

        # Sampling interval
        self.sample_interval = 30  # seconds

        # Add authentication checking
        self.authenticated = False
        self.last_auth_check = None

    def _create_default_interface_configs(self) -> List[InterfaceConfig]:
        """Create default interface configurations for common PAN-OS interfaces"""
        return [
            InterfaceConfig(
                name="ethernet1/1",
                display_name="Internet/WAN",
                description="Primary internet connection",
            ),
            InterfaceConfig(
                name="ethernet1/2",
                display_name="LAN/Internal",
                description="Internal network connection",
            ),
            InterfaceConfig(
                name="ethernet1/3", display_name="DMZ", description="DMZ network connection"
            ),
            InterfaceConfig(
                name="ae1",
                display_name="Aggregate 1",
                description="Link aggregation group 1",
                enabled=False,  # Disabled by default for auto-discovery
            ),
            InterfaceConfig(
                name="ae2",
                display_name="Aggregate 2",
                description="Link aggregation group 2",
                enabled=False,  # Disabled by default for auto-discovery
            ),
        ]

    def _check_authentication(self) -> bool:
        """Check if we're properly authenticated with the firewall (vendor-aware)"""
        try:
            if self.vendor_type == "palo_alto":
                # PAN-OS: Test with session info command
                xml = self.client.op("<show><session><info/></session></show>")
                if xml and 'status="success"' in xml:
                    self.authenticated = True
                    self.last_auth_check = datetime.now(timezone.utc)
                    return True
                else:
                    self.authenticated = False
                    LOG.warning(f"{self.name}: Authentication check failed")
                    return False
            elif self.vendor_type == "fortinet":
                # Fortinet: Check if client is authenticated
                if hasattr(self.client, "is_authenticated") and self.client.is_authenticated():
                    self.authenticated = True
                    self.last_auth_check = datetime.now(timezone.utc)
                    return True
                else:
                    self.authenticated = False
                    LOG.warning(f"{self.name}: Fortinet authentication check failed")
                    return False
            else:
                # Other vendors: Assume authenticated if client exists
                self.authenticated = True
                self.last_auth_check = datetime.now(timezone.utc)
                return True
        except Exception as e:
            LOG.error(f"{self.name}: Authentication check error: {e}")
            self.authenticated = False
            return False

    def _should_monitor_interface(self, interface_name: str) -> bool:
        """Determine if an interface should be monitored"""
        # Check exclusion patterns first
        for pattern in self.exclude_patterns:
            if pattern.lower() in interface_name.lower():
                return False

        # If we have firewall config, use its logic
        if self.firewall_config and hasattr(self.firewall_config, "should_monitor_interface"):
            return self.firewall_config.should_monitor_interface(interface_name)

        # If explicitly configured, check if enabled
        if interface_name in self.interface_configs:
            return self.interface_configs[interface_name].enabled

        # If auto-discovery enabled and not excluded, monitor it
        if self.auto_discover:
            return True

        return False

    def start_monitoring(self):
        """Start interface and session monitoring"""
        if self.running:
            return

        # Check authentication before starting
        if not self._check_authentication():
            LOG.error(f"{self.name}: Cannot start interface monitoring - authentication failed")
            return

        self.running = True
        self.stop_event.clear()
        self.thread = Thread(
            target=self._monitoring_worker, daemon=True, name=f"interface-monitor-{self.name}"
        )
        self.thread.start()
        LOG.info(f"{self.name}: Started interface monitoring")

    def stop_monitoring(self):
        """Stop interface and session monitoring"""
        if not self.running:
            return

        self.running = False
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        LOG.info(f"{self.name}: Stopped interface monitoring")

    def _monitoring_worker(self):
        """Worker thread for interface and session monitoring"""
        consecutive_failures = 0
        max_failures = 5

        while not self.stop_event.is_set():
            start_time = time.time()

            try:
                # Check authentication periodically
                current_time = datetime.now(timezone.utc)
                if (
                    self.last_auth_check is None
                    or (current_time - self.last_auth_check).total_seconds() > 300
                ):  # Check every 5 minutes
                    if not self._check_authentication():
                        consecutive_failures += 1
                        if consecutive_failures >= max_failures:
                            LOG.error(f"{self.name}: Too many auth failures, stopping monitoring")
                            break
                        else:
                            fails = consecutive_failures
                            LOG.warning(f"{self.name}: Auth fail ({fails}/{max_failures})")
                    else:
                        consecutive_failures = 0

                # Collect interface statistics
                if self.authenticated:
                    success = self._collect_interface_stats()
                    if not success:
                        consecutive_failures += 1
                    else:
                        consecutive_failures = 0

                    # Collect session statistics
                    self._collect_session_stats()

            except Exception as e:
                LOG.error(f"{self.name}: Monitoring error: {e}")
                consecutive_failures += 1

            # Exit if too many failures
            if consecutive_failures >= max_failures:
                LOG.error(f"{self.name}: Too many consecutive failures, stopping monitoring")
                break

            # Sleep for remaining interval time
            elapsed = time.time() - start_time
            sleep_time = max(0, self.sample_interval - elapsed)
            if sleep_time > 0:
                self.stop_event.wait(sleep_time)

    def _collect_interface_stats(self) -> bool:
        """Collect interface statistics (vendor-aware)"""
        try:
            current_samples = None

            if self.vendor_type == "palo_alto":
                LOG.debug(f"{self.name}: Collecting PAN-OS interface statistics...")
                current_samples = parse_interface_statistics_your_panos11(self.client)
            elif self.vendor_type == "fortinet":
                LOG.debug(f"{self.name}: Collecting FortiGate interface statistics...")
                if hasattr(self.client, "collect_interface_stats"):
                    current_samples = self.client.collect_interface_stats()
                else:
                    LOG.warning(
                        f"{self.name}: FortinetClient missing collect_interface_stats method"
                    )
                    return False
            else:
                LOG.debug(
                    f"{self.name}: Interface collection not implemented for {self.vendor_type}"
                )
                return False

            if not current_samples:
                LOG.warning(f"{self.name}: No interfaces collected from two-stage method")
                return False

            LOG.info(
                f"{self.name}: Successfully collected {len(current_samples)} interface samples"
            )

            with self.data_lock:
                for interface_name, sample in current_samples.items():
                    # Auto-discover if enabled
                    if self.auto_discover and interface_name not in self.discovered_interfaces:
                        if self._should_monitor_interface(interface_name):
                            self.discovered_interfaces.add(interface_name)
                            LOG.info(f"{self.name}: Auto-discovered interface: {interface_name}")

                    # Only store samples for interfaces we should monitor
                    if not self._should_monitor_interface(interface_name):
                        continue

                    # Store sample - deque automatically handles size limits
                    if interface_name not in self.interface_samples:
                        self.interface_samples[interface_name] = deque(maxlen=self.max_samples)
                    self.interface_samples[interface_name].append(sample)

                    # Calculate metrics if we have a previous sample
                    samples = self.interface_samples[interface_name]
                    if len(samples) >= 2:
                        prev_sample = samples[-2]
                        metrics = calculate_interface_metrics(prev_sample, sample)

                        if metrics:
                            if interface_name not in self.interface_metrics:
                                self.interface_metrics[interface_name] = deque(
                                    maxlen=self.max_samples
                                )
                            self.interface_metrics[interface_name].append(metrics)

                            LOG.debug(
                                f"{self.name}: {interface_name} - "
                                f"RX: {metrics.rx_mbps:.2f} Mbps, "
                                f"TX: {metrics.tx_mbps:.2f} Mbps"
                            )

                    # No manual cleanup needed - deque handles it automatically with maxlen

            return True

        except Exception as e:
            LOG.error(f"{self.name}: Interface collection error: {e}")
            import traceback

            LOG.debug(f"Full traceback: {traceback.format_exc()}")
            return False

    def _collect_session_stats(self) -> bool:
        """Collect session statistics (vendor-aware)"""
        try:
            LOG.debug(f"{self.name}: Collecting session statistics...")

            if self.vendor_type == "palo_alto":
                # PAN-OS: Use XML API
                xml = self.client.op("<show><session><info/></session></show>")
                if not xml:
                    LOG.warning(f"{self.name}: No response from session statistics API")
                    return False

                if 'status="error"' in xml:
                    LOG.warning(f"{self.name}: API error in session response")
                    return False

                LOG.debug(f"{self.name}: Received session XML response ({len(xml)} chars)")

                session_stats = parse_session_statistics_your_panos11(xml)
                if session_stats and session_stats.success:
                    with self.data_lock:
                        self.session_stats.append(session_stats)
                        LOG.debug(
                            f"{self.name}: Sessions - Active: {session_stats.active_sessions}, "
                            f"Max: {session_stats.max_sessions}"
                        )
                    return True
                else:
                    LOG.warning(f"{self.name}: Failed to parse session statistics")
                    return False

            elif self.vendor_type == "fortinet":
                # Fortinet: Use REST API
                if hasattr(self.client, "collect_session_stats"):
                    stats = self.client.collect_session_stats()
                    if stats:
                        # Convert FortiGate SessionStats to our format
                        session_stats = SessionStats(
                            timestamp=stats.timestamp,
                            active_sessions=stats.active_sessions,
                            max_sessions=stats.max_sessions,
                            tcp_sessions=stats.tcp_sessions,
                            udp_sessions=stats.udp_sessions,
                            icmp_sessions=stats.icmp_sessions,
                            session_rate=stats.session_rate,
                            success=True,
                        )
                        with self.data_lock:
                            self.session_stats.append(session_stats)
                            LOG.debug(
                                f"{self.name}: Sessions - Active: {session_stats.active_sessions}, "
                                f"Max: {session_stats.max_sessions}"
                            )
                        return True
                    else:
                        LOG.warning(f"{self.name}: Failed to collect Fortinet session statistics")
                        return False
                else:
                    LOG.warning(f"{self.name}: FortinetClient missing collect_session_stats method")
                    return False

            else:
                LOG.debug(f"{self.name}: Session collection not implemented for {self.vendor_type}")
                return False

        except Exception as e:
            LOG.error(f"{self.name}: Session collection error: {e}")
            return False

    # Keep all the existing getter methods unchanged
    def get_interface_metrics(
        self,
        interface_name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[InterfaceMetrics]:
        """Get interface metrics for specified time range"""
        with self.data_lock:
            metrics = self.interface_metrics.get(interface_name, [])

            if start_time or end_time:
                filtered_metrics = []
                for metric in metrics:
                    # Find corresponding sample timestamp
                    samples = self.interface_samples.get(interface_name, [])
                    metric_sample = next(
                        (s for s in samples if s.interface_name == interface_name), None
                    )

                    if metric_sample:
                        timestamp = metric_sample.timestamp
                        if start_time and timestamp < start_time:
                            continue
                        if end_time and timestamp > end_time:
                            continue
                        filtered_metrics.append(metric)

                return filtered_metrics

            return metrics.copy()

    def get_session_stats(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> List[SessionStats]:
        """Get session statistics for specified time range"""
        with self.data_lock:
            stats = list(self.session_stats)  # Convert deque to list

            if start_time or end_time:
                filtered_stats = []
                for stat in stats:
                    if start_time and stat.timestamp < start_time:
                        continue
                    if end_time and stat.timestamp > end_time:
                        continue
                    filtered_stats.append(stat)

                return filtered_stats

            return stats

    def get_available_interfaces(self) -> List[str]:
        """Get list of interfaces that have been discovered"""
        with self.data_lock:
            return list(self.interface_samples.keys())

    def get_latest_interface_metrics(self, interface_name: str) -> Optional[InterfaceMetrics]:
        """Get latest metrics for an interface"""
        with self.data_lock:
            metrics = self.interface_metrics.get(interface_name, [])
            return metrics[-1] if metrics else None

    def get_latest_session_stats(self) -> Optional[SessionStats]:
        """Get latest session statistics"""
        with self.data_lock:
            return self.session_stats[-1] if self.session_stats else None


def create_interface_configs_from_firewall_config(firewall_config) -> List[InterfaceConfig]:
    """Create interface configs from enhanced firewall configuration"""
    interface_configs = []

    # If we have detailed interface configs, use them
    if hasattr(firewall_config, "interface_configs") and firewall_config.interface_configs:
        interface_configs.extend(firewall_config.interface_configs)

    # If we have simple monitor_interfaces list, convert to configs
    if hasattr(firewall_config, "monitor_interfaces") and firewall_config.monitor_interfaces:
        for interface_name in firewall_config.monitor_interfaces:
            # Check if not already in interface_configs
            existing_names = [ic.name for ic in interface_configs]
            if interface_name not in existing_names:
                display_name = (
                    firewall_config._generate_display_name(interface_name)
                    if hasattr(firewall_config, "_generate_display_name")
                    else interface_name
                )
                interface_configs.append(
                    InterfaceConfig(
                        name=interface_name,
                        display_name=display_name,
                        enabled=True,
                        description=f"Monitored interface {interface_name}",
                    )
                )

    return interface_configs
