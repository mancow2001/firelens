#!/usr/bin/env python3
"""
FireLens Monitor - Data Collection Module
Optimized for PAN-OS 11 firewall API integration
"""
import time
import logging
# Use defusedxml to prevent XXE attacks when parsing XML from firewalls
try:
    import defusedxml.ElementTree as ET
except ImportError:
    # Fallback to standard library if defusedxml not available
    import xml.etree.ElementTree as ET
    import logging
    logging.getLogger("FireLens.collectors").warning(
        "defusedxml not installed - using standard xml.etree.ElementTree. "
        "Install defusedxml for XXE protection: pip install defusedxml"
    )
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Any
from threading import Thread, Event
from queue import Queue
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException
import urllib3

# Import our interface monitoring module - FIXED IMPORT
from .interface_monitor import (
    InterfaceMonitor, InterfaceConfig,
    parse_interface_statistics_your_panos11, parse_session_statistics_your_panos11
)

# Import vendor abstraction for multi-vendor support
from .vendors import get_vendor_adapter, is_vendor_supported

# Suppress TLS warnings when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG = logging.getLogger("FireLens.collectors")

# Firewall models with dedicated data plane cores that affect management CPU calculation
# These models have cores pre-spun at 100% for data plane, which contaminates mgmt CPU
# when using system resources/top parsing method
FIREWALL_CORE_ARCHITECTURE = {
    # PA-400 Series
    "PA-410": {"total_cores": 4, "mgmt_cores": 1, "dp_cores": 3},
    "PA-415": {"total_cores": 4, "mgmt_cores": 1, "dp_cores": 3},
    "PA-415-5G": {"total_cores": 4, "mgmt_cores": 1, "dp_cores": 3},
    "PA-440": {"total_cores": 4, "mgmt_cores": 1, "dp_cores": 3},
    "PA-445": {"total_cores": 4, "mgmt_cores": 1, "dp_cores": 3},
    "PA-450": {"total_cores": 6, "mgmt_cores": 2, "dp_cores": 4},
    "PA-450R": {"total_cores": 6, "mgmt_cores": 2, "dp_cores": 4},
    "PA-455": {"total_cores": 9, "mgmt_cores": 2, "dp_cores": 7},
    "PA-460": {"total_cores": 8, "mgmt_cores": 2, "dp_cores": 6},

    # PA-1400 Series
    "PA-1410": {"total_cores": 8, "mgmt_cores": 2, "dp_cores": 6},
    "PA-1420": {"total_cores": 12, "mgmt_cores": 3, "dp_cores": 9},

    # PA-3400 Series
    "PA-3410": {"total_cores": 12, "mgmt_cores": 3, "dp_cores": 9},
    "PA-3420": {"total_cores": 16, "mgmt_cores": 3, "dp_cores": 13},
    "PA-3430": {"total_cores": 20, "mgmt_cores": 4, "dp_cores": 16},
    "PA-3440": {"total_cores": 24, "mgmt_cores": 5, "dp_cores": 19},

    # PA-5400 Series
    "PA-5410": {"total_cores": 24, "mgmt_cores": 5, "dp_cores": 19},
    "PA-5420": {"total_cores": 32, "mgmt_cores": 6, "dp_cores": 26},
    "PA-5430": {"total_cores": 48, "mgmt_cores": 10, "dp_cores": 38},
    "PA-5440": {"total_cores": 64, "mgmt_cores": 12, "dp_cores": 52},
    "PA-5445": {"total_cores": 64, "mgmt_cores": 12, "dp_cores": 52},
}

def is_affected_by_dp_core_issue(model: str) -> bool:
    """
    Check if firewall model is affected by data plane core contamination issue.

    Affected models have dedicated data plane cores running at 100% that skew
    management CPU calculations when using top/system resources parsing.

    Args:
        model: Firewall model string (e.g., "PA-3430")

    Returns:
        True if model is in the affected list
    """
    return model in FIREWALL_CORE_ARCHITECTURE

def get_core_architecture(model: str) -> Optional[Dict[str, int]]:
    """
    Get core architecture details for a firewall model.

    Args:
        model: Firewall model string (e.g., "PA-3430")

    Returns:
        Dict with total_cores, mgmt_cores, dp_cores, or None if not in mapping
    """
    return FIREWALL_CORE_ARCHITECTURE.get(model)

@dataclass
class CollectionResult:
    """Result of a metrics collection attempt"""
    success: bool
    firewall_name: str
    metrics: Optional[Dict[str, Any]] = None
    interface_metrics: Optional[Dict[str, List[Any]]] = None
    session_stats: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: Optional[datetime] = None
    vendor_type: str = "palo_alto"  # Vendor type for routing to correct metrics table



def create_default_interface_configs() -> List[InterfaceConfig]:
    """Create default interface configurations for common PAN-OS interfaces"""
    return [
        InterfaceConfig(
            name="ethernet1/1",
            display_name="Internet/WAN",
            description="Primary internet connection"
        ),
        InterfaceConfig(
            name="ethernet1/2",
            display_name="LAN/Internal",
            description="Internal network connection"
        ),
        InterfaceConfig(
            name="ethernet1/3",
            display_name="DMZ",
            description="DMZ network connection"
        ),
        InterfaceConfig(
            name="ae1",
            display_name="Aggregate 1",
            description="Link aggregation group 1",
            enabled=False  # Disabled by default for auto-discovery
        ),
        InterfaceConfig(
            name="ae2",
            display_name="Aggregate 2",
            description="Link aggregation group 2",
            enabled=False  # Disabled by default for auto-discovery
        )
    ]

class FireLensClient:
    """PAN-OS API client for FireLens Monitor"""

    def __init__(self, host: str, verify_ssl: bool = True, ca_bundle_path: Optional[str] = None):
        self.base = host.rstrip("/")
        if not self.base.startswith("http"):
            self.base = "https://" + self.base
        self.session = requests.Session()

        # Configure SSL verification
        if verify_ssl:
            if ca_bundle_path and Path(ca_bundle_path).exists():
                self.session.verify = ca_bundle_path
                LOG.debug(f"Using custom CA bundle: {ca_bundle_path}")
            else:
                self.session.verify = True  # Use system CA bundle
        else:
            self.session.verify = False

        self.api_key: Optional[str] = None
        self.last_error: Optional[str] = None

    def close(self):
        """Close the requests session to prevent connection leaks"""
        if self.session:
            try:
                self.session.close()
                LOG.debug(f"Closed requests session for {self.base}")
            except Exception as e:
                LOG.warning(f"Error closing session: {e}")

    def __del__(self):
        """Cleanup when object is destroyed"""
        self.close()

    def keygen(self, username: str, password: str) -> bool:
        """Generate API key and return success status"""
        url = f"{self.base}/api/"
        try:
            resp = self.session.get(
                url,
                params={"type": "keygen", "user": username, "password": password},
                timeout=20
            )
            resp.raise_for_status()
            
            root = ET.fromstring(resp.text)
            
            # Check for errors first
            status = root.get('status')
            if status == 'error':
                error_code = root.findtext('.//code', 'unknown')
                error_msg = root.findtext('.//msg', 'Unknown authentication error')
                self.last_error = f"Authentication failed (code {error_code}): {error_msg}"
                LOG.error(f"Keygen failed: {self.last_error}")
                return False
            
            key = root.findtext("result/key")
            if not key:
                self.last_error = f"API key not found in response: {resp.text[:400]}..."
                LOG.error(f"Keygen failed: {self.last_error}")
                return False
                
            self.api_key = key
            self.last_error = None
            LOG.info("Successfully authenticated and obtained API key")
            return True
            
        except RequestException as e:
            self.last_error = f"Keygen HTTP error: {e}"
            LOG.error(f"Keygen failed: {self.last_error}")
            return False
        except Exception as e:
            self.last_error = f"Keygen parse error: {e}"
            LOG.error(f"Keygen failed: {self.last_error}")
            return False

    def op(self, xml_cmd: str, timeout: int = 30) -> Optional[str]:
        """Execute operational command and return XML response"""
        if not self.api_key:
            self.last_error = "API key not set; call keygen() first"
            return None
            
        url = f"{self.base}/api/"
        params = {"type": "op", "cmd": xml_cmd, "key": self.api_key}
        
        try:
            resp = self.session.get(url, params=params, timeout=timeout)
            resp.raise_for_status()
            
            # Check for API-level errors
            if 'status="error"' in resp.text:
                try:
                    root = ET.fromstring(resp.text)
                    error_code = root.findtext('.//code', 'unknown')
                    error_msg = root.findtext('.//msg', 'Unknown API error')
                    self.last_error = f"API error (code {error_code}): {error_msg}"
                    LOG.warning(f"API command failed: {self.last_error}")
                except:
                    self.last_error = f"API error in response: {resp.text[:200]}..."
                return None
            
            self.last_error = None
            return resp.text
            
        except RequestException as e:
            self.last_error = f"API request error: {e}"
            LOG.error(f"API request failed: {self.last_error}")
            return None
        except Exception as e:
            self.last_error = f"Unexpected error: {e}"
            LOG.error(f"API request failed: {self.last_error}")
            return None

    def op_fast(self, xml_cmd: str) -> Optional[str]:
        """Execute operational command with shorter timeout for frequent polling"""
        return self.op(xml_cmd, timeout=10)

    def request(self, xml_cmd: str) -> Optional[str]:
        """Execute request command - try it anyway for debug status"""
        if not self.api_key:
            self.last_error = "API key not set; call keygen() first"
            return None
            
        url = f"{self.base}/api/"
        # Request commands use type=op (not type=request)
        params = {"type": "op", "cmd": xml_cmd, "key": self.api_key}
        
        try:
            resp = self.session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            
            # Check for API-level errors
            if 'status="error"' in resp.text:
                try:
                    root = ET.fromstring(resp.text)
                    error_code = root.findtext('.//code', 'unknown')
                    error_msg = root.findtext('.//msg', '') or 'No error message'
                    self.last_error = f"API error (code {error_code}): {error_msg}"
                    # Use DEBUG level since this is expected during method fallbacks
                    LOG.debug(f"Request command returned error: {self.last_error}")
                except:
                    self.last_error = f"API error in response: {resp.text[:200]}..."
                return None
            
            self.last_error = None
            return resp.text
            
        except RequestException as e:
            self.last_error = f"API request error: {e}"
            LOG.error(f"Request command failed: {self.last_error}")
            return None
        except Exception as e:
            self.last_error = f"Unexpected error: {e}"
            LOG.error(f"Request command failed: {self.last_error}")
            return None

# Helper functions (same as before)
def _numbers_from_csv(text: str) -> List[float]:
    """Extract numbers from comma-separated text"""
    nums: List[float] = []
    for x in (text or "").split(","):
        xs = x.strip()
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", xs or ""):
            nums.append(float(xs))
    return nums

def _aggregate(values: List[float], mode: str = "mean") -> float:
    """Aggregate list of values using specified mode"""
    if not values:
        return 0.0
    mode = (mode or "mean").lower()
    if mode == "max":
        return max(values)
    if mode == "min":
        return min(values)
    if mode == "p95":
        return calculate_percentile(values, 0.95)
    return sum(values) / len(values)

def calculate_percentile(values: List[float], percentile: float) -> float:
    """Calculate percentile - Python 3.6 compatible version"""
    if not values:
        return 0.0
    sorted_values = sorted(values)
    if len(sorted_values) == 1:
        return sorted_values[0]
    
    # Calculate index for the percentile
    index = (len(sorted_values) - 1) * percentile
    lower_index = int(index)
    upper_index = min(lower_index + 1, len(sorted_values) - 1)
    
    if lower_index == upper_index:
        return sorted_values[lower_index]
    
    # Linear interpolation
    weight = index - lower_index
    return sorted_values[lower_index] * (1 - weight) + sorted_values[upper_index] * weight

def parse_dp_cpu_from_rm_your_panos11(xml_text: str) -> Tuple[Dict[str, float], str]:
    """Parse data plane CPU from resource monitor - optimized for your PAN-OS 11"""
    out: Dict[str, float] = {}
    
    if not xml_text or not xml_text.strip():
        return {}, "dp-cpu: empty resource monitor response"
    
    try:
        root = ET.fromstring(xml_text)
        
        # Check for API errors
        status = root.get('status')
        if status == 'error':
            error_msg = root.findtext('.//msg', 'Unknown API error')
            return {}, f"dp-cpu: resource monitor API error - {error_msg}"
        
        per_core_latest: List[float] = []
        
        # Based on debug results, your system has resource-monitor structure
        # Let's examine the actual structure more carefully
        
        # First, try the standard paths that should work based on debug success
        dp_paths = [
            ".//data-processors/*/minute/cpu-load-maximum/entry/value",
            ".//resource-monitor//data-processors/*/minute/cpu-load-maximum/entry/value",
            ".//result//data-processors/*/minute/cpu-load-maximum/entry/value"
        ]
        
        found_values = False
        for path in dp_paths:
            nodes = root.findall(path)
            if nodes:
                LOG.debug(f"Found DP CPU values using path: {path}")
                found_values = True
                
                for node in nodes:
                    if node.text:
                        arr = _numbers_from_csv(node.text)
                        if not arr:
                            continue
                        newest = arr[0]  # Most recent value
                        
                        # Check if values are fractional (0.0-1.0) and convert to percentage
                        has_decimals = any(v != int(v) for v in arr if v > 0)
                        if has_decimals and max(arr) <= 1.0:
                            newest *= 100.0
                            
                        # Validate reasonable range
                        if 0 <= newest <= 100:
                            per_core_latest.append(newest)
                        else:
                            LOG.debug(f"DP CPU value out of range: {newest}%")
                break
        
        # If standard paths don't work, try more general resource paths
        if not found_values:
            LOG.debug("Trying alternative DP CPU paths...")
            # Look for any CPU-related entries in the resource monitor
            for entry in root.findall(".//entry"):
                name_elem = entry.find("name")
                value_elem = entry.find("value")
                
                if name_elem is not None and value_elem is not None:
                    name = name_elem.text or ""
                    if "cpu" in name.lower():
                        LOG.debug(f"Found CPU entry: {name}")
                        arr = _numbers_from_csv(value_elem.text or "")
                        if arr:
                            value = arr[0]
                            # Check if fractional
                            if value <= 1.0:
                                value *= 100.0
                            if 0 <= value <= 100:
                                per_core_latest.append(value)
                                found_values = True

        # Calculate all three aggregation methods
        if per_core_latest:
            out["data_plane_cpu_mean"] = _aggregate(per_core_latest, "mean")
            out["data_plane_cpu_max"] = _aggregate(per_core_latest, "max")
            out["data_plane_cpu_p95"] = _aggregate(per_core_latest, "p95")
            
            # Keep the original field for backward compatibility (defaults to mean)
            out["data_plane_cpu"] = out["data_plane_cpu_mean"]
            
            return out, f"dp-cpu: {len(per_core_latest)} cores (your PAN-OS 11)"
        else:
            # Set zero values if no data found
            out["data_plane_cpu_mean"] = 0.0
            out["data_plane_cpu_max"] = 0.0
            out["data_plane_cpu_p95"] = 0.0
            out["data_plane_cpu"] = 0.0
            
            return out, "dp-cpu: no valid data found in resource monitor"

    except ET.ParseError as e:
        return {}, f"dp-cpu: XML parse error - {e}"
    except Exception as e:
        return {}, f"dp-cpu: unexpected parsing error - {e}"

def parse_pbuf_live_from_rm_your_panos11(xml_text: str) -> Tuple[Dict[str, float], str]:
    """Parse packet buffer from resource monitor - optimized for your PAN-OS 11"""
    out: Dict[str, float] = {}
    
    if not xml_text or not xml_text.strip():
        return {}, "pbuf: empty resource monitor response"
    
    try:
        root = ET.fromstring(xml_text)
        
        # Check for API errors
        status = root.get('status')
        if status == 'error':
            error_msg = root.findtext('.//msg', 'Unknown API error')
            return {}, f"pbuf: resource monitor API error - {error_msg}"
        
        latest_vals: List[float] = []
        
        # Look for packet buffer entries in resource monitor
        # Since your resource monitor works, we'll scan for relevant entries
        
        for entry in root.findall(".//entry"):
            name_elem = entry.find("name")
            value_elem = entry.find("value")
            
            if name_elem is not None and value_elem is not None:
                name = (name_elem.text or "").lower()
                
                # Look for packet buffer indicators
                if any(indicator in name for indicator in [
                    "packet buffer", "packet-buffer", "pbuf",
                    "buffer utilization", "buffer-utilization",
                    "memory utilization", "memory-utilization"
                ]):
                    LOG.debug(f"Found potential packet buffer entry: {name}")
                    value_text = value_elem.text or ""
                    arr = _numbers_from_csv(value_text)
                    if arr:
                        value = arr[0]  # Most recent value
                        if 0 <= value <= 100:  # Validate percentage
                            latest_vals.append(value)
                            LOG.debug(f"Added packet buffer value: {value}%")
                        else:
                            LOG.debug(f"Packet buffer value out of range: {value}%")
        
        if latest_vals:
            out["pbuf_util_percent"] = _aggregate(latest_vals, "mean")
            return out, f"pbuf: {len(latest_vals)} values (your PAN-OS 11)"
        else:
            out["pbuf_util_percent"] = 0.0
            return out, "pbuf: no packet buffer data found in resource monitor"
        
    except ET.ParseError as e:
        return {}, f"pbuf: XML parse error - {e}"
    except Exception as e:
        return {}, f"pbuf: unexpected parsing error - {e}"

def parse_cpu_from_debug_status(xml_text: str) -> Tuple[Dict[str, float], str]:
    """
    Parse management CPU from debug status - most accurate method
    Uses: <request><s><debug><status/></debug></s></request>
    This gives the same values as the GUI dashboard
    """
    out: Dict[str, float] = {}
    try:
        root = ET.fromstring(xml_text)
        
        # Look for the mp-cpu-utilization field
        mp_cpu = root.findtext(".//mp-cpu-utilization")
        if mp_cpu:
            try:
                cpu_percent = float(mp_cpu)
                out.update({
                    "mgmt_cpu": cpu_percent,
                    "mgmt_cpu_debug": cpu_percent  # Keep both for compatibility
                })
                return out, f"cpu: debug status {cpu_percent}%"
            except ValueError:
                pass
        
        return {}, "cpu: no mp-cpu-utilization in debug status"
    except Exception as e:
        return {}, f"cpu parse error from debug status: {e}"

def parse_cpu_from_system_info(xml_text: str) -> Tuple[Dict[str, float], str]:
    """
    Parse management CPU from system info - more reliable than top
    Uses: <show><s><info/></s></show>
    """
    out: Dict[str, float] = {}
    try:
        root = ET.fromstring(xml_text)
        
        # Look for system info load average fields
        load_avg_1min = root.findtext(".//system/load-avg-1-min")
        load_avg_5min = root.findtext(".//system/load-avg-5-min")
        load_avg_15min = root.findtext(".//system/load-avg-15-min")
        
        if load_avg_1min:
            try:
                # Load average is typically 0-N (where N is number of cores)
                # Convert to rough CPU percentage (load avg * 100, capped at 100%)
                load_avg = float(load_avg_1min)
                cpu_percent = min(load_avg * 100, 100.0)
                out.update({
                    "mgmt_cpu": cpu_percent,
                    "mgmt_cpu_load_avg": cpu_percent,
                    "load_avg_1min": load_avg
                })
                
                # Add 5min and 15min if available
                if load_avg_5min:
                    out["load_avg_5min"] = float(load_avg_5min)
                if load_avg_15min:
                    out["load_avg_15min"] = float(load_avg_15min)
                
                return out, f"cpu: system info load avg {load_avg} ({cpu_percent:.1f}%)"
            except ValueError:
                pass
        
        # Alternative: look for uptime field which might contain load average
        uptime = root.findtext(".//system/uptime") or ""
        if "load average:" in uptime.lower():
            # Extract load average from uptime string
            # Format: "up 1 day, 2:34, load average: 0.15, 0.10, 0.05"
            match = re.search(r"load average:\s*([0-9.]+)", uptime, re.IGNORECASE)
            if match:
                load_avg = float(match.group(1))
                cpu_percent = min(load_avg * 100, 100.0)
                out.update({
                    "mgmt_cpu": cpu_percent,
                    "mgmt_cpu_load_avg": cpu_percent,
                    "load_avg_1min": load_avg
                })
                return out, f"cpu: uptime load avg {load_avg} ({cpu_percent:.1f}%)"
        
        return {}, "cpu: no load average found in system info"
    except Exception as e:
        return {}, f"cpu parse error from system info: {e}"

def parse_system_info_hardware(xml_text: str) -> Dict[str, str]:
    """
    Extract firewall hardware/model information from system info XML.
    Uses: <show><system><info/></system></show>

    Returns dict with: model, family, platform_family, serial, hostname, sw_version
    """
    hardware_info: Dict[str, str] = {}
    try:
        root = ET.fromstring(xml_text)

        # Extract all available hardware fields
        hardware_info['model'] = root.findtext(".//system/model") or ""
        hardware_info['family'] = root.findtext(".//system/family") or ""
        hardware_info['platform_family'] = root.findtext(".//system/platform-family") or ""
        hardware_info['serial'] = root.findtext(".//system/serial") or ""
        hardware_info['hostname'] = root.findtext(".//system/hostname") or ""
        hardware_info['sw_version'] = root.findtext(".//system/sw-version") or ""

        # Log successful detection
        if hardware_info.get('model'):
            LOG.info(f"Detected firewall model: {hardware_info['model']} "
                    f"(family: {hardware_info.get('family', 'unknown')})")

        return hardware_info
    except Exception as e:
        LOG.error(f"Error parsing hardware info from system info: {e}")
        return {}

def parse_mgmt_cpu_from_load_average(xml_text: str, model: str) -> Tuple[Dict[str, float], str]:
    """
    Parse management CPU from 5-minute load average for affected models.

    For firewalls with dedicated DP cores (PA-400/1400/3400/5400 series), the DP cores
    contribute their core count to load average regardless of CPU utilization, because
    dedicated DP processes are always runnable.

    Formula: mgmt_cpu = ((load_avg_5min - dp_cores) / mgmt_cores) × 100

    Args:
        xml_text: XML response from <show><system><resources/></system></show>
        model: Firewall model (e.g., "PA-3430")

    Returns:
        Tuple of (metrics_dict, status_message)
    """
    out: Dict[str, float] = {}

    try:
        root = ET.fromstring(xml_text)
        raw = root.findtext("result") or "".join(root.itertext())
        if not raw:
            return {}, "mgmt-cpu: no result text from top"

        # Get core architecture for this model
        arch = get_core_architecture(model)
        if not arch:
            return {}, f"mgmt-cpu: no core architecture found for {model}"

        total_cores = arch['total_cores']
        mgmt_cores = arch['mgmt_cores']
        dp_cores = arch['dp_cores']

        # Extract load average from top output first line
        # Format: "top - HH:MM:SS up X days, load average: 18.34, 18.35, 18.06"
        # We want the 5-minute value (second number)
        match = re.search(r'load average[:\s]+([0-9.]+),\s*([0-9.]+),\s*([0-9.]+)', raw, re.IGNORECASE)
        if not match:
            return {}, "mgmt-cpu: no load average found in top output"

        load_1min = float(match.group(1))
        load_5min = float(match.group(2))  # Use 5-minute load
        load_15min = float(match.group(3))

        # Calculate management load by subtracting DP core count
        mgmt_load = load_5min - dp_cores

        # Handle edge case where load is entirely from DP cores
        if mgmt_load < 0:
            mgmt_load = 0

        # Calculate management CPU percentage
        mgmt_cpu = (mgmt_load / mgmt_cores) * 100

        # Cap at 100% for safety (though formula should naturally stay under)
        mgmt_cpu = min(mgmt_cpu, 100.0)

        out.update({
            "mgmt_cpu": mgmt_cpu,
            "load_average_1min": load_1min,
            "load_average_5min": load_5min,
            "load_average_15min": load_15min,
            "mgmt_load": mgmt_load
        })

        return out, f"mgmt-cpu: {mgmt_cpu:.1f}% (5min_load={load_5min:.2f}, mgmt_load={mgmt_load:.2f})"

    except Exception as e:
        return {}, f"mgmt-cpu: load average parse error - {e}"

def parse_cpu_from_top(xml_text: str) -> Tuple[Dict[str, float], str]:
    """
    Parse management CPU from top CDATA (fallback method)
    Enhanced version with better regex patterns
    """
    out: Dict[str, float] = {}
    try:
        root = ET.fromstring(xml_text)
        raw = root.findtext("result") or "".join(root.itertext())
        if not raw:
            return {}, "cpu: no result text"
        
        # Clean up the text
        text = raw.replace("\r", "").replace("\n", " ").replace("\t", " ")
        
        # Multiple regex patterns to handle different top output formats
        patterns = [
            # Standard format: %Cpu(s): 51.9%us, 5.4%sy, 1.0%ni, 41.6%id, 0.1%wa, 0.0%hi, 0.0%si, 0.0%st
            r"%?Cpu\(s\)[^0-9]*([0-9.]+)%?\s*us[, ]+\s*([0-9.]+)%?\s*sy[, ]+.*?([0-9.]+)%?\s*id",
            # Alternative format without %: Cpu(s): 51.9 us, 5.4 sy, 1.0 ni, 41.6 id
            r"Cpu\(s\):\s*([0-9.]+)\s*us[, ]+\s*([0-9.]+)\s*sy[, ]+.*?([0-9.]+)\s*id",
            # Compact format: CPU: 51.9us 5.4sy 41.6id
            r"CPU:\s*([0-9.]+)us\s*([0-9.]+)sy\s*([0-9.]+)id",
        ]
        
        for i, pattern in enumerate(patterns):
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                usr, sy, idle = map(float, match.groups())
                mgmt_cpu = usr + sy
                out.update({
                    "cpu_user": usr,
                    "cpu_system": sy,
                    "cpu_idle": idle,
                    "mgmt_cpu": mgmt_cpu
                })
                return out, f"cpu: fallback top pattern {i+1} - {mgmt_cpu}%"
        
        return {}, "cpu: no patterns matched in fallback top"
    except Exception as e:
        return {}, f"cpu fallback top parse error: {e}"

def parse_management_cpu_from_system_resources(xml_text: str) -> Tuple[Dict[str, float], str]:
    """Parse management plane CPU from system resources - for your PAN-OS 11"""
    out: Dict[str, float] = {}
    
    if not xml_text or not xml_text.strip():
        return {}, "mgmt-cpu: empty system resources response"
    
    try:
        root = ET.fromstring(xml_text)
        
        # Check for API errors
        status = root.get('status')
        if status == 'error':
            error_msg = root.findtext('.//msg', 'Unknown API error')
            return {}, f"mgmt-cpu: system resources API error - {error_msg}"
        
        # Common paths for management CPU in system resources
        # PAN-OS typically reports CPU usage as a percentage
        cpu_paths = [
            ".//result/cpu/user",
            ".//result/cpu/sys", 
            ".//cpu/user",
            ".//cpu/sys",
            ".//result/load-average/entry",
            ".//load-average/entry"
        ]
        
        cpu_values = []
        
        # Try to find CPU user and system time
        user_cpu = None
        sys_cpu = None
        
        for path in [".//result/cpu/user", ".//cpu/user"]:
            elem = root.find(path)
            if elem is not None and elem.text:
                try:
                    user_cpu = float(elem.text.strip().rstrip('%'))
                    break
                except ValueError:
                    pass
        
        for path in [".//result/cpu/sys", ".//cpu/sys"]:
            elem = root.find(path)
            if elem is not None and elem.text:
                try:
                    sys_cpu = float(elem.text.strip().rstrip('%'))
                    break
                except ValueError:
                    pass
        
        # If we found user and sys CPU, calculate total management CPU
        if user_cpu is not None and sys_cpu is not None:
            total_cpu = user_cpu + sys_cpu
            if 0 <= total_cpu <= 100:
                out["management_cpu"] = total_cpu
                out["management_cpu_user"] = user_cpu
                out["management_cpu_sys"] = sys_cpu
                return out, f"mgmt-cpu: parsed from system resources (user: {user_cpu}%, sys: {sys_cpu}%)"
        
        # Alternative: Look for load average and convert to percentage
        # Load average format: typically 1-minute, 5-minute, 15-minute
        load_entries = root.findall(".//load-average/entry") or root.findall(".//result/load-average/entry")
        if load_entries:
            # Get 1-minute load average (first entry)
            for entry in load_entries:
                name_elem = entry.find("name")
                value_elem = entry.find("value")
                if name_elem is not None and value_elem is not None:
                    name = name_elem.text or ""
                    if "1" in name or "one" in name.lower():  # 1-minute load average
                        try:
                            load_value = float(value_elem.text.strip())
                            # Convert load average to approximate CPU percentage
                            # Assuming single CPU core, load of 1.0 = 100%
                            # For multi-core, this is an approximation
                            cpu_percent = min(load_value * 100, 100)
                            out["management_cpu"] = cpu_percent
                            return out, f"mgmt-cpu: estimated from load average ({load_value})"
                        except ValueError:
                            pass
        
        # Try alternative structure - sometimes CPU is directly under result
        result = root.find(".//result")
        if result is not None:
            # Look for any element with "cpu" in the name
            for child in result:
                tag_lower = child.tag.lower()
                if "cpu" in tag_lower and child.text:
                    try:
                        value = float(child.text.strip().rstrip('%'))
                        if 0 <= value <= 100:
                            cpu_values.append(value)
                            LOG.debug(f"Found CPU value in {child.tag}: {value}%")
                    except ValueError:
                        pass
        
        if cpu_values:
            out["management_cpu"] = sum(cpu_values)
            return out, f"mgmt-cpu: parsed {len(cpu_values)} CPU values"
        
        # If we still haven't found anything, return empty
        out["management_cpu"] = 0.0
        return out, "mgmt-cpu: no CPU data found in system resources"
        
    except ET.ParseError as e:
        return {}, f"mgmt-cpu: XML parse error - {e}"
    except Exception as e:
        return {}, f"mgmt-cpu: unexpected parsing error - {e}"



class EnhancedFirewallCollector:
    """Enhanced collector optimized for multi-vendor firewall monitoring"""

    def __init__(self, name: str, config, global_config=None):
        self.name = name
        self.config = config
        self.global_config = global_config
        self.authenticated = False
        self.last_poll_time = None
        self.poll_count = 0

        # Determine vendor type (default to palo_alto for backward compatibility)
        self.vendor_type = getattr(config, 'type', 'palo_alto')

        # Validate vendor type is supported
        if not is_vendor_supported(self.vendor_type):
            raise ValueError(
                f"Unsupported vendor type '{self.vendor_type}' for firewall '{name}'. "
                f"Check config.yaml and ensure vendor module is available."
            )

        # Get CA bundle path from global config if available
        ca_bundle_path = None
        if global_config and hasattr(global_config, 'certs_directory'):
            from .cert_manager import CertificateManager
            cert_manager = CertificateManager(global_config.certs_directory)
            ca_bundle_path = cert_manager.get_ca_bundle_path()

        # Create vendor-specific client
        # For Palo Alto, use FireLensClient directly (full implementation)
        # For other vendors, use vendor adapter (stubs will raise NotImplementedError)
        LOG.info(f"{name}: Creating client with verify_ssl={config.verify_ssl} (type: {type(config.verify_ssl).__name__})")
        if self.vendor_type == 'palo_alto':
            self.client = FireLensClient(config.host, config.verify_ssl, ca_bundle_path)
        else:
            # Use vendor adapter for non-Palo Alto vendors
            adapter = get_vendor_adapter(self.vendor_type)
            self.client = adapter.create_client(config.host, config.verify_ssl, ca_bundle_path)
            LOG.warning(
                f"{self.name}: Using {adapter.vendor_name} adapter. "
                f"Note: This vendor may not be fully implemented yet."
            )

        # Hardware/model information (detected during authentication)
        self.hardware_info: Dict[str, str] = {}
        self.model: str = ""
        self.is_affected_model: bool = False

        # Interface monitoring (currently Palo Alto specific)
        interface_configs = getattr(config, 'interface_configs', None)
        if not interface_configs:
            interface_configs = create_default_interface_configs()

        self.interface_monitor = InterfaceMonitor(name, self.client, config)

        LOG.info(f"{self.name}: FireLens collector initialized (vendor: {self.vendor_type})")
        
    def authenticate(self) -> bool:
        """Authenticate with the firewall (vendor-aware)"""
        success = False

        if self.vendor_type == 'palo_alto':
            # Palo Alto uses keygen for API key generation
            success = self.client.keygen(self.config.username, self.config.password)
        else:
            # Other vendors use the standard authenticate interface
            # For Fortinet, password is the API token (username is ignored)
            success = self.client.authenticate(
                getattr(self.config, 'username', ''),
                self.config.password
            )

        if success:
            self.authenticated = True

            # Detect firewall model and hardware info (vendor-specific)
            self._detect_hardware_info()

            # Start interface monitoring
            self.interface_monitor.start_monitoring()

            LOG.info(f"Successfully authenticated with {self.name} and started monitoring")
        else:
            error_msg = getattr(self.client, 'last_error', 'Unknown error')
            LOG.error(f"Failed to authenticate with {self.name}: {error_msg}")
        return success

    def _detect_hardware_info(self):
        """Detect firewall hardware/model information after authentication (vendor-aware)"""
        if self.vendor_type == 'palo_alto':
            self._detect_palo_alto_hardware()
        elif self.vendor_type == 'fortinet':
            self._detect_fortinet_hardware()
        elif self.vendor_type == 'cisco_firepower':
            self._detect_cisco_hardware()
        else:
            LOG.info(f"{self.name}: Hardware detection not implemented for vendor {self.vendor_type}")

    def _detect_palo_alto_hardware(self):
        """Detect Palo Alto firewall hardware/model information"""
        try:
            LOG.info(f"{self.name}: Detecting Palo Alto firewall model and hardware info...")
            xml = self.client.op("<show><system><info/></system></show>")
            if xml and 'status="success"' in xml:
                self.hardware_info = parse_system_info_hardware(xml)
                self.model = self.hardware_info.get('model', '')

                # Check if this model is affected by DP core issue
                if self.model:
                    self.is_affected_model = is_affected_by_dp_core_issue(self.model)
                    if self.is_affected_model:
                        arch = get_core_architecture(self.model)
                        LOG.warning(
                            f"{self.name}: Model {self.model} is affected by data plane core "
                            f"contamination issue (architecture: {arch}). Management CPU "
                            f"calculation will use adjusted methods."
                        )
                    else:
                        LOG.info(f"{self.name}: Model {self.model} is not in affected models list")
            else:
                LOG.warning(f"{self.name}: Could not detect hardware info: {self.client.last_error}")
        except Exception as e:
            LOG.error(f"{self.name}: Error detecting Palo Alto hardware info: {e}")

    def _detect_fortinet_hardware(self):
        """Detect FortiGate hardware/model information"""
        try:
            LOG.info(f"{self.name}: Detecting FortiGate model and hardware info...")
            # FortinetClient has get_hardware_info() that returns HardwareInfo dataclass
            if hasattr(self.client, 'get_hardware_info'):
                hw_info = self.client.get_hardware_info()
                if hw_info:
                    self.model = hw_info.model
                    self.hardware_info = {
                        'model': hw_info.model,
                        'hostname': hw_info.hostname,
                        'serial': hw_info.serial,
                        'version': hw_info.sw_version,
                    }
                    LOG.info(f"{self.name}: FortiGate model detected: {self.model}")
                else:
                    LOG.warning(f"{self.name}: Could not get FortiGate hardware info")
            else:
                LOG.info(f"{self.name}: FortiGate hardware detection not available")
        except Exception as e:
            LOG.error(f"{self.name}: Error detecting FortiGate hardware info: {e}")

    def _detect_cisco_hardware(self):
        """Detect Cisco Firepower hardware/model information"""
        try:
            LOG.info(f"{self.name}: Detecting Cisco Firepower model and hardware info...")
            # Cisco Firepower detection - placeholder for future implementation
            self.model = "Cisco Firepower"
            self.hardware_info = {'model': self.model}
            LOG.info(f"{self.name}: Cisco Firepower hardware detection not yet implemented")
        except Exception as e:
            LOG.error(f"{self.name}: Error detecting Cisco Firepower hardware info: {e}")
    
    def collect_management_cpu_your_panos11(self) -> Dict[str, float]:
        """
        Collect Management CPU using multiple methods with fallback.

        For affected models (PA-400/1400/3400/5400 series with dedicated DP cores):
          - Use load average method exclusively (Methods 1 & 2 skipped)
          - Load average approach is most reliable for these models

        For other models:
          - Priority: debug status > system info > system resources (top)
        """
        cpu_metrics = {}

        # AFFECTED MODELS: Use load average method exclusively
        if self.is_affected_model:
            try:
                LOG.info(f"{self.name}: Attempting Management CPU collection via load average (5-min)")
                xml = self.client.op("<show><system><resources/></system></show>")
                if xml:

                    # Use load average formula for affected models
                    metrics, msg = parse_mgmt_cpu_from_load_average(xml, self.model)
                    if metrics and "mgmt_cpu" in metrics:
                        cpu_metrics.update(metrics)
                        LOG.info(f"{self.name}: ✅ Load Average Method SUCCESS - {msg}")
                        return cpu_metrics
                    else:
                        LOG.warning(f"{self.name}: Load average method failed: {msg}")
                else:
                    LOG.warning(f"{self.name}: Failed to get system resources: {self.client.last_error}")
            except Exception as e:
                LOG.warning(f"{self.name}: Load average method exception: {e}")

            LOG.error(f"{self.name}: ❌ Management CPU collection failed for {self.model}")
            return {}

        # NON-AFFECTED MODELS: Use existing multi-method approach
        # Method 1: Debug status (most accurate - matches GUI)
        try:
            LOG.info(f"{self.name}: Attempting Method 1 - Debug status")
            xml = self.client.request("<request><s><debug><status/></debug></s></request>")
            if xml and 'status="success"' in xml:
                metrics, msg = parse_cpu_from_debug_status(xml)
                if metrics and "mgmt_cpu" in metrics:
                    cpu_metrics.update(metrics)
                    LOG.info(f"{self.name}: ✅ Method 1 SUCCESS - {msg}")
                    return cpu_metrics
                else:
                    LOG.debug(f"{self.name}: Method 1 failed to parse: {msg}")
            else:
                LOG.debug(f"{self.name}: Method 1 failed: {self.client.last_error}")
        except Exception as e:
            LOG.debug(f"{self.name}: Method 1 exception: {e}")

        # Method 2: System info with load average
        try:
            LOG.info(f"{self.name}: Attempting Method 2 - System info")
            xml = self.client.op("<show><system><info/></system></show>")
            if xml and 'status="success"' in xml:
                metrics, msg = parse_cpu_from_system_info(xml)
                if metrics and "mgmt_cpu" in metrics:
                    cpu_metrics.update(metrics)
                    LOG.info(f"{self.name}: ✅ Method 2 SUCCESS - {msg}")
                    return cpu_metrics
                else:
                    LOG.debug(f"{self.name}: Method 2 failed to parse: {msg}")
            else:
                LOG.debug(f"{self.name}: Method 2 failed: {self.client.last_error}")
        except Exception as e:
            LOG.debug(f"{self.name}: Method 2 exception: {e}")

        # Method 3: System resources (top) - fallback for non-affected models
        try:
            LOG.info(f"{self.name}: Attempting Method 3 - System resources (top)")
            xml = self.client.op("<show><system><resources/></system></show>")
            if xml:
                # Try structured parser first
                metrics, msg = parse_management_cpu_from_system_resources(xml)
                if metrics and "management_cpu" in metrics and metrics["management_cpu"] > 0:
                    cpu_metrics["mgmt_cpu"] = metrics["management_cpu"]
                    if "management_cpu_user" in metrics:
                        cpu_metrics["cpu_user"] = metrics["management_cpu_user"]
                    if "management_cpu_sys" in metrics:
                        cpu_metrics["cpu_system"] = metrics["management_cpu_sys"]
                    LOG.info(f"{self.name}: ✅ Method 3a SUCCESS - {msg}")
                    return cpu_metrics

                # Fall back to top parser
                metrics, msg = parse_cpu_from_top(xml)
                if metrics and "mgmt_cpu" in metrics:
                    cpu_metrics.update(metrics)
                    LOG.info(f"{self.name}: ✅ Method 3b SUCCESS - {msg}")
                    return cpu_metrics
            else:
                LOG.warning(f"{self.name}: Method 3 failed to get XML: {self.client.last_error}")
        except Exception as e:
            LOG.warning(f"{self.name}: Method 3 exception: {e}")

        LOG.error(f"{self.name}: ❌ ALL CPU MONITORING METHODS FAILED")
        return {}

    def collect_metrics(self) -> CollectionResult:
        """Enhanced metrics collection (vendor-aware)"""
        if not self.authenticated:
            if not self.authenticate():
                return CollectionResult(
                    success=False,
                    firewall_name=self.name,
                    error="Authentication failed",
                    vendor_type=self.vendor_type
                )

        metrics = {}
        interface_metrics = {}
        session_stats = {}
        timestamp = datetime.now(timezone.utc)
        self.poll_count += 1

        # Vendor-specific CPU and system metrics collection
        if self.vendor_type == 'palo_alto':
            # PAN-OS: Management CPU using system resources command
            try:
                mgmt_cpu_metrics = self.collect_management_cpu_your_panos11()
                if mgmt_cpu_metrics:
                    metrics.update(mgmt_cpu_metrics)
                    LOG.debug(f"{self.name}: Management CPU collected: {mgmt_cpu_metrics.get('management_cpu', 0):.1f}%")
            except Exception as e:
                LOG.warning(f"{self.name}: Management CPU collection error: {e}")

            # Data plane CPU and packet buffer using resource monitor
            try:
                xml = self.client.op("<show><running><resource-monitor><minute></minute></resource-monitor></running></show>")
                if xml:
                    # DP CPU optimized for PAN-OS 11
                    d, msg = parse_dp_cpu_from_rm_your_panos11(xml)
                    metrics.update({k: v for k, v in d.items() if v is not None})
                    LOG.debug(f"{self.name}: {msg}")

                    # Packet buffer optimized for PAN-OS 11
                    d2, msg2 = parse_pbuf_live_from_rm_your_panos11(xml)
                    metrics.update({k: v for k, v in d2.items() if v is not None})
                    LOG.debug(f"{self.name}: {msg2}")
                else:
                    LOG.warning(f"{self.name}: Failed to get resource monitor: {self.client.last_error}")
            except Exception as e:
                LOG.warning(f"{self.name}: Resource monitor error: {e}")

        elif self.vendor_type == 'fortinet':
            # Fortinet: Use FortinetClient's collect_system_metrics
            try:
                if hasattr(self.client, 'collect_system_metrics'):
                    sys_metrics = self.client.collect_system_metrics()
                    if sys_metrics:
                        metrics['cpu_usage'] = sys_metrics.cpu_usage
                        metrics['memory_usage'] = sys_metrics.memory_usage
                        # Fortinet-specific metrics are in vendor_metrics dict
                        if sys_metrics.vendor_metrics:
                            if sys_metrics.vendor_metrics.get('session_setup_rate') is not None:
                                metrics['session_setup_rate'] = sys_metrics.vendor_metrics['session_setup_rate']
                            if sys_metrics.vendor_metrics.get('npu_sessions') is not None:
                                metrics['npu_sessions'] = sys_metrics.vendor_metrics['npu_sessions']
                            if sys_metrics.vendor_metrics.get('memory_usage_percent') is not None:
                                metrics['memory_usage_percent'] = sys_metrics.vendor_metrics['memory_usage_percent']
                        LOG.debug(f"{self.name}: FortiGate CPU: {sys_metrics.cpu_usage:.1f}%, Memory: {sys_metrics.memory_usage:.1f}%")
                    else:
                        LOG.warning(f"{self.name}: Failed to collect Fortinet system metrics")
                else:
                    LOG.warning(f"{self.name}: FortinetClient missing collect_system_metrics method")
            except Exception as e:
                LOG.warning(f"{self.name}: Fortinet system metrics error: {e}")

        else:
            # Other vendors - placeholder
            LOG.debug(f"{self.name}: Metrics collection not fully implemented for {self.vendor_type}")
        
        # Collect interface metrics using WORKING interface command
        try:
            available_interfaces = self.interface_monitor.get_available_interfaces()
            for interface_name in available_interfaces:
                latest_metrics = self.interface_monitor.get_latest_interface_metrics(interface_name)
                if latest_metrics:
                    interface_metrics[interface_name] = {
                        'timestamp': timestamp.isoformat(),
                        'interface_name': interface_name,
                        'rx_mbps': latest_metrics.rx_mbps,
                        'tx_mbps': latest_metrics.tx_mbps,
                        'total_mbps': latest_metrics.total_mbps,
                        'rx_pps': latest_metrics.rx_pps,
                        'tx_pps': latest_metrics.tx_pps,
                        'interval_seconds': latest_metrics.interval_seconds
                    }
        except Exception as e:
            LOG.warning(f"{self.name}: Interface metrics collection error: {e}")
        
        # Collect session statistics
        try:
            latest_session_stats = self.interface_monitor.get_latest_session_stats()
            if latest_session_stats:
                session_stats = {
                    'timestamp': timestamp.isoformat(),
                    'active_sessions': latest_session_stats.active_sessions,
                    'max_sessions': latest_session_stats.max_sessions,
                    'tcp_sessions': latest_session_stats.tcp_sessions,
                    'udp_sessions': latest_session_stats.udp_sessions,
                    'icmp_sessions': latest_session_stats.icmp_sessions,
                    'session_rate': latest_session_stats.session_rate
                }
        except Exception as e:
            LOG.warning(f"{self.name}: Session statistics collection error: {e}")
        
        # Add timestamp and firewall name
        metrics["timestamp"] = timestamp.isoformat()
        metrics["firewall_name"] = self.name
        
        self.last_poll_time = timestamp
        
        return CollectionResult(
            success=True,
            firewall_name=self.name,
            metrics=metrics,
            interface_metrics=interface_metrics,
            session_stats=session_stats,
            timestamp=timestamp,
            vendor_type=self.vendor_type
        )
    
    def stop(self):
        """Stop the collector and all monitoring"""
        self.interface_monitor.stop_monitoring()
        # Close the requests session to prevent connection leaks
        if hasattr(self, 'client') and self.client:
            self.client.close()
            LOG.debug(f"{self.name}: Closed API client session")

# Use the existing MultiFirewallCollector structure but with our updated collector
class MultiFirewallCollector:
    """Multi-vendor firewall collector manager"""

    def __init__(self, firewall_configs=None, database=None, global_config=None):
        """Initialize MultiFirewallCollector with optional arguments for backward compatibility"""

        # Handle the case where no arguments are provided (for backward compatibility)
        if firewall_configs is None:
            LOG.warning("MultiFirewallCollector initialized without arguments - using defaults")
            firewall_configs = {}
            database = None
            global_config = None

        self.firewall_configs = firewall_configs
        self.database = database
        self.global_config = global_config
        self.collectors: Dict[str, EnhancedFirewallCollector] = {}
        self.collection_threads: Dict[str, Thread] = {}
        self.stop_events: Dict[str, Event] = {}
        # Set maximum queue size to prevent unbounded memory growth
        # With 10 firewalls polling every 30s, this allows ~8 hours of backlog
        self.metrics_queue = Queue(maxsize=1000)
        self.running = False
        self.queue_full_warnings = 0  # Track queue overflow warnings

        # Initialize enhanced collectors only if we have firewall configs
        if firewall_configs:
            for name, config in firewall_configs.items():
                if hasattr(config, 'enabled') and config.enabled:
                    self.collectors[name] = EnhancedFirewallCollector(name, config, global_config)
                    self.stop_events[name] = Event()
        else:
            LOG.info("No firewall configurations provided - collector initialized in minimal mode")
    
    def start_collection(self):
        """Start collection threads for all enabled firewalls"""
        if self.running:
            LOG.warning("Collection is already running")
            return
        
        self.running = True
        LOG.info(f"Starting multi-vendor firewall collection for {len(self.collectors)} firewalls")

        # Start collection thread for each firewall
        for name, collector in self.collectors.items():
            thread = Thread(
                target=self._collection_worker,
                args=(name, collector, self.stop_events[name]),
                daemon=True,
                name=f"enhanced-collector-{name}"
            )
            thread.start()
            self.collection_threads[name] = thread

        # Start metrics processing thread
        self.metrics_thread = Thread(
            target=self._enhanced_metrics_processor,
            daemon=True,
            name="enhanced-metrics-processor"
        )
        self.metrics_thread.start()

        LOG.info("All collection threads started")
    
    def stop_collection(self):
        """Stop all collection threads"""
        if not self.running:
            return
        
        LOG.info("Stopping collection threads...")
        self.running = False
        
        # Stop collectors
        for collector in self.collectors.values():
            collector.stop()
        
        # Signal all threads to stop
        for stop_event in self.stop_events.values():
            stop_event.set()
        
        # Wait for threads to finish
        for name, thread in self.collection_threads.items():
            if thread.is_alive():
                thread.join(timeout=5)
                if thread.is_alive():
                    LOG.warning(f"Thread {name} did not stop gracefully")
        
        # Wait for metrics processor
        if hasattr(self, 'metrics_thread') and self.metrics_thread.is_alive():
            self.metrics_thread.join(timeout=5)
        
        LOG.info("All collection threads stopped")

    def add_collector(self, name: str, config) -> bool:
        """
        Hot-add a new collector for a firewall.
        Used by admin interface for adding firewalls without restart.
        """
        if name in self.collectors:
            LOG.warning(f"Collector {name} already exists, cannot add")
            return False

        try:
            # Create collector
            collector = EnhancedFirewallCollector(name, config, self.global_config)
            self.collectors[name] = collector
            self.firewall_configs[name] = config
            self.stop_events[name] = Event()

            # Start collection thread if we're running
            if self.running:
                thread = Thread(
                    target=self._collection_worker,
                    args=(name, collector, self.stop_events[name]),
                    daemon=True,
                    name=f"enhanced-collector-{name}"
                )
                thread.start()
                self.collection_threads[name] = thread
                LOG.info(f"Hot-added and started collector for {name}")
            else:
                LOG.info(f"Hot-added collector for {name} (not started - collection not running)")

            return True

        except Exception as e:
            LOG.error(f"Failed to add collector for {name}: {e}")
            # Cleanup on failure
            self.collectors.pop(name, None)
            self.firewall_configs.pop(name, None)
            self.stop_events.pop(name, None)
            return False

    def remove_collector(self, name: str) -> bool:
        """
        Hot-remove a collector for a firewall.
        Used by admin interface for removing firewalls without restart.
        """
        if name not in self.collectors:
            LOG.warning(f"Collector {name} does not exist, cannot remove")
            return False

        try:
            # Signal thread to stop
            if name in self.stop_events:
                self.stop_events[name].set()

            # Wait for thread to finish
            if name in self.collection_threads:
                thread = self.collection_threads[name]
                if thread.is_alive():
                    thread.join(timeout=5)
                    if thread.is_alive():
                        LOG.warning(f"Thread for {name} did not stop gracefully")

            # Stop and cleanup collector
            if name in self.collectors:
                self.collectors[name].stop()

            # Remove from all tracking dicts
            self.collectors.pop(name, None)
            self.firewall_configs.pop(name, None)
            self.stop_events.pop(name, None)
            self.collection_threads.pop(name, None)

            LOG.info(f"Hot-removed collector for {name}")
            return True

        except Exception as e:
            LOG.error(f"Failed to remove collector for {name}: {e}")
            return False

    def update_collector(self, name: str, new_config) -> bool:
        """
        Hot-update a collector with new configuration.
        Used by admin interface for updating firewalls without restart.
        """
        if name not in self.collectors:
            # If doesn't exist, just add it
            return self.add_collector(name, new_config)

        try:
            # Remove old collector
            self.remove_collector(name)

            # Add with new config (only if enabled)
            if new_config.enabled:
                return self.add_collector(name, new_config)
            else:
                LOG.info(f"Collector {name} updated but not started (disabled)")
                return True

        except Exception as e:
            LOG.error(f"Failed to update collector for {name}: {e}")
            return False

    def _collection_worker(self, name: str, collector: EnhancedFirewallCollector, stop_event: Event):
        """Worker thread for collecting metrics from a single firewall"""
        config = self.firewall_configs[name]
        interval = config.poll_interval
        hardware_registered = False  # Track if we've registered hardware info

        LOG.info(f"Started collection worker for {name} (interval: {interval}s)")

        while not stop_event.is_set():
            start_time = time.time()
            
            try:
                result = collector.collect_metrics()
                # Use put with timeout to avoid blocking if queue is full
                try:
                    self.metrics_queue.put(result, timeout=5)
                except Exception as queue_err:
                    self.queue_full_warnings += 1
                    if self.queue_full_warnings % 10 == 1:  # Log every 10th warning
                        LOG.error(f"Metrics queue is full! Dropped metrics from {name}. "
                                 f"Queue size: {self.metrics_queue.qsize()}, "
                                 f"Total drops: {self.queue_full_warnings}")
                    # Continue to next iteration - metrics are dropped but collection continues

                if result.success:
                    LOG.debug(f"{name}: Metrics collected successfully")

                    # Register hardware info after first successful authentication
                    if not hardware_registered and collector.hardware_info and self.database:
                        try:
                            self.database.register_firewall(name, config.host, collector.hardware_info)
                            hardware_registered = True
                            LOG.info(f"{name}: Registered hardware info in database")
                        except Exception as e:
                            LOG.warning(f"{name}: Could not register hardware info: {e}")
                else:
                    LOG.warning(f"{name}: Collection failed - {result.error}")
                    
            except Exception as e:
                LOG.error(f"{name}: Unexpected error in collection: {e}")
                result = CollectionResult(
                    success=False,
                    firewall_name=name,
                    error=str(e),
                    vendor_type=collector.vendor_type
                )
                self.metrics_queue.put(result)
            
            # Sleep for remaining interval time
            elapsed = time.time() - start_time
            sleep_time = max(0, interval - elapsed)
            if sleep_time > 0:
                stop_event.wait(sleep_time)
        
        LOG.info(f"Collection worker for {name} stopped")
    
    def _enhanced_metrics_processor(self):
        """Process collected metrics and store in database"""
        LOG.info("Started enhanced metrics processor")
        
        while self.running:
            try:
                try:
                    result = self.metrics_queue.get(timeout=1.0)
                except:
                    continue
                
                if result.success:
                    # Store metrics (common + vendor-specific routed automatically)
                    if result.metrics:
                        # Pass vendor_type to route data to appropriate vendor table
                        success = self.database.insert_metrics(
                            result.firewall_name,
                            result.metrics,
                            vendor_type=result.vendor_type
                        )
                        if success:
                            LOG.debug(f"Stored metrics for {result.firewall_name} (vendor: {result.vendor_type})")
                        else:
                            LOG.error(f"Failed to store metrics for {result.firewall_name}")

                    # Store interface metrics
                    if result.interface_metrics and hasattr(self.database, 'insert_interface_metrics'):
                        for interface_name, interface_data in result.interface_metrics.items():
                            success = self.database.insert_interface_metrics(result.firewall_name, interface_data)
                            if success:
                                LOG.debug(f"Stored interface metrics for {result.firewall_name}:{interface_name}")
                            else:
                                LOG.error(f"Failed to store interface metrics for {result.firewall_name}:{interface_name}")

                    # Store session statistics
                    if result.session_stats and hasattr(self.database, 'insert_session_statistics'):
                        success = self.database.insert_session_statistics(result.firewall_name, result.session_stats)
                        if success:
                            LOG.debug(f"Stored session statistics for {result.firewall_name}")
                        else:
                            LOG.error(f"Failed to store session statistics for {result.firewall_name}")
                            
                else:
                    LOG.warning(f"Skipping failed collection for {result.firewall_name}: {result.error}")
                
                self.metrics_queue.task_done()
                
            except Exception as e:
                LOG.error(f"Error in metrics processor: {e}")
        
        LOG.info("Enhanced metrics processor stopped")
    
    def get_collector_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all collectors"""
        status = {}
        for name, collector in self.collectors.items():
            thread_alive = self.collection_threads.get(name, Thread()).is_alive()
            basic_status = {
                'authenticated': collector.authenticated,
                'running': thread_alive,  # Used by admin dashboard
                'last_poll': collector.last_poll_time.isoformat() if collector.last_poll_time else None,
                'poll_count': collector.poll_count,
                'thread_alive': thread_alive,
                'config': {
                    'host': collector.config.host,
                    'interval': collector.config.poll_interval,
                    'enabled': collector.config.enabled
                }
            }
            
            # Add interface monitoring status
            available_interfaces = collector.interface_monitor.get_available_interfaces()
            basic_status.update({
                'interface_monitor_running': collector.interface_monitor.running,
                'available_interfaces': available_interfaces,
                'interface_count': len(available_interfaces)
            })
            
            status[name] = basic_status
            
        return status

# Maintain backward compatibility
class FirewallCollector(EnhancedFirewallCollector):
    """Backward compatibility alias"""
    pass
