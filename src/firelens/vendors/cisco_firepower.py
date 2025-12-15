#!/usr/bin/env python3
"""
FireLens Monitor - Cisco Firepower Vendor Implementation

Supports both management interfaces:
- FDM (Firepower Device Manager) - Local REST API for direct device access
- FMC (Firepower Management Center) - Centralized API for multi-device deployments

API Documentation:
- FDM REST API: https://developer.cisco.com/docs/ftd-rest-api/
- FMC REST API: https://developer.cisco.com/docs/fmc-rest-api/

Architecture Notes:
- FTD (Firepower Threat Defense) is the OS running on Firepower hardware
- Can be managed by FMC (Firepower Management Center) or FDM (local management)
- FDM uses OAuth2 token authentication
- FMC uses HTTP Basic Auth with token response in headers
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

import requests
from requests.exceptions import HTTPError, RequestException

from . import register_vendor
from .base import (
    HardwareInfo,
    InterfaceSample,
    SessionStats,
    SystemMetrics,
    VendorAdapter,
    VendorClient,
)

LOG = logging.getLogger("FireLens.vendors.cisco_firepower")

# Constants
TOKEN_REFRESH_MARGIN_MINUTES = 5  # Refresh token when within 5 minutes of expiry
DEFAULT_TIMEOUT = 30  # seconds
FDM_API_VERSION = "v6"
FMC_API_VERSION = "v1"


@dataclass
class FMCManagedDevice:
    """Represents a device managed by FMC."""

    device_id: str
    name: str
    model: str
    health_status: str
    sw_version: str
    host_name: str = ""
    vendor_specific: Dict[str, Any] = field(default_factory=dict)


class CiscoFirepowerFDMClient(VendorClient):
    """
    Cisco Firepower Threat Defense (FTD) client using FDM REST API.

    FDM (Firepower Device Manager) provides local management for single devices.
    Uses OAuth2 token authentication.

    Authentication:
    - POST /api/fdm/v6/fdm/token with grant_type=password
    - Token valid for 30 minutes, refreshable

    Supported Platforms:
    - Firepower 1000/2100/4100 Series
    - Firepower 9300
    - FTDv (Virtual)
    """

    VENDOR_NAME = "Cisco Firepower (FDM)"
    VENDOR_TYPE = "cisco_firepower"

    def __init__(self, host: str, verify_ssl: bool = True, ca_bundle_path: Optional[str] = None):
        """
        Initialize FDM client.

        Args:
            host: FTD device IP/hostname (https:// prefix optional)
            verify_ssl: Verify SSL certificates (False for self-signed)
            ca_bundle_path: Optional path to custom CA bundle
        """
        self._host = host.rstrip("/")
        if not self._host.startswith("http"):
            self._host = f"https://{self._host}"
        self._base_url = f"{self._host}/api/fdm/{FDM_API_VERSION}"
        self._verify_ssl = verify_ssl
        self._ca_bundle_path = ca_bundle_path
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        self._session: Optional[requests.Session] = None
        self._authenticated = False
        self._hardware_info: Optional[HardwareInfo] = None

        LOG.debug(f"FDM client initialized for {self._host}")

    @property
    def vendor_name(self) -> str:
        return self.VENDOR_NAME

    @property
    def vendor_type(self) -> str:
        return self.VENDOR_TYPE

    def _get_verify_param(self) -> Union[bool, str]:
        """Get the verify parameter for requests."""
        if not self._verify_ssl:
            return False
        if self._ca_bundle_path:
            return self._ca_bundle_path
        return True

    def _create_session(self) -> requests.Session:
        """Create and configure a requests session."""
        session = requests.Session()
        session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        return session

    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate with FTD using OAuth2 password grant.

        Args:
            username: FTD admin username
            password: FTD admin password

        Returns:
            True if authentication successful
        """
        LOG.debug(f"Authenticating to FDM at {self._host}")

        self._session = self._create_session()

        try:
            # OAuth2 password grant
            auth_url = f"{self._base_url}/fdm/token"
            auth_data = {
                "grant_type": "password",
                "username": username,
                "password": password,
            }

            response = self._session.post(
                auth_url,
                json=auth_data,
                verify=self._get_verify_param(),
                timeout=DEFAULT_TIMEOUT,
            )
            response.raise_for_status()

            token_data = response.json()
            self._access_token = token_data.get("access_token")
            self._refresh_token = token_data.get("refresh_token")

            # Calculate token expiration
            expires_in = token_data.get("expires_in", 1800)  # Default 30 min
            self._token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

            # Set authorization header
            self._session.headers["Authorization"] = f"Bearer {self._access_token}"
            self._authenticated = True

            LOG.info(f"Successfully authenticated to FDM at {self._host}")

            # Cache hardware info
            try:
                self._hardware_info = self.get_hardware_info()
            except Exception as e:
                LOG.warning(f"Could not cache hardware info: {e}")

            return True

        except HTTPError as e:
            LOG.error(f"FDM authentication failed: {e}")
            if e.response is not None:
                LOG.error(f"Response: {e.response.text}")
            return False
        except RequestException as e:
            LOG.error(f"FDM connection error: {e}")
            return False

    def is_authenticated(self) -> bool:
        """Check if client is currently authenticated with valid token."""
        if not self._authenticated or not self._access_token:
            return False

        if self._token_expires_at:
            if datetime.now(timezone.utc) >= self._token_expires_at:
                return False

        return True

    def _refresh_token_if_needed(self) -> bool:
        """
        Refresh access token if near expiry.

        Returns:
            True if token is valid (refreshed or not expired)
        """
        if not self._authenticated or not self._session:
            return False

        if not self._token_expires_at:
            return True

        # Check if token expires within margin
        time_until_expiry = self._token_expires_at - datetime.now(timezone.utc)
        if time_until_expiry > timedelta(minutes=TOKEN_REFRESH_MARGIN_MINUTES):
            return True

        LOG.debug("Refreshing FDM access token")

        try:
            auth_url = f"{self._base_url}/fdm/token"
            refresh_data = {
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
            }

            # Temporarily remove auth header for refresh
            old_auth = self._session.headers.pop("Authorization", None)

            response = self._session.post(
                auth_url,
                json=refresh_data,
                verify=self._get_verify_param(),
                timeout=DEFAULT_TIMEOUT,
            )
            response.raise_for_status()

            token_data = response.json()
            self._access_token = token_data.get("access_token")
            self._refresh_token = token_data.get("refresh_token")

            expires_in = token_data.get("expires_in", 1800)
            self._token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

            self._session.headers["Authorization"] = f"Bearer {self._access_token}"

            LOG.debug("FDM token refreshed successfully")
            return True

        except Exception as e:
            LOG.error(f"Failed to refresh FDM token: {e}")
            # Restore old auth header if refresh failed
            if old_auth:
                self._session.headers["Authorization"] = old_auth
            return False

    def _get(self, endpoint: str) -> Dict[str, Any]:
        """
        Make GET request to FDM API.

        Args:
            endpoint: API endpoint (without base URL)

        Returns:
            JSON response as dictionary
        """
        if not self._refresh_token_if_needed():
            raise RuntimeError("Not authenticated or token refresh failed")

        url = f"{self._base_url}/{endpoint.lstrip('/')}"
        response = self._session.get(url, verify=self._get_verify_param(), timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        return response.json()

    def _post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make POST request to FDM API.

        Args:
            endpoint: API endpoint (without base URL)
            data: JSON data to send

        Returns:
            JSON response as dictionary
        """
        if not self._refresh_token_if_needed():
            raise RuntimeError("Not authenticated or token refresh failed")

        url = f"{self._base_url}/{endpoint.lstrip('/')}"
        response = self._session.post(
            url, json=data, verify=self._get_verify_param(), timeout=DEFAULT_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def _execute_cli(self, command: str) -> str:
        """
        Execute CLI command via FDM API.

        Args:
            command: CLI command to execute

        Returns:
            CLI output as string
        """
        result = self._post("action/clicommand", {"commandInput": command})
        return result.get("response", "")

    def get_hardware_info(self) -> HardwareInfo:
        """Get hardware information from Firepower."""
        if self._hardware_info:
            return self._hardware_info

        try:
            data = self._get("operational/systeminfo")

            self._hardware_info = HardwareInfo(
                vendor="Cisco",
                model=data.get("model", "Unknown"),
                serial=data.get("serialNumber", "Unknown"),
                hostname=data.get("hostname", "Unknown"),
                sw_version=data.get("softwareVersion", "Unknown"),
                vendor_specific={
                    "device_type": data.get("deviceType", "FTD"),
                    "management_mode": "fdm",
                },
            )
            return self._hardware_info

        except Exception as e:
            LOG.error(f"Failed to get hardware info: {e}")
            raise

    def collect_system_metrics(self) -> SystemMetrics:
        """Collect CPU and memory metrics from Firepower."""
        try:
            # Try REST API first
            data = self._get("operational/devicestatus")

            cpu_usage = data.get("cpuUsage", 0.0)
            memory_usage = data.get("memoryUsage", 0.0)
            disk_usage = data.get("diskUsage", 0.0)

            vendor_metrics = {
                "disk_usage": disk_usage,
            }

            # Try to get detailed CPU metrics via CLI
            try:
                cli_output = self._execute_cli("show cpu usage")
                cpu_metrics = self._parse_cpu_output(cli_output)
                vendor_metrics.update(cpu_metrics)
            except Exception as e:
                LOG.debug(f"Could not get detailed CPU metrics: {e}")

            return SystemMetrics(
                timestamp=datetime.now(timezone.utc),
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                vendor_metrics=vendor_metrics,
            )

        except Exception as e:
            LOG.error(f"Failed to collect system metrics: {e}")
            raise

    def _parse_cpu_output(self, output: str) -> Dict[str, float]:
        """Parse CLI 'show cpu usage' output for CPU metrics."""
        metrics = {}

        # Pattern: "CPU utilization for 5 seconds = 15%"
        patterns = [
            (r"5 seconds\s*=\s*(\d+(?:\.\d+)?)\s*%", "cpu_5sec"),
            (r"1 minute\s*=\s*(\d+(?:\.\d+)?)\s*%", "cpu_1min"),
            (r"5 minutes\s*=\s*(\d+(?:\.\d+)?)\s*%", "cpu_5min"),
        ]

        for pattern, key in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                metrics[key] = float(match.group(1))

        return metrics

    def collect_interface_stats(
        self, interfaces: Optional[List[str]] = None
    ) -> Dict[str, InterfaceSample]:
        """Collect interface statistics from Firepower."""
        try:
            data = self._get("operational/interfaces")
            items = data.get("items", [])

            results = {}
            timestamp = datetime.now(timezone.utc)

            for iface in items:
                name = iface.get("name", "")
                if not name:
                    continue

                # Filter if specific interfaces requested
                if interfaces and name not in interfaces:
                    continue

                results[name] = InterfaceSample(
                    timestamp=timestamp,
                    interface_name=name,
                    rx_bytes=iface.get("inBytes", 0),
                    tx_bytes=iface.get("outBytes", 0),
                    rx_packets=iface.get("inPackets", 0),
                    tx_packets=iface.get("outPackets", 0),
                    rx_errors=iface.get("inErrors", 0),
                    tx_errors=iface.get("outErrors", 0),
                    success=True,
                )

            return results

        except Exception as e:
            LOG.error(f"Failed to collect interface stats: {e}")
            raise

    def collect_session_stats(self) -> SessionStats:
        """Collect connection/session statistics from Firepower."""
        try:
            # Use CLI command for session count
            cli_output = self._execute_cli("show conn count")

            active_sessions = 0
            max_sessions = 0

            # Parse: "1234 in use, 5678 most used"
            match = re.search(
                r"(\d+)\s+in\s+use[,\s]+(\d+)\s+most\s+used", cli_output, re.IGNORECASE
            )
            if match:
                active_sessions = int(match.group(1))
                max_sessions = int(match.group(2))

            return SessionStats(
                timestamp=datetime.now(timezone.utc),
                active_sessions=active_sessions,
                max_sessions=max_sessions,
            )

        except Exception as e:
            LOG.error(f"Failed to collect session stats: {e}")
            raise

    def discover_interfaces(self) -> List[str]:
        """Discover available interfaces on Firepower."""
        try:
            data = self._get("operational/interfaces")
            items = data.get("items", [])

            interfaces = []
            for iface in items:
                name = iface.get("name", "")
                if name:
                    interfaces.append(name)

            return sorted(interfaces)

        except Exception as e:
            LOG.error(f"Failed to discover interfaces: {e}")
            raise

    def close(self) -> None:
        """Close the API client and cleanup resources."""
        if self._session:
            self._session.close()
            self._session = None
        self._authenticated = False
        self._access_token = None
        self._refresh_token = None
        LOG.debug("FDM client closed")


class CiscoFirepowerFMCClient(VendorClient):
    """
    Cisco Firepower Management Center (FMC) REST API client.

    FMC provides centralized management for multiple FTD devices.
    Uses HTTP Basic Auth with tokens in response headers.

    Authentication:
    - POST /api/fmc_platform/v1/auth/generatetoken with Basic Auth
    - Tokens returned in X-auth-access-token and X-auth-refresh-token headers
    - Token valid for 30 minutes, refreshable up to 3 times (90 min max)
    """

    VENDOR_NAME = "Cisco Firepower (FMC)"
    VENDOR_TYPE = "cisco_firepower"

    def __init__(
        self,
        host: str,
        verify_ssl: bool = True,
        ca_bundle_path: Optional[str] = None,
        device_id: Optional[str] = None,
    ):
        """
        Initialize FMC client.

        Args:
            host: FMC IP/hostname (https:// prefix optional)
            verify_ssl: Verify SSL certificates (False for self-signed)
            ca_bundle_path: Optional path to custom CA bundle
            device_id: Optional device UUID to monitor (for device-specific metrics)
        """
        self._host = host.rstrip("/")
        if not self._host.startswith("http"):
            self._host = f"https://{self._host}"
        self._base_url = f"{self._host}/api/fmc_platform/{FMC_API_VERSION}"
        self._config_url = f"{self._host}/api/fmc_config/{FMC_API_VERSION}"
        self._verify_ssl = verify_ssl
        self._ca_bundle_path = ca_bundle_path
        self._device_id = device_id
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._domain_uuid: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        self._refresh_count = 0  # FMC limits to 3 refreshes
        self._session: Optional[requests.Session] = None
        self._authenticated = False
        self._hardware_info: Optional[HardwareInfo] = None

        LOG.debug(f"FMC client initialized for {self._host}")

    @property
    def vendor_name(self) -> str:
        return self.VENDOR_NAME

    @property
    def vendor_type(self) -> str:
        return self.VENDOR_TYPE

    def _get_verify_param(self) -> Union[bool, str]:
        """Get the verify parameter for requests."""
        if not self._verify_ssl:
            return False
        if self._ca_bundle_path:
            return self._ca_bundle_path
        return True

    def _create_session(self) -> requests.Session:
        """Create and configure a requests session."""
        session = requests.Session()
        session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        return session

    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate with FMC using HTTP Basic Auth.

        Args:
            username: FMC API username
            password: FMC API password

        Returns:
            True if authentication successful
        """
        LOG.debug(f"Authenticating to FMC at {self._host}")

        self._session = self._create_session()

        try:
            # FMC uses Basic Auth, tokens in response headers
            auth_url = f"{self._base_url}/auth/generatetoken"

            response = self._session.post(
                auth_url,
                auth=(username, password),
                verify=self._get_verify_param(),
                timeout=DEFAULT_TIMEOUT,
            )
            response.raise_for_status()

            # Tokens are in response headers, not body
            self._access_token = response.headers.get("X-auth-access-token")
            self._refresh_token = response.headers.get("X-auth-refresh-token")
            self._domain_uuid = response.headers.get("DOMAIN_UUID")

            if not self._access_token:
                LOG.error("No access token in FMC response headers")
                return False

            # FMC tokens valid for 30 minutes
            self._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
            self._refresh_count = 0

            # Set auth header for subsequent requests
            self._session.headers["X-auth-access-token"] = self._access_token
            self._authenticated = True

            LOG.info(f"Successfully authenticated to FMC at {self._host}")
            LOG.debug(f"Domain UUID: {self._domain_uuid}")

            # Cache hardware info
            try:
                self._hardware_info = self.get_hardware_info()
            except Exception as e:
                LOG.warning(f"Could not cache hardware info: {e}")

            return True

        except HTTPError as e:
            LOG.error(f"FMC authentication failed: {e}")
            if e.response is not None:
                LOG.error(f"Response: {e.response.text}")
            return False
        except RequestException as e:
            LOG.error(f"FMC connection error: {e}")
            return False

    def is_authenticated(self) -> bool:
        """Check if client is currently authenticated with valid token."""
        if not self._authenticated or not self._access_token:
            return False

        if self._token_expires_at:
            if datetime.now(timezone.utc) >= self._token_expires_at:
                return False

        return True

    def _refresh_token_if_needed(self) -> bool:
        """
        Refresh access token if near expiry.

        FMC limits refreshes to 3 times per initial auth.

        Returns:
            True if token is valid (refreshed or not expired)
        """
        if not self._authenticated or not self._session:
            return False

        if not self._token_expires_at:
            return True

        time_until_expiry = self._token_expires_at - datetime.now(timezone.utc)
        if time_until_expiry > timedelta(minutes=TOKEN_REFRESH_MARGIN_MINUTES):
            return True

        # Check if we've exceeded refresh limit
        if self._refresh_count >= 3:
            LOG.warning("FMC token refresh limit reached, re-authentication required")
            return False

        LOG.debug("Refreshing FMC access token")

        try:
            refresh_url = f"{self._base_url}/auth/refreshtoken"

            # Use refresh token header
            headers = {"X-auth-refresh-token": self._refresh_token}

            response = self._session.post(
                refresh_url,
                headers=headers,
                verify=self._get_verify_param(),
                timeout=DEFAULT_TIMEOUT,
            )
            response.raise_for_status()

            self._access_token = response.headers.get("X-auth-access-token")
            self._refresh_token = response.headers.get("X-auth-refresh-token")

            self._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
            self._refresh_count += 1

            self._session.headers["X-auth-access-token"] = self._access_token

            LOG.debug(f"FMC token refreshed successfully (refresh {self._refresh_count}/3)")
            return True

        except Exception as e:
            LOG.error(f"Failed to refresh FMC token: {e}")
            return False

    def _get(self, endpoint: str, base: str = "config") -> Dict[str, Any]:
        """
        Make GET request to FMC API.

        Args:
            endpoint: API endpoint (without base URL)
            base: Which API base to use ('config' or 'platform')

        Returns:
            JSON response as dictionary
        """
        if not self._refresh_token_if_needed():
            raise RuntimeError("Not authenticated or token refresh failed")

        if base == "platform":
            url = f"{self._base_url}/{endpoint.lstrip('/')}"
        else:
            url = f"{self._config_url}/{endpoint.lstrip('/')}"

        response = self._session.get(url, verify=self._get_verify_param(), timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        return response.json()

    def _post(self, endpoint: str, data: Dict[str, Any], base: str = "config") -> Dict[str, Any]:
        """
        Make POST request to FMC API.

        Args:
            endpoint: API endpoint (without base URL)
            data: JSON data to send
            base: Which API base to use ('config' or 'platform')

        Returns:
            JSON response as dictionary
        """
        if not self._refresh_token_if_needed():
            raise RuntimeError("Not authenticated or token refresh failed")

        if base == "platform":
            url = f"{self._base_url}/{endpoint.lstrip('/')}"
        else:
            url = f"{self._config_url}/{endpoint.lstrip('/')}"

        response = self._session.post(
            url, json=data, verify=self._get_verify_param(), timeout=DEFAULT_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def discover_managed_devices(self) -> List[FMCManagedDevice]:
        """
        Discover devices managed by this FMC.

        Returns:
            List of FMCManagedDevice objects
        """
        try:
            endpoint = f"domain/{self._domain_uuid}/devices/devicerecords"
            data = self._get(endpoint)

            devices = []
            items = data.get("items", [])

            for item in items:
                device = FMCManagedDevice(
                    device_id=item.get("id", ""),
                    name=item.get("name", "Unknown"),
                    model=item.get("model", "Unknown"),
                    health_status=item.get("healthStatus", "Unknown"),
                    sw_version=item.get("sw_version", item.get("softwareVersion", "Unknown")),
                    host_name=item.get("hostName", ""),
                    vendor_specific={
                        "access_policy": item.get("accessPolicy", {}).get("name", ""),
                        "license_caps": item.get("license_caps", []),
                    },
                )
                devices.append(device)

            LOG.info(f"Discovered {len(devices)} managed devices on FMC")
            return devices

        except Exception as e:
            LOG.error(f"Failed to discover managed devices: {e}")
            raise

    def get_hardware_info(self) -> HardwareInfo:
        """Get hardware information from FMC or managed device."""
        if self._hardware_info:
            return self._hardware_info

        try:
            # If device_id specified, get device info
            if self._device_id:
                endpoint = f"domain/{self._domain_uuid}/devices/devicerecords/{self._device_id}"
                data = self._get(endpoint)

                self._hardware_info = HardwareInfo(
                    vendor="Cisco",
                    model=data.get("model", "Unknown"),
                    serial=data.get("serialNumber", "Unknown"),
                    hostname=data.get("hostName", data.get("name", "Unknown")),
                    sw_version=data.get("softwareVersion", "Unknown"),
                    vendor_specific={
                        "device_type": "FTD",
                        "management_mode": "fmc",
                        "fmc_host": self._host,
                        "device_id": self._device_id,
                    },
                )
            else:
                # Get FMC server info
                data = self._get("info/serverversion", base="platform")

                self._hardware_info = HardwareInfo(
                    vendor="Cisco",
                    model="Firepower Management Center",
                    serial="N/A",
                    hostname=data.get("serverVersion", "Unknown"),
                    sw_version=data.get("serverVersion", "Unknown"),
                    vendor_specific={
                        "device_type": "FMC",
                        "management_mode": "fmc",
                        "geo_location_update_version": data.get("geoLocationUpdateVersion", ""),
                        "vdb_version": data.get("vdbVersion", ""),
                    },
                )

            return self._hardware_info

        except Exception as e:
            LOG.error(f"Failed to get hardware info: {e}")
            raise

    def collect_system_metrics(self) -> SystemMetrics:
        """
        Collect system metrics from FMC or managed device.

        Note: FMC API has limited metrics availability. Device-specific
        metrics may require direct device access.
        """
        try:
            vendor_metrics = {}

            if self._device_id:
                # Try to get device health
                try:
                    endpoint = f"domain/{self._domain_uuid}/health/alerts"
                    data = self._get(endpoint)
                    vendor_metrics["health_alerts"] = len(data.get("items", []))
                except Exception:
                    pass

            # FMC doesn't provide direct CPU/memory metrics via REST API
            # Return basic metrics structure
            return SystemMetrics(
                timestamp=datetime.now(timezone.utc),
                cpu_usage=0.0,  # Not available via FMC API
                memory_usage=None,
                vendor_metrics=vendor_metrics,
            )

        except Exception as e:
            LOG.error(f"Failed to collect system metrics: {e}")
            raise

    def collect_interface_stats(
        self, interfaces: Optional[List[str]] = None
    ) -> Dict[str, InterfaceSample]:
        """
        Collect interface statistics.

        Note: FMC provides interface configuration but limited runtime stats.
        """
        if not self._device_id:
            LOG.warning("No device_id specified, cannot collect interface stats")
            return {}

        try:
            # Get physical interfaces
            endpoint = (
                f"domain/{self._domain_uuid}/devices/devicerecords/"
                f"{self._device_id}/physicalinterfaces"
            )
            data = self._get(endpoint)

            results = {}
            timestamp = datetime.now(timezone.utc)

            for iface in data.get("items", []):
                name = iface.get("name", "")
                if not name:
                    continue

                if interfaces and name not in interfaces:
                    continue

                # FMC provides config, not runtime stats
                results[name] = InterfaceSample(
                    timestamp=timestamp,
                    interface_name=name,
                    rx_bytes=0,  # Not available via FMC
                    tx_bytes=0,
                    rx_packets=0,
                    tx_packets=0,
                    rx_errors=0,
                    tx_errors=0,
                    success=True,
                    error="Runtime stats not available via FMC API",
                )

            return results

        except Exception as e:
            LOG.error(f"Failed to collect interface stats: {e}")
            raise

    def collect_session_stats(self) -> SessionStats:
        """
        Collect session statistics.

        Note: Direct session counts not available via FMC API.
        """
        return SessionStats(
            timestamp=datetime.now(timezone.utc),
            active_sessions=0,
            max_sessions=0,
        )

    def discover_interfaces(self) -> List[str]:
        """Discover available interfaces on managed device."""
        if not self._device_id:
            LOG.warning("No device_id specified, cannot discover interfaces")
            return []

        try:
            interfaces = []

            # Get physical interfaces
            endpoint = (
                f"domain/{self._domain_uuid}/devices/devicerecords/"
                f"{self._device_id}/physicalinterfaces"
            )
            try:
                data = self._get(endpoint)
                for iface in data.get("items", []):
                    name = iface.get("name", "")
                    if name:
                        interfaces.append(name)
            except Exception as e:
                LOG.debug(f"Could not get physical interfaces: {e}")

            # Get subinterfaces
            endpoint = (
                f"domain/{self._domain_uuid}/devices/devicerecords/"
                f"{self._device_id}/subinterfaces"
            )
            try:
                data = self._get(endpoint)
                for iface in data.get("items", []):
                    name = iface.get("name", "")
                    if name:
                        interfaces.append(name)
            except Exception as e:
                LOG.debug(f"Could not get subinterfaces: {e}")

            return sorted(set(interfaces))

        except Exception as e:
            LOG.error(f"Failed to discover interfaces: {e}")
            raise

    def close(self) -> None:
        """Close the API client and cleanup resources."""
        if self._session:
            self._session.close()
            self._session = None
        self._authenticated = False
        self._access_token = None
        self._refresh_token = None
        LOG.debug("FMC client closed")


class CiscoFirepowerAdapter(VendorAdapter):
    """
    Cisco Firepower vendor adapter.

    Factory for creating Firepower clients (FDM or FMC) and providing
    vendor-specific configuration.

    Supported Management Modes:
    - fdm: Local device management via FDM REST API
    - fmc: Centralized management via FMC REST API
    """

    VENDOR_NAME = "Cisco Firepower"
    VENDOR_TYPE = "cisco_firepower"

    @property
    def vendor_name(self) -> str:
        return self.VENDOR_NAME

    @property
    def vendor_type(self) -> str:
        return self.VENDOR_TYPE

    def create_client(
        self,
        host: str,
        verify_ssl: bool = True,
        ca_bundle_path: Optional[str] = None,
        management_mode: str = "fdm",
        device_id: Optional[str] = None,
    ) -> Union[CiscoFirepowerFDMClient, CiscoFirepowerFMCClient]:
        """
        Create a new Firepower API client.

        Args:
            host: Device/FMC IP/hostname
            verify_ssl: Verify SSL certificates
            ca_bundle_path: Optional path to custom CA bundle
            management_mode: 'fdm' for local or 'fmc' for centralized
            device_id: For FMC mode, the device UUID to monitor

        Returns:
            Configured client instance (FDM or FMC)
        """
        if management_mode == "fmc":
            return CiscoFirepowerFMCClient(host, verify_ssl, ca_bundle_path, device_id=device_id)
        else:
            return CiscoFirepowerFDMClient(host, verify_ssl, ca_bundle_path)

    def get_supported_metrics(self) -> List[str]:
        """Get list of metrics supported by Firepower devices."""
        return [
            "cpu_usage",
            "cpu_5sec",
            "cpu_1min",
            "cpu_5min",
            "memory_usage",
            "disk_usage",
            "active_connections",
            "max_connections",
            "xlate_count",
        ]

    def get_hardware_fields(self) -> List[str]:
        """Get list of hardware info fields for Firepower devices."""
        return [
            "model",
            "serial",
            "hostname",
            "sw_version",
            "device_type",
            "management_mode",
        ]

    def get_default_exclude_interfaces(self) -> List[str]:
        """Get default interface exclusion patterns for Firepower."""
        return [
            "Management",
            "Diagnostic",
            "nlp_int_tap",
            "ccl_ha_port",
            "cmi_mgmt_int",
            "Internal-",
        ]


# Backward compatibility alias
CiscoFirepowerClient = CiscoFirepowerFDMClient

# Register this vendor
register_vendor(CiscoFirepowerAdapter.VENDOR_TYPE, CiscoFirepowerAdapter)
LOG.debug("Registered Cisco Firepower vendor adapter")
