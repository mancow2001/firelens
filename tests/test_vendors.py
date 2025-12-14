#!/usr/bin/env python3
"""
Unit tests for vendor abstraction layer
Tests vendor registry, adapters, and client interfaces
"""
import unittest
from unittest.mock import Mock, patch, MagicMock


class TestVendorRegistry(unittest.TestCase):
    """Test vendor registry functionality"""

    def test_registry_has_palo_alto(self):
        """Test that Palo Alto is registered by default"""
        from firelens.vendors import is_vendor_supported
        self.assertTrue(is_vendor_supported('palo_alto'))

    def test_registry_has_fortinet(self):
        """Test that Fortinet is registered"""
        from firelens.vendors import is_vendor_supported
        self.assertTrue(is_vendor_supported('fortinet'))

    def test_registry_has_cisco_firepower(self):
        """Test that Cisco Firepower is registered"""
        from firelens.vendors import is_vendor_supported
        self.assertTrue(is_vendor_supported('cisco_firepower'))

    def test_unknown_vendor_not_supported(self):
        """Test that unknown vendor types are not supported"""
        from firelens.vendors import is_vendor_supported
        self.assertFalse(is_vendor_supported('unknown_vendor'))
        self.assertFalse(is_vendor_supported('juniper'))  # Not implemented

    def test_get_available_vendors(self):
        """Test getting list of available vendors"""
        from firelens.vendors import get_available_vendors
        vendors = get_available_vendors()

        self.assertIn('palo_alto', vendors)
        self.assertEqual(vendors['palo_alto'], 'Palo Alto Networks')

        self.assertIn('fortinet', vendors)
        self.assertEqual(vendors['fortinet'], 'Fortinet FortiGate')

        self.assertIn('cisco_firepower', vendors)
        self.assertEqual(vendors['cisco_firepower'], 'Cisco Firepower')

    def test_get_vendor_adapter_palo_alto(self):
        """Test getting Palo Alto adapter"""
        from firelens.vendors import get_vendor_adapter
        adapter = get_vendor_adapter('palo_alto')

        self.assertEqual(adapter.vendor_type, 'palo_alto')
        self.assertEqual(adapter.vendor_name, 'Palo Alto Networks')

    def test_get_vendor_adapter_fortinet(self):
        """Test getting Fortinet adapter"""
        from firelens.vendors import get_vendor_adapter
        adapter = get_vendor_adapter('fortinet')

        self.assertEqual(adapter.vendor_type, 'fortinet')
        self.assertEqual(adapter.vendor_name, 'Fortinet FortiGate')

    def test_get_vendor_adapter_cisco(self):
        """Test getting Cisco Firepower adapter"""
        from firelens.vendors import get_vendor_adapter
        adapter = get_vendor_adapter('cisco_firepower')

        self.assertEqual(adapter.vendor_type, 'cisco_firepower')
        self.assertEqual(adapter.vendor_name, 'Cisco Firepower')

    def test_get_unknown_vendor_raises(self):
        """Test that unknown vendor type raises ValueError"""
        from firelens.vendors import get_vendor_adapter

        with self.assertRaises(ValueError) as ctx:
            get_vendor_adapter('unknown_vendor')

        self.assertIn('Unknown vendor type', str(ctx.exception))
        self.assertIn('unknown_vendor', str(ctx.exception))


class TestVendorBaseClasses(unittest.TestCase):
    """Test vendor base class data structures"""

    def test_interface_sample_creation(self):
        """Test InterfaceSample dataclass"""
        from datetime import datetime, timezone
        from firelens.vendors.base import InterfaceSample

        sample = InterfaceSample(
            timestamp=datetime.now(timezone.utc),
            interface_name='ethernet1/1',
            rx_bytes=1000,
            tx_bytes=2000,
            rx_packets=100,
            tx_packets=200,
            rx_errors=0,
            tx_errors=0,
            success=True
        )

        self.assertEqual(sample.interface_name, 'ethernet1/1')
        self.assertEqual(sample.rx_bytes, 1000)
        self.assertEqual(sample.tx_bytes, 2000)
        self.assertTrue(sample.success)

    def test_session_stats_creation(self):
        """Test SessionStats dataclass"""
        from datetime import datetime, timezone
        from firelens.vendors.base import SessionStats

        stats = SessionStats(
            timestamp=datetime.now(timezone.utc),
            active_sessions=5000,
            max_sessions=100000,
            tcp_sessions=4000,
            udp_sessions=800,
            icmp_sessions=200,
            session_rate=50.5
        )

        self.assertEqual(stats.active_sessions, 5000)
        self.assertEqual(stats.max_sessions, 100000)
        self.assertEqual(stats.tcp_sessions, 4000)
        self.assertAlmostEqual(stats.session_rate, 50.5)

    def test_hardware_info_creation(self):
        """Test HardwareInfo dataclass"""
        from firelens.vendors.base import HardwareInfo

        info = HardwareInfo(
            vendor='Palo Alto Networks',
            model='PA-3260',
            serial='001234567890',
            hostname='datacenter-fw',
            sw_version='10.2.3',
            vendor_specific={'family': 'PA-3200 Series'}
        )

        self.assertEqual(info.vendor, 'Palo Alto Networks')
        self.assertEqual(info.model, 'PA-3260')
        self.assertEqual(info.vendor_specific['family'], 'PA-3200 Series')

    def test_hardware_info_default_vendor_specific(self):
        """Test HardwareInfo initializes vendor_specific to empty dict"""
        from firelens.vendors.base import HardwareInfo

        info = HardwareInfo(
            vendor='Test',
            model='Test-100',
            serial='123',
            hostname='test',
            sw_version='1.0'
        )

        self.assertIsNotNone(info.vendor_specific)
        self.assertEqual(info.vendor_specific, {})

    def test_system_metrics_creation(self):
        """Test SystemMetrics dataclass"""
        from datetime import datetime, timezone
        from firelens.vendors.base import SystemMetrics

        metrics = SystemMetrics(
            timestamp=datetime.now(timezone.utc),
            cpu_usage=45.5,
            memory_usage=60.0,
            vendor_metrics={'mgmt_cpu': 30.0, 'data_plane_cpu': 50.0}
        )

        self.assertAlmostEqual(metrics.cpu_usage, 45.5)
        self.assertAlmostEqual(metrics.memory_usage, 60.0)
        self.assertEqual(metrics.vendor_metrics['mgmt_cpu'], 30.0)


class TestPaloAltoAdapter(unittest.TestCase):
    """Test Palo Alto vendor adapter"""

    def test_adapter_properties(self):
        """Test Palo Alto adapter properties"""
        from firelens.vendors.palo_alto import PaloAltoAdapter

        adapter = PaloAltoAdapter()
        self.assertEqual(adapter.vendor_type, 'palo_alto')
        self.assertEqual(adapter.vendor_name, 'Palo Alto Networks')

    def test_supported_metrics(self):
        """Test Palo Alto supported metrics list"""
        from firelens.vendors.palo_alto import PaloAltoAdapter

        adapter = PaloAltoAdapter()
        metrics = adapter.get_supported_metrics()

        self.assertIn('cpu_usage', metrics)
        self.assertIn('mgmt_cpu', metrics)
        self.assertIn('data_plane_cpu', metrics)
        self.assertIn('pbuf_util_percent', metrics)
        self.assertIn('active_sessions', metrics)

    def test_hardware_fields(self):
        """Test Palo Alto hardware fields list"""
        from firelens.vendors.palo_alto import PaloAltoAdapter

        adapter = PaloAltoAdapter()
        fields = adapter.get_hardware_fields()

        self.assertIn('model', fields)
        self.assertIn('serial', fields)
        self.assertIn('hostname', fields)
        self.assertIn('sw_version', fields)

    def test_default_exclude_interfaces(self):
        """Test Palo Alto default interface exclusions"""
        from firelens.vendors.palo_alto import PaloAltoAdapter

        adapter = PaloAltoAdapter()
        excludes = adapter.get_default_exclude_interfaces()

        self.assertIn('mgmt', excludes)
        self.assertIn('loopback', excludes)
        self.assertIn('ha1', excludes)
        self.assertIn('tunnel', excludes)


class TestFortinetAdapter(unittest.TestCase):
    """Test Fortinet vendor adapter"""

    def test_adapter_properties(self):
        """Test Fortinet adapter properties"""
        from firelens.vendors.fortinet import FortinetAdapter

        adapter = FortinetAdapter()
        self.assertEqual(adapter.vendor_type, 'fortinet')
        self.assertEqual(adapter.vendor_name, 'Fortinet FortiGate')

    def test_supported_metrics(self):
        """Test Fortinet supported metrics list"""
        from firelens.vendors.fortinet import FortinetAdapter

        adapter = FortinetAdapter()
        metrics = adapter.get_supported_metrics()

        self.assertIn('cpu_usage', metrics)
        self.assertIn('memory_usage', metrics)
        self.assertIn('disk_usage', metrics)
        self.assertIn('active_sessions', metrics)
        self.assertIn('max_sessions', metrics)

    def test_hardware_fields(self):
        """Test Fortinet hardware fields list"""
        from firelens.vendors.fortinet import FortinetAdapter

        adapter = FortinetAdapter()
        fields = adapter.get_hardware_fields()

        self.assertIn('model', fields)
        self.assertIn('serial', fields)
        self.assertIn('hostname', fields)
        self.assertIn('sw_version', fields)
        self.assertIn('build', fields)

    def test_default_exclude_interfaces(self):
        """Test Fortinet default interface exclusions"""
        from firelens.vendors.fortinet import FortinetAdapter

        adapter = FortinetAdapter()
        excludes = adapter.get_default_exclude_interfaces()

        self.assertIn('mgmt', excludes)
        self.assertIn('fortilink', excludes)
        self.assertIn('ha1', excludes)
        self.assertIn('ssl.root', excludes)

    def test_create_client(self):
        """Test that adapter creates FortinetClient instance"""
        from firelens.vendors.fortinet import FortinetAdapter, FortinetClient

        adapter = FortinetAdapter()
        client = adapter.create_client('192.168.1.1', verify_ssl=False)

        self.assertIsInstance(client, FortinetClient)


class TestFortinetClient(unittest.TestCase):
    """Test Fortinet FortiGate API client"""

    def test_client_initialization(self):
        """Test FortinetClient initialization"""
        from firelens.vendors.fortinet import FortinetClient

        client = FortinetClient('192.168.1.1', verify_ssl=False)

        self.assertEqual(client.vendor_type, 'fortinet')
        self.assertEqual(client.vendor_name, 'Fortinet FortiGate')
        self.assertFalse(client.is_authenticated())

    def test_client_adds_https_prefix(self):
        """Test that client adds https:// prefix if missing"""
        from firelens.vendors.fortinet import FortinetClient

        client = FortinetClient('192.168.1.1')
        self.assertTrue(client._host.startswith('https://'))

        client2 = FortinetClient('https://192.168.1.1')
        self.assertEqual(client2._host, 'https://192.168.1.1')

    def test_set_vdom(self):
        """Test VDOM setting"""
        from firelens.vendors.fortinet import FortinetClient

        client = FortinetClient('192.168.1.1')
        self.assertEqual(client._vdom, 'root')  # Default

        client.set_vdom('customer1')
        self.assertEqual(client._vdom, 'customer1')

    @patch('firelens.vendors.fortinet.requests.Session')
    def test_authenticate_sets_bearer_header(self, mock_session_class):
        """Test that authentication sets Bearer token header"""
        from firelens.vendors.fortinet import FortinetClient

        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        mock_response = Mock()
        mock_response.json.return_value = {
            'results': {
                'hostname': 'FW-01',
                'serial': 'FG100F1234567890',
                'model_name': 'FortiGate-100F',
                'version': '7.4.0',
                'build': 2573
            }
        }
        mock_response.raise_for_status = Mock()
        mock_session.get.return_value = mock_response

        # Test authentication
        client = FortinetClient('192.168.1.1', verify_ssl=False)
        result = client.authenticate('admin', 'test_api_token')

        self.assertTrue(result)
        self.assertTrue(client.is_authenticated())

        # Verify Bearer header was set
        mock_session.headers.update.assert_called()
        call_args = mock_session.headers.update.call_args[0][0]
        self.assertIn('Authorization', call_args)
        self.assertEqual(call_args['Authorization'], 'Bearer test_api_token')

    @patch('firelens.vendors.fortinet.requests.Session')
    def test_authenticate_caches_hardware_info(self, mock_session_class):
        """Test that authentication caches hardware info from response"""
        from firelens.vendors.fortinet import FortinetClient

        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        mock_response = Mock()
        mock_response.json.return_value = {
            'results': {
                'hostname': 'FW-01',
                'serial': 'FG100F1234567890',
                'model_name': 'FortiGate-100F',
                'version': '7.4.0',
                'build': 2573
            }
        }
        mock_response.raise_for_status = Mock()
        mock_session.get.return_value = mock_response

        # Test
        client = FortinetClient('192.168.1.1', verify_ssl=False)
        client.authenticate('admin', 'token')

        hw_info = client.get_hardware_info()
        self.assertEqual(hw_info.model, 'FortiGate-100F')
        self.assertEqual(hw_info.serial, 'FG100F1234567890')
        self.assertEqual(hw_info.hostname, 'FW-01')
        self.assertIn('7.4.0', hw_info.sw_version)

    @patch('firelens.vendors.fortinet.requests.Session')
    def test_collect_system_metrics(self, mock_session_class):
        """Test system metrics collection"""
        from firelens.vendors.fortinet import FortinetClient

        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # First call for auth, second for metrics
        auth_response = Mock()
        auth_response.json.return_value = {'results': {'hostname': 'FW-01', 'model_name': 'FortiGate-100F', 'version': '7.4.0', 'build': 2573}}
        auth_response.raise_for_status = Mock()

        metrics_response = Mock()
        metrics_response.json.return_value = {
            'results': {
                'cpu': [{'current': 25, 'allowed': 100}],
                'memory': [{'used': 2048, 'total': 4096}],
                'disk': [{'used': 1024, 'total': 8192}]
            }
        }
        metrics_response.raise_for_status = Mock()

        mock_session.get.side_effect = [auth_response, metrics_response]

        # Test
        client = FortinetClient('192.168.1.1', verify_ssl=False)
        client.authenticate('admin', 'token')
        metrics = client.collect_system_metrics()

        self.assertEqual(metrics.cpu_usage, 25.0)
        self.assertEqual(metrics.memory_usage, 50.0)  # 2048/4096 * 100
        self.assertIn('disk_usage', metrics.vendor_metrics)

    @patch('firelens.vendors.fortinet.requests.Session')
    def test_collect_interface_stats(self, mock_session_class):
        """Test interface statistics collection"""
        from firelens.vendors.fortinet import FortinetClient

        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        auth_response = Mock()
        auth_response.json.return_value = {'results': {'hostname': 'FW-01', 'model_name': 'FortiGate-100F', 'version': '7.4.0', 'build': 2573}}
        auth_response.raise_for_status = Mock()

        interface_response = Mock()
        interface_response.json.return_value = {
            'results': [
                {
                    'name': 'port1',
                    'link': True,
                    'speed': 1000,
                    'tx_bytes': 1234567890,
                    'rx_bytes': 9876543210,
                    'tx_packets': 12345678,
                    'rx_packets': 98765432,
                    'tx_errors': 0,
                    'rx_errors': 5
                },
                {
                    'name': 'port2',
                    'link': True,
                    'speed': 1000,
                    'tx_bytes': 1000,
                    'rx_bytes': 2000,
                    'tx_packets': 10,
                    'rx_packets': 20,
                    'tx_errors': 0,
                    'rx_errors': 0
                }
            ]
        }
        interface_response.raise_for_status = Mock()

        mock_session.get.side_effect = [auth_response, interface_response]

        # Test
        client = FortinetClient('192.168.1.1', verify_ssl=False)
        client.authenticate('admin', 'token')
        stats = client.collect_interface_stats()

        self.assertIn('port1', stats)
        self.assertIn('port2', stats)
        self.assertEqual(stats['port1'].rx_bytes, 9876543210)
        self.assertEqual(stats['port1'].tx_bytes, 1234567890)
        self.assertEqual(stats['port1'].rx_errors, 5)
        self.assertTrue(stats['port1'].success)

    @patch('firelens.vendors.fortinet.requests.Session')
    def test_collect_interface_stats_with_filter(self, mock_session_class):
        """Test interface statistics collection with filter"""
        from firelens.vendors.fortinet import FortinetClient

        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        auth_response = Mock()
        auth_response.json.return_value = {'results': {'hostname': 'FW-01', 'model_name': 'FortiGate-100F', 'version': '7.4.0', 'build': 2573}}
        auth_response.raise_for_status = Mock()

        interface_response = Mock()
        interface_response.json.return_value = {
            'results': [
                {'name': 'port1', 'tx_bytes': 100, 'rx_bytes': 200, 'tx_packets': 1, 'rx_packets': 2, 'tx_errors': 0, 'rx_errors': 0},
                {'name': 'port2', 'tx_bytes': 300, 'rx_bytes': 400, 'tx_packets': 3, 'rx_packets': 4, 'tx_errors': 0, 'rx_errors': 0},
                {'name': 'port3', 'tx_bytes': 500, 'rx_bytes': 600, 'tx_packets': 5, 'rx_packets': 6, 'tx_errors': 0, 'rx_errors': 0}
            ]
        }
        interface_response.raise_for_status = Mock()

        mock_session.get.side_effect = [auth_response, interface_response]

        # Test with filter
        client = FortinetClient('192.168.1.1', verify_ssl=False)
        client.authenticate('admin', 'token')
        stats = client.collect_interface_stats(interfaces=['port1', 'port3'])

        self.assertIn('port1', stats)
        self.assertIn('port3', stats)
        self.assertNotIn('port2', stats)

    @patch('firelens.vendors.fortinet.requests.Session')
    def test_collect_session_stats(self, mock_session_class):
        """Test session statistics collection"""
        from firelens.vendors.fortinet import FortinetClient

        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        auth_response = Mock()
        auth_response.json.return_value = {'results': {'hostname': 'FW-01', 'model_name': 'FortiGate-100F', 'version': '7.4.0', 'build': 2573}}
        auth_response.raise_for_status = Mock()

        # Session stats now come from /monitor/system/resource/usage
        resource_response = Mock()
        resource_response.json.return_value = {
            'results': {
                'session': [{
                    'current': 50000,
                    'historical': {
                        '24-hour': {'max': 1000000}
                    }
                }]
            }
        }
        resource_response.raise_for_status = Mock()

        mock_session.get.side_effect = [auth_response, resource_response]

        # Test
        client = FortinetClient('192.168.1.1', verify_ssl=False)
        client.authenticate('admin', 'token')
        stats = client.collect_session_stats()

        self.assertEqual(stats.active_sessions, 50000)
        self.assertEqual(stats.max_sessions, 1000000)

    @patch('firelens.vendors.fortinet.requests.Session')
    def test_discover_interfaces(self, mock_session_class):
        """Test interface discovery"""
        from firelens.vendors.fortinet import FortinetClient

        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        auth_response = Mock()
        auth_response.json.return_value = {'results': {'hostname': 'FW-01', 'model_name': 'FortiGate-100F', 'version': '7.4.0', 'build': 2573}}
        auth_response.raise_for_status = Mock()

        interface_response = Mock()
        interface_response.json.return_value = {
            'results': [
                {'name': 'port1'},
                {'name': 'port2'},
                {'name': 'wan1'},
                {'name': 'internal'}
            ]
        }
        interface_response.raise_for_status = Mock()

        mock_session.get.side_effect = [auth_response, interface_response]

        # Test
        client = FortinetClient('192.168.1.1', verify_ssl=False)
        client.authenticate('admin', 'token')
        interfaces = client.discover_interfaces()

        self.assertEqual(len(interfaces), 4)
        self.assertIn('port1', interfaces)
        self.assertIn('port2', interfaces)
        self.assertIn('wan1', interfaces)
        self.assertIn('internal', interfaces)

    @patch('firelens.vendors.fortinet.requests.Session')
    def test_vdom_added_to_requests(self, mock_session_class):
        """Test that VDOM parameter is added to all API requests"""
        from firelens.vendors.fortinet import FortinetClient

        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        mock_response = Mock()
        mock_response.json.return_value = {'results': {'hostname': 'FW-01', 'model_name': 'FortiGate-100F', 'version': '7.4.0', 'build': 2573}}
        mock_response.raise_for_status = Mock()
        mock_session.get.return_value = mock_response

        # Test with custom VDOM
        client = FortinetClient('192.168.1.1', verify_ssl=False)
        client.set_vdom('customer1')
        client.authenticate('admin', 'token')

        # Verify VDOM was included in request params
        call_args = mock_session.get.call_args
        self.assertIn('params', call_args.kwargs)
        self.assertEqual(call_args.kwargs['params']['vdom'], 'customer1')

    def test_close_cleans_up_session(self):
        """Test that close() cleans up session properly"""
        from firelens.vendors.fortinet import FortinetClient

        client = FortinetClient('192.168.1.1', verify_ssl=False)
        client._session = Mock()
        client._authenticated = True
        client._api_token = 'test_token'

        client.close()

        self.assertIsNone(client._session)
        self.assertFalse(client._authenticated)
        self.assertIsNone(client._api_token)

    @patch('firelens.vendors.fortinet.requests.Session')
    def test_authentication_failure(self, mock_session_class):
        """Test handling of authentication failure"""
        from firelens.vendors.fortinet import FortinetClient
        import requests

        # Setup mock to raise HTTP error
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError('401 Unauthorized')
        mock_session.get.return_value = mock_response

        # Test
        client = FortinetClient('192.168.1.1', verify_ssl=False)
        result = client.authenticate('admin', 'bad_token')

        self.assertFalse(result)
        self.assertFalse(client.is_authenticated())


class TestCiscoFirepowerAdapter(unittest.TestCase):
    """Test Cisco Firepower vendor adapter"""

    def test_adapter_properties(self):
        """Test Cisco Firepower adapter properties"""
        from firelens.vendors.cisco_firepower import CiscoFirepowerAdapter

        adapter = CiscoFirepowerAdapter()
        self.assertEqual(adapter.vendor_type, 'cisco_firepower')
        self.assertEqual(adapter.vendor_name, 'Cisco Firepower')

    def test_supported_metrics(self):
        """Test Cisco Firepower supported metrics list"""
        from firelens.vendors.cisco_firepower import CiscoFirepowerAdapter

        adapter = CiscoFirepowerAdapter()
        metrics = adapter.get_supported_metrics()

        self.assertIn('cpu_usage', metrics)
        self.assertIn('memory_usage', metrics)
        self.assertIn('active_connections', metrics)

    def test_client_raises_not_implemented(self):
        """Test Cisco Firepower client methods raise NotImplementedError"""
        from firelens.vendors.cisco_firepower import CiscoFirepowerClient

        client = CiscoFirepowerClient('https://192.168.1.1', verify_ssl=False)

        with self.assertRaises(NotImplementedError):
            client.authenticate('admin', 'password')

        with self.assertRaises(NotImplementedError):
            client.collect_system_metrics()

        with self.assertRaises(NotImplementedError):
            client.collect_interface_stats()

        with self.assertRaises(NotImplementedError):
            client.collect_session_stats()

        with self.assertRaises(NotImplementedError):
            client.discover_interfaces()

    def test_default_exclude_interfaces(self):
        """Test Cisco Firepower default interface exclusions"""
        from firelens.vendors.cisco_firepower import CiscoFirepowerAdapter

        adapter = CiscoFirepowerAdapter()
        excludes = adapter.get_default_exclude_interfaces()

        self.assertIn('Management', excludes)
        self.assertIn('Diagnostic', excludes)
        self.assertIn('nlp_int_tap', excludes)


class TestConfigVendorType(unittest.TestCase):
    """Test vendor type field in configuration"""

    def test_config_has_type_field(self):
        """Test that EnhancedFirewallConfig has type field"""
        from firelens.config import EnhancedFirewallConfig

        config = EnhancedFirewallConfig(
            name='test_fw',
            host='https://192.168.1.1',
            username='admin',
            password='password',
            type='palo_alto'
        )

        self.assertEqual(config.type, 'palo_alto')

    def test_config_default_type_is_palo_alto(self):
        """Test that default vendor type is palo_alto"""
        from firelens.config import EnhancedFirewallConfig

        config = EnhancedFirewallConfig(
            name='test_fw',
            host='https://192.168.1.1',
            username='admin',
            password='password'
        )

        self.assertEqual(config.type, 'palo_alto')

    def test_config_validation_rejects_invalid_type(self):
        """Test that validation rejects invalid vendor types"""
        from firelens.config import EnhancedConfigManager, EnhancedFirewallConfig

        manager = EnhancedConfigManager.__new__(EnhancedConfigManager)
        manager.global_config = type('GlobalConfig', (), {
            'web_port': 8080
        })()
        manager.firewalls = {
            'test_fw': EnhancedFirewallConfig(
                name='test_fw',
                host='https://192.168.1.1',
                username='admin',
                password='password',
                type='invalid_vendor'
            )
        }

        errors = manager.validate_enhanced_config()
        self.assertTrue(any('invalid_vendor' in e for e in errors))
        self.assertTrue(any('unsupported vendor type' in e for e in errors))

    def test_supported_vendor_types_constant(self):
        """Test SUPPORTED_VENDOR_TYPES constant"""
        from firelens.config import SUPPORTED_VENDOR_TYPES

        self.assertIn('palo_alto', SUPPORTED_VENDOR_TYPES)
        self.assertIn('fortinet', SUPPORTED_VENDOR_TYPES)
        self.assertIn('cisco_firepower', SUPPORTED_VENDOR_TYPES)

    def test_config_has_vdom_field(self):
        """Test that EnhancedFirewallConfig has vdom field"""
        from firelens.config import EnhancedFirewallConfig

        config = EnhancedFirewallConfig(
            name='test_fw',
            host='https://192.168.1.1',
            username='admin',
            password='token',
            type='fortinet',
            vdom='customer1'
        )

        self.assertEqual(config.vdom, 'customer1')

    def test_config_default_vdom_is_root(self):
        """Test that default VDOM is 'root'"""
        from firelens.config import EnhancedFirewallConfig

        config = EnhancedFirewallConfig(
            name='test_fw',
            host='https://192.168.1.1',
            username='admin',
            password='token',
            type='fortinet'
        )

        self.assertEqual(config.vdom, 'root')


if __name__ == '__main__':
    unittest.main()
