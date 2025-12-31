"""
Property-based tests for service monitoring functionality.

This module contains property-based tests that validate the correctness
of service monitoring including TCP/UDP port checks, HTTP endpoint monitoring,
and plugin system functionality.

Tests validate Properties 17-18 from the design document:
- Property 17: Service check protocol support
- Property 18: Plugin execution safety
"""

# Configure Django settings if not already configured
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nms.settings')

import django
django.setup()

import pytest
import asyncio
import tempfile
import socket
from unittest.mock import Mock, patch, AsyncMock
from hypothesis import given, strategies as st, settings, assume, example
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, invariant
from hypothesis.extra.django import TestCase as HypothesisTestCase
from django.test import TestCase
from django.utils import timezone

from monitoring.models import Host, Location, DeviceGroup, MonitoringMetric
from monitoring.service_monitor import (
    ServiceMonitoringService, PortChecker, HTTPChecker, PluginSystem,
    ServiceCheckResult, check_host_services, check_tcp_port, check_udp_port,
    check_http_endpoint
)


# Test data strategies
@st.composite
def valid_host_data(draw):
    """Generate valid host data for service monitoring."""
    hostname = draw(st.text(min_size=1, max_size=50, alphabet=st.characters(
        whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-.'
    )).filter(lambda x: x and not x.startswith('.') and not x.endswith('.')))
    
    # Generate valid IP address
    ip_parts = [draw(st.integers(min_value=1, max_value=254)) for _ in range(4)]
    ip_address = '.'.join(map(str, ip_parts))
    
    return {
        'hostname': hostname,
        'ip_address': ip_address,
        'monitoring_enabled': True,
        'service_checks_enabled': True
    }


@st.composite
def port_list_strategy(draw):
    """Generate comma-separated port lists."""
    ports = draw(st.lists(
        st.integers(min_value=1, max_value=65535),
        min_size=0, max_size=5, unique=True
    ))
    return ','.join(map(str, ports))


@st.composite
def url_list_strategy(draw):
    """Generate newline-separated URL lists."""
    protocols = ['http', 'https']
    domains = ['example.com', 'test.org', 'localhost']
    
    urls = []
    for _ in range(draw(st.integers(min_value=0, max_value=3))):
        protocol = draw(st.sampled_from(protocols))
        domain = draw(st.sampled_from(domains))
        port = draw(st.integers(min_value=80, max_value=8080))
        path = draw(st.text(alphabet=st.characters(
            whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='/-_'
        ), max_size=20))
        
        url = f"{protocol}://{domain}:{port}"
        if path and not path.startswith('/'):
            url += '/' + path
        elif path:
            url += path
            
        urls.append(url)
    
    return '\n'.join(urls)


class TestServiceMonitoringProperties(HypothesisTestCase):
    """Property-based tests for service monitoring system."""
    
    def setUp(self):
        """Set up test environment."""
        self.location = Location.objects.create(
            name="Test Location",
            address="Test Address"
        )
        self.group = DeviceGroup.objects.create(
            name="Test Group",
            description="Test group for service monitoring"
        )
    
    @given(host_data=valid_host_data())
    @settings(max_examples=50, deadline=5000)
    def test_property_service_monitoring_completeness(self, host_data):
        """
        Property 17a: Service monitoring completeness
        
        For any host with service checks enabled, all configured services
        should be checked and results should be consistent.
        """
        # Create host
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            **host_data
        )
        
        # Test with no services configured
        service = ServiceMonitoringService()
        
        async def run_test():
            results = await service.check_host_services(host)
            
            # Should return empty results for host with no services
            assert isinstance(results, dict)
            assert 'tcp_ports' in results
            assert 'udp_ports' in results
            assert 'http_endpoints' in results
            
            # All result lists should be empty
            assert len(results['tcp_ports']) == 0
            assert len(results['udp_ports']) == 0
            assert len(results['http_endpoints']) == 0
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_test())
        finally:
            loop.close()
    
    @given(
        host_data=valid_host_data(),
        tcp_ports=port_list_strategy(),
        udp_ports=port_list_strategy()
    )
    @settings(max_examples=30, deadline=10000)
    def test_property_port_check_consistency(self, host_data, tcp_ports, udp_ports):
        """
        Property 17b: Port check protocol support consistency
        
        Port checks should consistently handle valid and invalid ports,
        and results should have proper structure.
        """
        # Create host with port configurations
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            tcp_ports=tcp_ports,
            udp_ports=udp_ports,
            **host_data
        )
        
        service = ServiceMonitoringService()
        
        async def run_test():
            with patch('monitoring.service_monitor.asyncio.open_connection') as mock_tcp, \
                 patch('socket.socket') as mock_socket:
                
                # Mock successful TCP connections
                mock_tcp.return_value = (AsyncMock(), AsyncMock())
                
                # Mock UDP socket
                mock_udp = Mock()
                mock_socket.return_value = mock_udp
                mock_udp.sendto.return_value = None
                mock_udp.recvfrom.side_effect = socket.timeout()  # Simulate timeout (normal for UDP)
                
                results = await service.check_host_services(host)
                
                # Verify result structure
                assert isinstance(results, dict)
                assert 'tcp_ports' in results
                assert 'udp_ports' in results
                assert 'http_endpoints' in results
                
                # Parse expected ports
                expected_tcp = service._parse_ports(tcp_ports)
                expected_udp = service._parse_ports(udp_ports)
                
                # Verify correct number of results
                assert len(results['tcp_ports']) == len(expected_tcp)
                assert len(results['udp_ports']) == len(expected_udp)
                
                # Verify all results are ServiceCheckResult objects
                for result in results['tcp_ports']:
                    assert isinstance(result, ServiceCheckResult)
                    assert hasattr(result, 'success')
                    assert hasattr(result, 'response_time')
                    assert hasattr(result, 'timestamp')
                    assert isinstance(result.response_time, (int, float))
                    assert result.response_time >= 0
                
                for result in results['udp_ports']:
                    assert isinstance(result, ServiceCheckResult)
                    assert hasattr(result, 'success')
                    assert hasattr(result, 'response_time')
                    assert hasattr(result, 'timestamp')
                    assert isinstance(result.response_time, (int, float))
                    assert result.response_time >= 0
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_test())
        finally:
            loop.close()
    
    @given(
        host_data=valid_host_data(),
        urls=url_list_strategy()
    )
    @settings(max_examples=20, deadline=10000)
    def test_property_http_check_consistency(self, host_data, urls):
        """
        Property 17c: HTTP endpoint monitoring consistency
        
        HTTP checks should handle various URL formats and return
        consistent results with proper error handling.
        """
        # Create host with HTTP URLs
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            http_urls=urls,
            **host_data
        )
        
        service = ServiceMonitoringService()
        
        async def run_test():
            with patch('aiohttp.ClientSession.get') as mock_get:
                # Mock HTTP response
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.text.return_value = "OK"
                mock_response.headers = {'Content-Type': 'text/html'}
                mock_get.return_value.__aenter__.return_value = mock_response
                
                results = await service.check_host_services(host)
                
                # Verify result structure
                assert isinstance(results, dict)
                assert 'http_endpoints' in results
                
                # Parse expected URLs
                expected_urls = service._parse_urls(urls)
                
                # Verify correct number of results
                assert len(results['http_endpoints']) == len(expected_urls)
                
                # Verify all results are ServiceCheckResult objects
                for result in results['http_endpoints']:
                    assert isinstance(result, ServiceCheckResult)
                    assert hasattr(result, 'success')
                    assert hasattr(result, 'response_time')
                    assert hasattr(result, 'status_code')
                    assert hasattr(result, 'timestamp')
                    assert isinstance(result.response_time, (int, float))
                    assert result.response_time >= 0
                    
                    if result.success:
                        assert result.status_code == 200
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_test())
        finally:
            loop.close()
    
    @given(
        port=st.integers(min_value=1, max_value=65535),
        timeout=st.integers(min_value=1, max_value=10)
    )
    @settings(max_examples=20, deadline=5000)
    def test_property_port_checker_timeout_handling(self, port, timeout):
        """
        Property 17d: Port checker timeout handling
        
        Port checkers should properly handle timeouts and return
        consistent results within expected time bounds.
        """
        checker = PortChecker(timeout=timeout)
        
        async def run_test():
            # Test with unreachable host (should timeout)
            result = await checker.check_tcp_port('192.0.2.1', port)  # TEST-NET-1
            
            # Verify timeout behavior
            assert isinstance(result, ServiceCheckResult)
            assert not result.success  # Should fail for unreachable host
            assert result.response_time >= timeout * 1000 * 0.9  # Allow 10% tolerance
            assert 'timeout' in result.error_message.lower() or 'unreachable' in result.error_message.lower()
            assert result.additional_data['port'] == port
            assert result.additional_data['protocol'] == 'tcp'
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_test())
        finally:
            loop.close()
    
    def test_property_plugin_system_safety(self):
        """
        Property 18: Plugin execution safety
        
        Plugin system should safely execute plugins with proper
        sandboxing, timeout handling, and error isolation.
        """
        # Create temporary plugin directory
        with tempfile.TemporaryDirectory() as plugin_dir:
            # Create a test plugin
            plugin_content = '''
class Plugin:
    async def check(self, host, **kwargs):
        from monitoring.service_monitor import ServiceCheckResult
        return ServiceCheckResult(
            success=True,
            response_time=100.0,
            additional_data={'plugin_test': True}
        )
'''
            plugin_path = os.path.join(plugin_dir, 'test_plugin.py')
            with open(plugin_path, 'w') as f:
                f.write(plugin_content)
            
            # Initialize plugin system
            plugin_system = PluginSystem(plugin_dir=plugin_dir)
            
            # Verify plugin loaded
            assert 'test_plugin' in plugin_system.get_available_plugins()
            
            # Create test host
            host = Host.objects.create(
                location=self.location,
                group=self.group,
                hostname='test-host',
                ip_address='192.168.1.1'
            )
            
            async def run_test():
                # Execute plugin
                result = await plugin_system.execute_plugin('test_plugin', host)
                
                # Verify result
                assert isinstance(result, ServiceCheckResult)
                assert result.success
                assert result.response_time == 100.0
                assert result.additional_data['plugin_test'] is True
                
                # Test non-existent plugin
                result = await plugin_system.execute_plugin('nonexistent', host)
                assert isinstance(result, ServiceCheckResult)
                assert not result.success
                assert 'not found' in result.error_message
            
            # Run async test
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_test())
            finally:
                loop.close()
    
    def test_property_plugin_timeout_safety(self):
        """
        Property 18b: Plugin timeout safety
        
        Plugin system should enforce timeouts and handle
        long-running or hanging plugins safely.
        """
        # Create temporary plugin directory
        with tempfile.TemporaryDirectory() as plugin_dir:
            # Create a hanging plugin
            plugin_content = '''
import asyncio

class Plugin:
    async def check(self, host, **kwargs):
        # Simulate hanging plugin
        await asyncio.sleep(60)  # Sleep longer than timeout
        from monitoring.service_monitor import ServiceCheckResult
        return ServiceCheckResult(success=True, response_time=0)
'''
            plugin_path = os.path.join(plugin_dir, 'hanging_plugin.py')
            with open(plugin_path, 'w') as f:
                f.write(plugin_content)
            
            # Initialize plugin system
            plugin_system = PluginSystem(plugin_dir=plugin_dir)
            
            # Create test host
            host = Host.objects.create(
                location=self.location,
                group=self.group,
                hostname='test-host',
                ip_address='192.168.1.1'
            )
            
            async def run_test():
                import time
                start_time = time.time()
                
                # Execute hanging plugin (should timeout)
                result = await plugin_system.execute_plugin('hanging_plugin', host)
                
                execution_time = time.time() - start_time
                
                # Verify timeout behavior
                assert isinstance(result, ServiceCheckResult)
                assert not result.success
                assert 'timeout' in result.error_message.lower()
                assert execution_time < 35  # Should timeout before 35 seconds
                assert result.response_time == 30000  # 30 second timeout
            
            # Run async test
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_test())
            finally:
                loop.close()
    
    @given(
        ports_string=st.text(max_size=100),
        urls_string=st.text(max_size=200)
    )
    @settings(max_examples=50, deadline=2000)
    def test_property_input_parsing_robustness(self, ports_string, urls_string):
        """
        Property 17e: Input parsing robustness
        
        Service monitoring should robustly handle malformed
        port lists and URL strings without crashing.
        """
        service = ServiceMonitoringService()
        
        # Test port parsing
        try:
            parsed_ports = service._parse_ports(ports_string)
            # Should return list of valid integers
            assert isinstance(parsed_ports, list)
            for port in parsed_ports:
                assert isinstance(port, int)
                assert 1 <= port <= 65535
        except Exception as e:
            # Should not raise exceptions, but log warnings
            assert False, f"Port parsing should not raise exceptions: {e}"
        
        # Test URL parsing
        try:
            parsed_urls = service._parse_urls(urls_string)
            # Should return list of strings
            assert isinstance(parsed_urls, list)
            for url in parsed_urls:
                assert isinstance(url, str)
                # Should have added http:// if no scheme
                assert url.startswith(('http://', 'https://'))
        except Exception as e:
            # Should not raise exceptions
            assert False, f"URL parsing should not raise exceptions: {e}"
    
    def test_property_metric_storage_consistency(self):
        """
        Property 17f: Metric storage consistency
        
        Service check results should be consistently stored
        in the database with proper data integrity.
        """
        # Create test host
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            hostname='test-host',
            ip_address='192.168.1.1',
            tcp_ports='80,443',
            service_checks_enabled=True
        )
        
        service = ServiceMonitoringService()
        
        async def run_test():
            with patch('monitoring.service_monitor.asyncio.open_connection') as mock_tcp:
                # Mock successful connection
                mock_tcp.return_value = (AsyncMock(), AsyncMock())
                
                # Clear existing metrics
                MonitoringMetric.objects.filter(host=host).delete()
                
                # Run service checks
                results = await service.check_host_services(host)
                
                # Verify metrics were stored
                metrics = MonitoringMetric.objects.filter(
                    host=host,
                    metric_type='service_check'
                )
                
                # Should have metrics for each TCP port (response_time and status)
                expected_tcp_ports = service._parse_ports('80,443')
                expected_metrics = len(expected_tcp_ports) * 2  # 2 metrics per port
                
                assert metrics.count() == expected_metrics
                
                # Verify metric structure
                for metric in metrics:
                    assert metric.host == host
                    assert metric.metric_type == 'service_check'
                    assert metric.value is not None
                    assert isinstance(metric.value, (int, float))
                    assert metric.additional_data is not None
                    assert 'service_type' in metric.additional_data
                    assert 'service_name' in metric.additional_data
                    assert 'success' in metric.additional_data
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_test())
        finally:
            loop.close()


class ServiceMonitoringStateMachine(RuleBasedStateMachine):
    """
    Stateful property-based testing for service monitoring system.
    
    This tests the service monitoring system through various state transitions
    and verifies that invariants hold throughout the execution.
    """
    
    def __init__(self):
        super().__init__()
        self.hosts = []
        self.service_results = {}
        
        # Set up test environment
        self.location = Location.objects.create(
            name="State Test Location",
            address="State Test Address"
        )
        self.group = DeviceGroup.objects.create(
            name="State Test Group",
            description="State test group"
        )
    
    @initialize()
    def setup(self):
        """Initialize the state machine."""
        # Clear any existing data
        Host.objects.filter(location=self.location).delete()
        self.hosts = []
        self.service_results = {}
    
    @rule(
        hostname=st.text(min_size=1, max_size=20, alphabet=st.characters(
            whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-'
        )),
        tcp_ports=port_list_strategy(),
        service_enabled=st.booleans()
    )
    def add_host(self, hostname, tcp_ports, service_enabled):
        """Add a new host to monitor."""
        assume(len(self.hosts) < 10)  # Limit number of hosts
        
        # Generate unique hostname
        hostname = f"{hostname}_{len(self.hosts)}"
        
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            hostname=hostname,
            ip_address=f"192.168.1.{len(self.hosts) + 1}",
            tcp_ports=tcp_ports,
            monitoring_enabled=True,
            service_checks_enabled=service_enabled
        )
        
        self.hosts.append(host)
        self.service_results[host.id] = None
    
    @rule()
    def monitor_services(self):
        """Monitor services for all hosts."""
        assume(len(self.hosts) > 0)
        
        async def run_monitoring():
            service = ServiceMonitoringService()
            
            with patch('monitoring.service_monitor.asyncio.open_connection') as mock_tcp:
                # Mock successful connections
                mock_tcp.return_value = (AsyncMock(), AsyncMock())
                
                for host in self.hosts:
                    if host.service_checks_enabled:
                        results = await service.check_host_services(host)
                        self.service_results[host.id] = results
        
        # Run async monitoring
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_monitoring())
        finally:
            loop.close()
    
    @rule(host_index=st.integers(min_value=0, max_value=9))
    def toggle_service_monitoring(self, host_index):
        """Toggle service monitoring for a host."""
        assume(host_index < len(self.hosts))
        
        host = self.hosts[host_index]
        host.service_checks_enabled = not host.service_checks_enabled
        host.save(update_fields=['service_checks_enabled'])
    
    @invariant()
    def service_results_consistency(self):
        """Verify service results are consistent with host configuration."""
        for host in self.hosts:
            if host.id in self.service_results and self.service_results[host.id] is not None:
                results = self.service_results[host.id]
                
                # Results should be a dictionary
                assert isinstance(results, dict)
                assert 'tcp_ports' in results
                assert 'udp_ports' in results
                assert 'http_endpoints' in results
                
                # If service checks are disabled, should have empty results
                if not host.service_checks_enabled:
                    assert len(results['tcp_ports']) == 0
                    assert len(results['udp_ports']) == 0
                    assert len(results['http_endpoints']) == 0
                else:
                    # Should have results matching configured ports
                    service = ServiceMonitoringService()
                    expected_tcp = service._parse_ports(host.tcp_ports or '')
                    assert len(results['tcp_ports']) == len(expected_tcp)
    
    @invariant()
    def host_data_integrity(self):
        """Verify host data integrity is maintained."""
        for host in self.hosts:
            # Refresh from database
            host.refresh_from_db()
            
            # Basic data integrity checks
            assert host.hostname is not None
            assert host.ip_address is not None
            assert host.location == self.location
            assert host.group == self.group
            assert isinstance(host.monitoring_enabled, bool)
            assert isinstance(host.service_checks_enabled, bool)


# Test runner for stateful tests
TestServiceMonitoringState = ServiceMonitoringStateMachine.TestCase


# Example-based tests for edge cases
class TestServiceMonitoringExamples(TestCase):
    """Example-based tests for specific edge cases."""
    
    def setUp(self):
        """Set up test environment."""
        self.location = Location.objects.create(
            name="Example Location",
            address="Example Address"
        )
        self.group = DeviceGroup.objects.create(
            name="Example Group",
            description="Example group"
        )
    
    def test_empty_port_configuration(self):
        """Test service monitoring with empty port configuration."""
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            hostname='empty-config',
            ip_address='192.168.1.1',
            tcp_ports='',
            udp_ports='',
            http_urls='',
            service_checks_enabled=True
        )
        
        service = ServiceMonitoringService()
        
        async def run_test():
            results = await service.check_host_services(host)
            
            # Should return empty results
            assert len(results['tcp_ports']) == 0
            assert len(results['udp_ports']) == 0
            assert len(results['http_endpoints']) == 0
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_test())
        finally:
            loop.close()
    
    def test_malformed_port_configuration(self):
        """Test service monitoring with malformed port configuration."""
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            hostname='malformed-config',
            ip_address='192.168.1.1',
            tcp_ports='80,abc,443,99999,-1',  # Mix of valid and invalid
            service_checks_enabled=True
        )
        
        service = ServiceMonitoringService()
        
        # Should only parse valid ports
        parsed_ports = service._parse_ports(host.tcp_ports)
        assert parsed_ports == [80, 443]  # Only valid ports
    
    def test_url_normalization(self):
        """Test URL normalization in HTTP monitoring."""
        service = ServiceMonitoringService()
        
        # Test various URL formats
        test_urls = "example.com\nhttp://test.org\nhttps://secure.com:8443\nlocalhost:3000/api"
        parsed_urls = service._parse_urls(test_urls)
        
        expected = [
            'http://example.com',
            'http://test.org',
            'https://secure.com:8443',
            'http://localhost:3000/api'
        ]
        
        assert parsed_urls == expected


if __name__ == '__main__':
    pytest.main([__file__])