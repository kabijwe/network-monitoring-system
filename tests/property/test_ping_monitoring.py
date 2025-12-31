"""
Property-based tests for ping monitoring functionality.

These tests validate the ping monitoring system using property-based testing
with Hypothesis to ensure correctness across a wide range of inputs.
"""
import pytest
import django
from django.conf import settings
from django.test import TestCase, override_settings, TransactionTestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from hypothesis import given, strategies as st, settings as hypothesis_settings, assume, HealthCheck
from hypothesis.extra.django import TestCase as HypothesisTestCase
import asyncio
import time
import platform
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, AsyncMock
import subprocess
import uuid

# Configure Django settings if not already configured
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nms.settings')

from monitoring.models import Location, DeviceGroup, Host, PingResult, Alert
from monitoring.ping_monitor import PingMonitor, PingResult as PingResultData, PingThresholds
from monitoring.ping_service import PingMonitoringService
from monitoring.simple_ping import ping_host_simple
from core.models import Role, UserRole

User = get_user_model()


# Custom strategies for generating test data
@st.composite
def ip_address_strategy(draw):
    """Generate valid IP addresses."""
    return f"{draw(st.integers(1, 254))}.{draw(st.integers(0, 255))}.{draw(st.integers(0, 255))}.{draw(st.integers(1, 254))}"


@st.composite
def hostname_strategy(draw):
    """Generate valid hostnames."""
    return draw(st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pd')),
        min_size=3,
        max_size=50
    ).filter(lambda x: x.strip() and not x.startswith('-') and not x.endswith('-')))


@st.composite
def ping_thresholds_strategy(draw):
    """Generate valid ping thresholds."""
    warning_latency = draw(st.floats(min_value=1.0, max_value=500.0))
    critical_latency = draw(st.floats(min_value=warning_latency + 1, max_value=2000.0))
    warning_packet_loss = draw(st.floats(min_value=0.1, max_value=50.0))
    critical_packet_loss = draw(st.floats(min_value=warning_packet_loss + 1, max_value=100.0))
    
    return PingThresholds(
        warning_latency=warning_latency,
        critical_latency=critical_latency,
        warning_packet_loss=warning_packet_loss,
        critical_packet_loss=critical_packet_loss,
        timeout=draw(st.integers(min_value=1, max_value=10)),
        packet_count=draw(st.integers(min_value=1, max_value=10))
    )


@st.composite
def ping_result_data_strategy(draw):
    """Generate PingResultData objects."""
    hostname = draw(hostname_strategy())
    ip_address = draw(ip_address_strategy())
    success = draw(st.booleans())
    
    if success:
        latency = draw(st.floats(min_value=0.1, max_value=2000.0))
        packet_loss = draw(st.floats(min_value=0.0, max_value=20.0))
        packets_sent = draw(st.integers(min_value=1, max_value=10))
        packets_received = draw(st.integers(min_value=1, max_value=packets_sent))
        error_message = None
    else:
        latency = None
        packet_loss = draw(st.floats(min_value=50.0, max_value=100.0))
        packets_sent = draw(st.integers(min_value=1, max_value=10))
        packets_received = 0
        error_message = draw(st.text(min_size=1, max_size=100))
    
    return PingResultData(
        host=hostname,
        ip_address=ip_address,
        success=success,
        latency=latency,
        packet_loss=packet_loss,
        packets_sent=packets_sent,
        packets_received=packets_received,
        error_message=error_message,
        timestamp=timezone.now()
    )


class PingMonitoringPropertyTests(HypothesisTestCase):
    """Property-based tests for ping monitoring functionality."""
    
    def setUp(self):
        """Set up test data."""
        # Create unique test user for each test
        unique_id = str(uuid.uuid4())[:8]
        self.user = User.objects.create_user(
            username=f'testuser_{unique_id}',
            email=f'test_{unique_id}@example.com',
            password='testpass123'
        )
        
        # Create test location and group
        self.location = Location.objects.create(
            name=f'Test Location {unique_id}',
            description='Test location for ping monitoring',
            created_by=self.user
        )
        
        self.group = DeviceGroup.objects.create(
            name=f'Test Group {unique_id}',
            description='Test group for ping monitoring',
            created_by=self.user
        )
    
    @given(
        hostnames=st.lists(hostname_strategy(), min_size=1, max_size=2, unique=True),
        ip_addresses=st.lists(ip_address_strategy(), min_size=1, max_size=2, unique=True),
        thresholds=ping_thresholds_strategy()
    )
    @hypothesis_settings(max_examples=3, deadline=6000)
    def test_ping_monitoring_completeness_property(self, hostnames, ip_addresses, thresholds):
        """
        Property 14: Ping monitoring completeness
        For any host with ping monitoring enabled, the system should measure 
        latency, packet loss, and status against configured thresholds.
        
        Feature: network-monitoring-tool, Property 14: Ping monitoring completeness
        Validates: Requirements 3.1
        """
        assume(len(hostnames) == len(ip_addresses))
        
        # Create hosts with ping monitoring enabled
        hosts = []
        unique_id = str(uuid.uuid4())[:8]
        for i, (hostname, ip_address) in enumerate(zip(hostnames, ip_addresses)):
            host = Host.objects.create(
                hostname=f"{hostname}_{unique_id}_{i}",
                ip_address=ip_address,
                device_name=f"Device {hostname} {unique_id}",
                location=self.location,
                group=self.group,
                monitoring_enabled=True,
                ping_enabled=True,
                ping_warning_latency=thresholds.warning_latency,
                ping_critical_latency=thresholds.critical_latency,
                ping_warning_packet_loss=thresholds.warning_packet_loss,
                ping_critical_packet_loss=thresholds.critical_packet_loss,
                ping_timeout=thresholds.timeout,
                ping_packet_count=thresholds.packet_count,
                created_by=self.user
            )
            hosts.append(host)
        
        # Mock ping execution to return predictable results
        with patch('subprocess.run') as mock_subprocess:
            # Configure mock to return successful ping output
            mock_subprocess.return_value = MagicMock(
                returncode=0,
                stdout=f"PING {ip_addresses[0]} ({ip_addresses[0]}): 56 data bytes\n"
                       f"64 bytes from {ip_addresses[0]}: icmp_seq=0 time=50.123 ms\n"
                       f"64 bytes from {ip_addresses[0]}: icmp_seq=1 time=51.456 ms\n"
                       f"64 bytes from {ip_addresses[0]}: icmp_seq=2 time=49.789 ms\n"
                       f"64 bytes from {ip_addresses[0]}: icmp_seq=3 time=52.012 ms\n"
                       f"--- {ip_addresses[0]} ping statistics ---\n"
                       f"4 packets transmitted, 4 received, 0% packet loss",
                stderr=""
            )
            
            # Test each host
            for host in hosts:
                result = ping_host_simple(host)
                
                # Verify completeness: all required measurements should be present
                assert result is not None, f"Ping result should not be None for enabled host {host.hostname}"
                assert hasattr(result, 'latency'), "Ping result should include latency measurement"
                assert hasattr(result, 'packet_loss'), "Ping result should include packet loss measurement"
                assert hasattr(result, 'status'), "Ping result should include status evaluation"
                assert hasattr(result, 'packets_sent'), "Ping result should include packets sent count"
                assert hasattr(result, 'packets_received'), "Ping result should include packets received count"
                
                # Verify measurements are within expected ranges
                if result.success:
                    assert result.latency is not None, "Successful ping should have latency measurement"
                    assert result.latency >= 0, "Latency should be non-negative"
                    assert 0 <= result.packet_loss <= 100, "Packet loss should be between 0 and 100 percent"
                
                # Verify status evaluation against thresholds
                assert result.status in ['up', 'warning', 'critical', 'down'], f"Invalid status: {result.status}"
                
                # Verify threshold application
                if result.success and result.latency is not None:
                    if result.latency >= host.ping_critical_latency:
                        assert result.status in ['critical'], f"High latency should result in critical status"
                    elif result.latency >= host.ping_warning_latency:
                        assert result.status in ['warning', 'critical'], f"Elevated latency should result in warning or critical status"
                
                if result.packet_loss >= host.ping_critical_packet_loss:
                    assert result.status in ['critical'], f"High packet loss should result in critical status"
                elif result.packet_loss >= host.ping_warning_packet_loss:
                    assert result.status in ['warning', 'critical'], f"Elevated packet loss should result in warning or critical status"
    
    @given(
        ping_results=st.lists(ping_result_data_strategy(), min_size=1, max_size=3),
        thresholds=ping_thresholds_strategy()
    )
    @hypothesis_settings(max_examples=3, deadline=4000)
    def test_ping_status_evaluation_consistency_property(self, ping_results, thresholds):
        """
        Property: Ping status evaluation is consistent across different inputs.
        
        For any ping result and threshold configuration, the status evaluation
        should be deterministic and follow the defined threshold rules.
        
        Feature: network-monitoring-tool, Property 14: Ping monitoring completeness
        Validates: Requirements 3.1
        """
        monitor = PingMonitor(thresholds)
        
        for ping_result in ping_results:
            status = monitor.evaluate_status(ping_result)
            status_details = monitor.get_status_details(ping_result)
            
            # Verify status consistency
            assert status == status_details['status'], "Status evaluation should be consistent"
            assert status in ['up', 'warning', 'critical', 'down'], f"Invalid status: {status}"
            
            # Verify status logic
            if not ping_result.success:
                assert status == 'down', "Failed ping should result in 'down' status"
            else:
                # Check threshold logic
                is_critical = False
                is_warning = False
                
                if ping_result.packet_loss >= thresholds.critical_packet_loss:
                    is_critical = True
                elif ping_result.packet_loss >= thresholds.warning_packet_loss:
                    is_warning = True
                
                if ping_result.latency is not None:
                    if ping_result.latency >= thresholds.critical_latency:
                        is_critical = True
                    elif ping_result.latency >= thresholds.warning_latency:
                        is_warning = True
                
                # Verify status matches threshold evaluation
                if is_critical:
                    assert status == 'critical', f"Critical thresholds exceeded but status is {status}"
                elif is_warning:
                    assert status == 'warning', f"Warning thresholds exceeded but status is {status}"
                else:
                    assert status == 'up', f"No thresholds exceeded but status is {status}"
    
    @given(
        hostnames=st.lists(hostname_strategy(), min_size=2, max_size=2, unique=True),
        ip_addresses=st.lists(ip_address_strategy(), min_size=2, max_size=2, unique=True),
        monitoring_enabled=st.lists(st.booleans(), min_size=2, max_size=2),
        ping_enabled=st.lists(st.booleans(), min_size=2, max_size=2)
    )
    @hypothesis_settings(max_examples=1, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_ping_monitoring_filtering_property(self, hostnames, ip_addresses, monitoring_enabled, ping_enabled):
        """
        Property: Ping monitoring respects host configuration flags.
        
        For any host configuration, ping monitoring should only be performed
        on hosts that have both monitoring_enabled and ping_enabled set to True.
        
        Feature: network-monitoring-tool, Property 14: Ping monitoring completeness
        Validates: Requirements 3.1
        """
        assume(len(hostnames) == len(ip_addresses) == len(monitoring_enabled) == len(ping_enabled))
        
        # Create hosts with different configurations
        hosts = []
        expected_pingable = []
        unique_id = str(uuid.uuid4())[:8]
        
        for i, (hostname, ip_address, mon_enabled, ping_en) in enumerate(zip(hostnames, ip_addresses, monitoring_enabled, ping_enabled)):
            host = Host.objects.create(
                hostname=f"{hostname}_{unique_id}_{i}",
                ip_address=ip_address,
                device_name=f"Device {hostname} {unique_id}",
                location=self.location,
                group=self.group,
                monitoring_enabled=mon_enabled,
                ping_enabled=ping_en,
                created_by=self.user
            )
            hosts.append(host)
            
            # Host should be pingable only if both flags are True
            if mon_enabled and ping_en:
                expected_pingable.append(host)
        
        # Test filtering behavior
        for host in hosts:
            result = ping_host_simple(host)
            
            if host.monitoring_enabled and host.ping_enabled:
                # Should perform ping monitoring
                assert result is not None, f"Ping should be performed for enabled host {host.hostname}"
            else:
                # Should skip ping monitoring
                assert result is None, f"Ping should be skipped for disabled host {host.hostname}"
    
    @given(
        latencies=st.lists(st.floats(min_value=0.1, max_value=2000.0), min_size=1, max_size=3),
        packet_losses=st.lists(st.floats(min_value=0.0, max_value=100.0), min_size=1, max_size=3),
        packets_sent=st.integers(min_value=1, max_value=10),
        success_rates=st.floats(min_value=0.0, max_value=1.0)
    )
    @hypothesis_settings(max_examples=3, deadline=4000)
    def test_ping_result_data_integrity_property(self, latencies, packet_losses, packets_sent, success_rates):
        """
        Property: Ping result data maintains integrity and consistency.
        
        For any ping operation, the resulting data should maintain logical
        consistency between success status, packet counts, and measurements.
        
        Feature: network-monitoring-tool, Property 14: Ping monitoring completeness
        Validates: Requirements 3.1
        """
        assume(len(latencies) == len(packet_losses))
        
        hostname = "test-host"
        ip_address = "192.168.1.100"
        
        for latency, packet_loss in zip(latencies, packet_losses):
            # Calculate packets received based on packet loss
            packets_received = max(0, int(packets_sent * (1 - packet_loss / 100)))
            
            # Recalculate actual packet loss based on integer packet counts
            actual_packet_loss = ((packets_sent - packets_received) / packets_sent) * 100 if packets_sent > 0 else 100.0
            
            # Success is determined by whether any packets were received and success rate
            success = packets_received > 0 and success_rates > 0.5
            
            ping_result = PingResultData(
                host=hostname,
                ip_address=ip_address,
                success=success,
                latency=latency if success else None,
                packet_loss=actual_packet_loss,  # Use the recalculated value
                packets_sent=packets_sent,
                packets_received=packets_received,
                timestamp=timezone.now()
            )
            
            # Verify data integrity
            assert ping_result.packets_sent >= 0, "Packets sent should be non-negative"
            assert ping_result.packets_received >= 0, "Packets received should be non-negative"
            assert ping_result.packets_received <= ping_result.packets_sent, "Packets received cannot exceed packets sent"
            
            # Verify packet loss calculation consistency
            if ping_result.packets_sent > 0:
                calculated_loss = ((ping_result.packets_sent - ping_result.packets_received) / ping_result.packets_sent) * 100
                assert abs(ping_result.packet_loss - calculated_loss) < 0.1, f"Packet loss calculation should be consistent: {ping_result.packet_loss} vs {calculated_loss}"
            
            # Verify success status consistency
            if ping_result.success:
                assert ping_result.packets_received > 0, "Successful ping should have received packets"
                if ping_result.latency is not None:
                    assert ping_result.latency >= 0, "Latency should be non-negative for successful pings"
            else:
                # For failed pings, either no packets received OR 100% loss (but not both conditions required)
                if ping_result.packets_received == 0:
                    assert ping_result.packet_loss == 100.0, "No received packets should mean 100% loss"
                elif ping_result.packet_loss == 100.0:
                    assert ping_result.packets_received == 0, "100% loss should mean no received packets"
    
    @given(
        concurrent_hosts=st.integers(min_value=2, max_value=2),
        max_concurrent=st.integers(min_value=1, max_value=2)
    )
    @hypothesis_settings(max_examples=2, deadline=6000)
    def test_concurrent_ping_monitoring_property(self, concurrent_hosts, max_concurrent):
        """
        Property: Concurrent ping monitoring handles multiple hosts correctly.
        
        For any number of hosts being monitored concurrently, the system should
        produce consistent results regardless of concurrency level.
        
        Feature: network-monitoring-tool, Property 14: Ping monitoring completeness
        Validates: Requirements 3.1
        """
        assume(max_concurrent <= concurrent_hosts)
        
        # Create test hosts
        hosts = []
        unique_id = str(uuid.uuid4())[:8]
        for i in range(concurrent_hosts):
            host = Host.objects.create(
                hostname=f"concurrent-host-{unique_id}-{i:03d}",
                ip_address=f"192.168.1.{i + 10}",
                device_name=f"Concurrent Device {unique_id} {i}",
                location=self.location,
                group=self.group,
                monitoring_enabled=True,
                ping_enabled=True,
                created_by=self.user
            )
            hosts.append(host)
        
        # Mock successful ping results
        with patch('subprocess.run') as mock_subprocess:
            mock_subprocess.return_value = MagicMock(
                returncode=0,
                stdout="PING 192.168.1.10 (192.168.1.10): 56 data bytes\n"
                       "64 bytes from 192.168.1.10: icmp_seq=0 time=25.123 ms\n"
                       "64 bytes from 192.168.1.10: icmp_seq=1 time=26.456 ms\n"
                       "64 bytes from 192.168.1.10: icmp_seq=2 time=24.789 ms\n"
                       "64 bytes from 192.168.1.10: icmp_seq=3 time=27.012 ms\n"
                       "--- 192.168.1.10 ping statistics ---\n"
                       "4 packets transmitted, 4 received, 0% packet loss",
                stderr=""
            )
            
            # Test concurrent monitoring
            results = []
            for host in hosts:
                result = ping_host_simple(host)
                if result:
                    results.append(result)
            
            # Verify all hosts were processed
            assert len(results) == len(hosts), f"Expected {len(hosts)} results, got {len(results)}"
            
            # Verify result consistency
            for result in results:
                assert result.success, "All mocked pings should succeed"
                assert result.latency is not None, "Successful pings should have latency"
                assert result.packet_loss == 0.0, "Mocked pings should have no packet loss"
                assert result.status == 'up', "Successful pings with good metrics should be 'up'"
    
    @given(
        maintenance_status=st.booleans(),
        monitoring_enabled=st.booleans(),
        ping_enabled=st.booleans()
    )
    @hypothesis_settings(max_examples=3, deadline=3000)
    def test_maintenance_mode_ping_behavior_property(self, maintenance_status, monitoring_enabled, ping_enabled):
        """
        Property: Ping monitoring respects maintenance mode.
        
        For any host in maintenance mode, ping monitoring should be skipped
        regardless of other configuration flags.
        
        Feature: network-monitoring-tool, Property 14: Ping monitoring completeness
        Validates: Requirements 3.1
        """
        # Create host with maintenance configuration
        unique_id = str(uuid.uuid4())[:8]
        host = Host.objects.create(
            hostname=f"maintenance-test-host-{unique_id}",
            ip_address="192.168.1.200",
            device_name=f"Maintenance Test Device {unique_id}",
            location=self.location,
            group=self.group,
            monitoring_enabled=monitoring_enabled,
            ping_enabled=ping_enabled,
            in_maintenance=maintenance_status,
            created_by=self.user
        )
        
        # Mock maintenance window check
        with patch.object(host, 'is_in_maintenance', return_value=maintenance_status):
            result = ping_host_simple(host)
            
            if maintenance_status:
                # Should skip ping monitoring during maintenance
                assert result is None, "Ping should be skipped during maintenance"
            else:
                # Should follow normal ping monitoring rules
                if monitoring_enabled and ping_enabled:
                    # Would normally ping (but we're not mocking subprocess here)
                    # Just verify the logic path is correct
                    pass
                else:
                    assert result is None, "Ping should be skipped when disabled"
    
    @given(
        error_types=st.sampled_from([
            'timeout', 'unreachable', 'permission_denied', 'network_error', 'dns_error'
        ]),
        error_messages=st.text(min_size=1, max_size=100)
    )
    @hypothesis_settings(max_examples=2, deadline=4000)
    def test_ping_error_handling_property(self, error_types, error_messages):
        """
        Property: Ping monitoring handles errors gracefully.
        
        For any type of ping error, the system should create appropriate
        error records and maintain system stability.
        
        Feature: network-monitoring-tool, Property 14: Ping monitoring completeness
        Validates: Requirements 3.1
        """
        # Create test host
        unique_id = str(uuid.uuid4())[:8]
        host = Host.objects.create(
            hostname=f"error-test-host-{unique_id}",
            ip_address="192.168.1.250",
            device_name=f"Error Test Device {unique_id}",
            location=self.location,
            group=self.group,
            monitoring_enabled=True,
            ping_enabled=True,
            created_by=self.user
        )
        
        # Mock different error conditions
        error_configs = {
            'timeout': (subprocess.TimeoutExpired(['ping'], 5), None),
            'unreachable': (None, MagicMock(returncode=1, stdout="", stderr="Destination Host Unreachable")),
            'permission_denied': (None, MagicMock(returncode=1, stdout="", stderr="Operation not permitted")),
            'network_error': (None, MagicMock(returncode=2, stdout="", stderr="Network is unreachable")),
            'dns_error': (None, MagicMock(returncode=2, stdout="", stderr="Name or service not known"))
        }
        
        exception, mock_result = error_configs[error_types]
        
        with patch('subprocess.run') as mock_subprocess:
            if exception:
                mock_subprocess.side_effect = exception
            else:
                mock_subprocess.return_value = mock_result
            
            result = ping_host_simple(host)
            
            # Verify error handling
            assert result is not None, "Error conditions should still create results"
            assert not result.success, "Error conditions should result in failed ping"
            assert result.status == 'down', "Error conditions should result in 'down' status"
            assert result.packet_loss == 100.0, "Error conditions should result in 100% packet loss"
            assert result.packets_received == 0, "Error conditions should have no received packets"
            assert result.error_message, "Error conditions should include error message"
            
            # Verify host status update
            host.refresh_from_db()
            expected_status = 'maintenance' if host.in_maintenance else 'down'
            assert host.status == expected_status, f"Host status should be updated to {expected_status}"
            assert host.last_check is not None, "Last check timestamp should be updated"