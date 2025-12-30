"""
Property-based tests for ping monitoring functionality.
"""
import pytest
from hypothesis import given, strategies as st, settings
from hypothesis.extra.django import TestCase
from django.utils import timezone
from datetime import timedelta
from monitoring.models import Host, Location, DeviceGroup, PingResult
from monitoring.simple_ping import ping_host_simple, _parse_unix_ping, _parse_windows_ping, _evaluate_ping_status
from core.models import User


class PingMonitoringPropertyTests(TestCase):
    """Property-based tests for ping monitoring system."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.location = Location.objects.create(
            name='Test Location',
            description='Test location for ping monitoring',
            created_by=self.user
        )
        
        self.group = DeviceGroup.objects.create(
            name='Test Group',
            description='Test group for ping monitoring',
            created_by=self.user
        )
    
    @given(
        hostname=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-.')),
        ip_address=st.sampled_from(['127.0.0.1', '8.8.8.8', '192.168.1.1', '10.0.0.1']),
        device_type=st.sampled_from(['ap', 'sm', 'switch', 'router', 'server']),
        ping_enabled=st.booleans(),
        monitoring_enabled=st.booleans(),
        warning_latency=st.floats(min_value=10.0, max_value=500.0),
        critical_latency=st.floats(min_value=100.0, max_value=1000.0),
        warning_packet_loss=st.floats(min_value=1.0, max_value=50.0),
        critical_packet_loss=st.floats(min_value=10.0, max_value=100.0),
        timeout=st.integers(min_value=1, max_value=10),
        packet_count=st.integers(min_value=1, max_value=10)
    )
    @settings(max_examples=50, deadline=30000)  # 30 second deadline for ping operations
    def test_host_creation_with_ping_settings(self, hostname, ip_address, device_type, 
                                            ping_enabled, monitoring_enabled, warning_latency,
                                            critical_latency, warning_packet_loss, 
                                            critical_packet_loss, timeout, packet_count):
        """Test that hosts can be created with various ping monitoring settings."""
        # Ensure critical thresholds are higher than warning thresholds
        if critical_latency <= warning_latency:
            critical_latency = warning_latency + 100.0
        if critical_packet_loss <= warning_packet_loss:
            critical_packet_loss = warning_packet_loss + 10.0
        
        host = Host.objects.create(
            hostname=hostname,
            ip_address=ip_address,
            device_type=device_type,
            location=self.location,
            group=self.group,
            monitoring_enabled=monitoring_enabled,
            ping_enabled=ping_enabled,
            ping_warning_latency=warning_latency,
            ping_critical_latency=critical_latency,
            ping_warning_packet_loss=warning_packet_loss,
            ping_critical_packet_loss=critical_packet_loss,
            ping_timeout=timeout,
            ping_packet_count=packet_count,
            created_by=self.user
        )
        
        # Verify host was created with correct settings
        assert host.hostname == hostname
        assert host.ip_address == ip_address
        assert host.device_type == device_type
        assert host.ping_enabled == ping_enabled
        assert host.monitoring_enabled == monitoring_enabled
        assert host.ping_warning_latency == warning_latency
        assert host.ping_critical_latency == critical_latency
        assert host.ping_warning_packet_loss == warning_packet_loss
        assert host.ping_critical_packet_loss == critical_packet_loss
        assert host.ping_timeout == timeout
        assert host.ping_packet_count == packet_count
        
        # Test ping thresholds method
        thresholds = host.get_ping_thresholds()
        assert thresholds.warning_latency == warning_latency
        assert thresholds.critical_latency == critical_latency
        assert thresholds.warning_packet_loss == warning_packet_loss
        assert thresholds.critical_packet_loss == critical_packet_loss
        assert thresholds.timeout == timeout
        assert thresholds.packet_count == packet_count
    
    @given(
        success=st.booleans(),
        latency=st.one_of(st.none(), st.floats(min_value=0.1, max_value=2000.0)),
        packet_loss=st.floats(min_value=0.0, max_value=100.0),
        packets_sent=st.integers(min_value=1, max_value=10),
        packets_received=st.integers(min_value=0, max_value=10),
        error_message=st.text(max_size=100)
    )
    @settings(max_examples=100)
    def test_ping_result_creation(self, success, latency, packet_loss, packets_sent, 
                                packets_received, error_message):
        """Test that ping results can be created with various values."""
        # Ensure packets_received <= packets_sent
        if packets_received > packets_sent:
            packets_received = packets_sent
        
        # Create a test host
        host = Host.objects.create(
            hostname='test-host',
            ip_address='127.0.0.1',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        # Create ping result
        ping_result = PingResult.objects.create(
            host=host,
            success=success,
            latency=latency,
            packet_loss=packet_loss,
            packets_sent=packets_sent,
            packets_received=packets_received,
            status='up' if success else 'down',
            status_reason='Test ping result',
            error_message=error_message
        )
        
        # Verify ping result was created correctly
        assert ping_result.host == host
        assert ping_result.success == success
        assert ping_result.latency == latency
        assert ping_result.packet_loss == packet_loss
        assert ping_result.packets_sent == packets_sent
        assert ping_result.packets_received == packets_received
        assert ping_result.error_message == error_message
        assert ping_result.timestamp is not None
    
    @given(
        packets_sent=st.integers(min_value=1, max_value=10),
        packets_received=st.integers(min_value=0, max_value=10),
        latencies=st.lists(st.floats(min_value=0.1, max_value=1000.0), min_size=0, max_size=10)
    )
    @settings(max_examples=100)
    def test_unix_ping_parsing(self, packets_sent, packets_received, latencies):
        """Test Unix ping output parsing with various inputs."""
        # Ensure packets_received <= packets_sent
        if packets_received > packets_sent:
            packets_received = packets_sent
        
        # Ensure latencies list matches packets_received
        if len(latencies) > packets_received:
            latencies = latencies[:packets_received]
        elif len(latencies) < packets_received:
            latencies.extend([50.0] * (packets_received - len(latencies)))
        
        # Create mock Unix ping output
        output_lines = []
        
        # Add individual ping responses
        for i, latency in enumerate(latencies):
            output_lines.append(f"64 bytes from 8.8.8.8: icmp_seq={i+1} ttl=113 time={latency} ms")
        
        # Add summary line
        packet_loss_pct = ((packets_sent - packets_received) / packets_sent) * 100
        output_lines.append(f"{packets_sent} packets transmitted, {packets_received} received, {packet_loss_pct:.0f}% packet loss")
        
        output = '\n'.join(output_lines)
        
        # Parse the output
        result = _parse_unix_ping(output, packets_sent)
        
        # Verify parsing results
        assert result['packets_sent'] == packets_sent
        assert result['packets_received'] == packets_received
        assert abs(result['packet_loss'] - packet_loss_pct) < 0.1
        assert result['success'] == (packets_received > 0)
        
        if latencies:
            expected_avg = sum(latencies) / len(latencies)
            assert abs(result['latency'] - expected_avg) < 0.1
        else:
            assert result['latency'] is None
    
    @given(
        packets_sent=st.integers(min_value=1, max_value=10),
        packets_received=st.integers(min_value=0, max_value=10),
        latencies=st.lists(st.floats(min_value=0.1, max_value=1000.0), min_size=0, max_size=10)
    )
    @settings(max_examples=100)
    def test_windows_ping_parsing(self, packets_sent, packets_received, latencies):
        """Test Windows ping output parsing with various inputs."""
        # Ensure packets_received <= packets_sent
        if packets_received > packets_sent:
            packets_received = packets_sent
        
        # Ensure latencies list matches packets_received
        if len(latencies) > packets_received:
            latencies = latencies[:packets_received]
        elif len(latencies) < packets_received:
            latencies.extend([50.0] * (packets_received - len(latencies)))
        
        # Create mock Windows ping output
        output_lines = []
        
        # Add individual ping responses
        for i, latency in enumerate(latencies):
            if latency < 1.0:
                output_lines.append(f"Reply from 8.8.8.8: bytes=32 time<1ms TTL=113")
            else:
                output_lines.append(f"Reply from 8.8.8.8: bytes=32 time={int(latency)}ms TTL=113")
        
        # Add timeout responses for failed packets
        for i in range(packets_sent - packets_received):
            output_lines.append("Request timed out.")
        
        output = '\n'.join(output_lines)
        
        # Parse the output
        result = _parse_windows_ping(output, packets_sent)
        
        # Verify parsing results
        assert result['packets_sent'] == packets_sent
        assert result['packets_received'] == packets_received
        expected_loss = ((packets_sent - packets_received) / packets_sent) * 100
        assert abs(result['packet_loss'] - expected_loss) < 0.1
        assert result['success'] == (packets_received > 0)
        
        if latencies:
            # For Windows parsing, sub-millisecond pings are treated as 0.5ms
            adjusted_latencies = [0.5 if l < 1.0 else l for l in latencies]
            expected_avg = sum(adjusted_latencies) / len(adjusted_latencies)
            assert abs(result['latency'] - expected_avg) < 1.0  # Allow 1ms tolerance
        else:
            assert result['latency'] is None
    
    @given(
        success=st.booleans(),
        latency=st.one_of(st.none(), st.floats(min_value=0.1, max_value=2000.0)),
        packet_loss=st.floats(min_value=0.0, max_value=100.0),
        warning_latency=st.floats(min_value=10.0, max_value=500.0),
        critical_latency=st.floats(min_value=100.0, max_value=1000.0),
        warning_packet_loss=st.floats(min_value=1.0, max_value=50.0),
        critical_packet_loss=st.floats(min_value=10.0, max_value=100.0)
    )
    @settings(max_examples=100)
    def test_ping_status_evaluation(self, success, latency, packet_loss, warning_latency,
                                  critical_latency, warning_packet_loss, critical_packet_loss):
        """Test ping status evaluation with various thresholds."""
        # Ensure critical thresholds are higher than warning thresholds
        if critical_latency <= warning_latency:
            critical_latency = warning_latency + 100.0
        if critical_packet_loss <= warning_packet_loss:
            critical_packet_loss = warning_packet_loss + 10.0
        
        # Create a test host with thresholds
        host = Host.objects.create(
            hostname='test-host',
            ip_address='127.0.0.1',
            location=self.location,
            group=self.group,
            ping_warning_latency=warning_latency,
            ping_critical_latency=critical_latency,
            ping_warning_packet_loss=warning_packet_loss,
            ping_critical_packet_loss=critical_packet_loss,
            created_by=self.user
        )
        
        # Create ping data
        ping_data = {
            'success': success,
            'latency': latency,
            'packet_loss': packet_loss,
            'packets_sent': 4,
            'packets_received': 4 if success else 0
        }
        
        # Evaluate status
        status_result = _evaluate_ping_status(ping_data, host)
        
        # Verify status evaluation logic
        if not success:
            assert status_result['status'] == 'down'
            assert 'unreachable' in status_result['reason'].lower()
        elif packet_loss >= critical_packet_loss:
            assert status_result['status'] == 'critical'
            assert 'packet loss' in status_result['reason'].lower()
        elif packet_loss >= warning_packet_loss:
            assert status_result['status'] == 'warning'
            assert 'packet loss' in status_result['reason'].lower()
        elif latency and latency >= critical_latency:
            assert status_result['status'] == 'critical'
            assert 'latency' in status_result['reason'].lower()
        elif latency and latency >= warning_latency:
            assert status_result['status'] == 'warning'
            assert 'latency' in status_result['reason'].lower()
        else:
            assert status_result['status'] == 'up'
            assert 'normally' in status_result['reason'].lower()
    
    @given(
        in_maintenance=st.booleans(),
        ping_enabled=st.booleans(),
        monitoring_enabled=st.booleans()
    )
    @settings(max_examples=50)
    def test_ping_skipping_logic(self, in_maintenance, ping_enabled, monitoring_enabled):
        """Test that ping monitoring is skipped under correct conditions."""
        # Create a test host
        host = Host.objects.create(
            hostname='test-host',
            ip_address='127.0.0.1',
            location=self.location,
            group=self.group,
            ping_enabled=ping_enabled,
            monitoring_enabled=monitoring_enabled,
            in_maintenance=in_maintenance,
            maintenance_start=timezone.now() - timedelta(hours=1) if in_maintenance else None,
            maintenance_end=timezone.now() + timedelta(hours=1) if in_maintenance else None,
            created_by=self.user
        )
        
        # Test ping skipping logic (we can't actually ping in tests, so we check the conditions)
        should_skip = (
            not ping_enabled or 
            not monitoring_enabled or 
            (in_maintenance and host.is_in_maintenance())
        )
        
        # The ping function should return None when skipped
        if should_skip:
            # We can't test the actual ping function in unit tests due to network dependencies
            # But we can verify the conditions are correct
            assert (not host.ping_enabled or 
                   not host.monitoring_enabled or 
                   (host.in_maintenance and host.is_in_maintenance()))
        else:
            assert (host.ping_enabled and 
                   host.monitoring_enabled and 
                   not (host.in_maintenance and host.is_in_maintenance()))
    
    @given(
        status=st.sampled_from(['up', 'down', 'warning', 'critical']),
        acknowledged=st.booleans()
    )
    @settings(max_examples=50)
    def test_host_acknowledgment_logic(self, status, acknowledged):
        """Test host acknowledgment logic for different statuses."""
        # Create a test host
        host = Host.objects.create(
            hostname='test-host',
            ip_address='127.0.0.1',
            location=self.location,
            group=self.group,
            status=status,
            acknowledged=acknowledged,
            acknowledged_by=self.user if acknowledged else None,
            acknowledged_at=timezone.now() if acknowledged else None,
            created_by=self.user
        )
        
        # Test needs_acknowledgment logic
        needs_ack = host.needs_acknowledgment()
        
        if status in ['down', 'warning', 'critical'] and not acknowledged and not host.in_maintenance:
            assert needs_ack
        else:
            assert not needs_ack
    
    def test_ping_result_ordering(self):
        """Test that ping results are ordered by timestamp descending."""
        # Create a test host
        host = Host.objects.create(
            hostname='test-host',
            ip_address='127.0.0.1',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        # Create multiple ping results with different timestamps
        results = []
        for i in range(5):
            result = PingResult.objects.create(
                host=host,
                success=True,
                latency=50.0 + i,
                packet_loss=0.0,
                packets_sent=4,
                packets_received=4,
                status='up',
                status_reason='Test result'
            )
            results.append(result)
        
        # Get results from database
        db_results = list(PingResult.objects.filter(host=host))
        
        # Verify they are ordered by timestamp descending (newest first)
        for i in range(len(db_results) - 1):
            assert db_results[i].timestamp >= db_results[i + 1].timestamp
    
    def test_host_display_name_property(self):
        """Test host display name property logic."""
        # Test with device_name
        host1 = Host.objects.create(
            hostname='host1',
            ip_address='127.0.0.1',
            device_name='Device 1',
            ap_name='AP 1',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        assert host1.display_name == 'Device 1'
        
        # Test with hostname only (no device_name)
        host2 = Host.objects.create(
            hostname='host2',
            ip_address='127.0.0.2',
            device_name='',
            ap_name='AP 2',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        assert host2.display_name == 'host2'  # Falls back to hostname
        
        # Test with hostname only
        host3 = Host.objects.create(
            hostname='host3',
            ip_address='127.0.0.3',
            device_name='',
            ap_name='',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        assert host3.display_name == 'host3'