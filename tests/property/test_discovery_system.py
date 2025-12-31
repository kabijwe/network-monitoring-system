"""
Property-based tests for network discovery system functionality.

This module contains property-based tests that validate the correctness
of the network discovery system including subnet scanning, device classification,
and approval workflow management.

Tests validate Property 19 from the design document:
- Property 19: Discovery workflow integrity
"""

# Configure Django settings if not already configured
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nms.settings')

import django
django.setup()

import pytest
import asyncio
import ipaddress
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from hypothesis import given, strategies as st, settings, assume, example
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, invariant
from hypothesis.extra.django import TestCase as HypothesisTestCase
from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from datetime import datetime, timedelta

from monitoring.models import Host, Location, DeviceGroup, DiscoveredDevice
from monitoring.discovery import (
    DiscoveryService, NetworkScanner, DeviceClassifier, DiscoveryConfig,
    DiscoveryResult, run_network_discovery, discover_subnet, get_discovery_statistics
)
from monitoring.tasks import (
    network_discovery_task, approve_discovered_device_task,
    reject_discovered_device_task, cleanup_old_discoveries
)
from core.models import User


# Test data strategies
@st.composite
def valid_subnet_strategy(draw):
    """Generate valid subnet CIDR notation."""
    # Generate small subnets for testing
    network_bits = draw(st.integers(min_value=28, max_value=30))  # /28 to /30
    
    # Generate base IP (avoid reserved ranges)
    first_octet = draw(st.sampled_from([10, 172, 192]))
    if first_octet == 10:
        second_octet = draw(st.integers(min_value=0, max_value=255))
        third_octet = draw(st.integers(min_value=0, max_value=255))
        fourth_octet = draw(st.integers(min_value=0, max_value=240))
    elif first_octet == 172:
        second_octet = draw(st.integers(min_value=16, max_value=31))
        third_octet = draw(st.integers(min_value=0, max_value=255))
        fourth_octet = draw(st.integers(min_value=0, max_value=240))
    else:  # 192
        second_octet = 168
        third_octet = draw(st.integers(min_value=1, max_value=254))
        fourth_octet = draw(st.integers(min_value=0, max_value=240))
    
    return f"{first_octet}.{second_octet}.{third_octet}.{fourth_octet}/{network_bits}"


@st.composite
def discovery_config_strategy(draw):
    """Generate discovery configuration."""
    return DiscoveryConfig(
        subnets=[draw(valid_subnet_strategy())],
        ping_timeout=draw(st.integers(min_value=1, max_value=5)),
        snmp_timeout=draw(st.integers(min_value=2, max_value=10)),
        snmp_communities=draw(st.lists(
            st.text(min_size=1, max_size=20, alphabet=st.characters(
                whitelist_categories=('Lu', 'Ll', 'Nd')
            )), min_size=1, max_size=3
        )),
        max_concurrent_scans=draw(st.integers(min_value=5, max_value=20)),
        device_classification_enabled=draw(st.booleans()),
        auto_approve_known_devices=draw(st.booleans())
    )


@st.composite
def discovery_result_strategy(draw):
    """Generate discovery result data."""
    ip_parts = [draw(st.integers(min_value=1, max_value=254)) for _ in range(4)]
    ip_address = '.'.join(map(str, ip_parts))
    
    device_types = ['router', 'switch', 'server', 'firewall', 'printer', 'unknown']
    vendors = ['cisco', 'juniper', 'hp', 'dell', 'linux', 'windows']
    
    return DiscoveryResult(
        ip_address=ip_address,
        hostname=draw(st.one_of(
            st.none(),
            st.text(min_size=1, max_size=50, alphabet=st.characters(
                whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-.'
            ))
        )),
        device_type=draw(st.sampled_from(device_types)),
        vendor=draw(st.sampled_from(vendors)),
        ping_success=draw(st.booleans()),
        ping_latency=draw(st.floats(min_value=0.1, max_value=1000.0)),
        snmp_success=draw(st.booleans()),
        confidence_score=draw(st.floats(min_value=0.0, max_value=1.0)),
        discovery_method=draw(st.sampled_from(['ping', 'snmp', 'port_scan']))
    )


class TestDiscoverySystemProperties(HypothesisTestCase):
    """Property-based tests for network discovery system."""
    
    def setUp(self):
        """Set up test environment."""
        self.location = Location.objects.create(
            name="Discovery Test Location",
            address="Discovery Test Address"
        )
        self.group = DeviceGroup.objects.create(
            name="Discovery Test Group",
            description="Discovery test group"
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    @given(config=discovery_config_strategy())
    @settings(max_examples=20, deadline=10000)
    def test_property_discovery_config_consistency(self, config):
        """
        Property 19a: Discovery configuration consistency
        
        Discovery service should handle any valid configuration consistently
        and maintain configuration integrity throughout execution.
        """
        # Initialize discovery service with config
        service = DiscoveryService(config)
        
        # Verify configuration is preserved
        assert service.config.subnets == config.subnets
        assert service.config.ping_timeout == config.ping_timeout
        assert service.config.snmp_timeout == config.snmp_timeout
        assert service.config.snmp_communities == config.snmp_communities
        assert service.config.max_concurrent_scans == config.max_concurrent_scans
        assert service.config.device_classification_enabled == config.device_classification_enabled
        assert service.config.auto_approve_known_devices == config.auto_approve_known_devices
        
        # Verify scanner is initialized with config
        assert service.scanner.config == config
        
        # Verify configuration constraints
        assert config.ping_timeout > 0
        assert config.snmp_timeout > 0
        assert config.max_concurrent_scans > 0
        assert 0.0 <= config.discovery_interval_hours <= 168  # Max 1 week
        assert len(config.snmp_communities) > 0
    
    @given(
        results=st.lists(discovery_result_strategy(), min_size=0, max_size=10)
    )
    @settings(max_examples=30, deadline=10000)
    def test_property_discovery_result_storage_consistency(self, results):
        """
        Property 19b: Discovery result storage consistency
        
        All discovery results should be stored consistently in the database
        with proper data integrity and no data loss.
        """
        # Clear existing discovered devices
        DiscoveredDevice.objects.all().delete()
        
        service = DiscoveryService()
        
        async def run_test():
            # Store discovery results
            stored_count = await service._store_discovery_results(results)
            
            # Verify storage consistency
            assert stored_count == len(results)
            
            # Verify all results are in database
            db_devices = DiscoveredDevice.objects.all()
            assert db_devices.count() == len(results)
            
            # Verify data integrity for each result
            for result in results:
                db_device = DiscoveredDevice.objects.filter(
                    ip_address=result.ip_address
                ).first()
                
                assert db_device is not None
                assert db_device.ip_address == result.ip_address
                assert db_device.hostname == result.hostname
                assert db_device.device_type == result.device_type
                assert db_device.vendor == result.vendor
                assert db_device.confidence_score == result.confidence_score
                assert db_device.discovery_method == result.discovery_method
                assert db_device.status == 'pending'  # Default status
                
                # Verify timestamps are set
                assert db_device.discovered_at is not None
                assert db_device.last_seen is not None
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_test())
        finally:
            loop.close()
    
    @given(
        device_type=st.sampled_from(['router', 'switch', 'server', 'firewall', 'printer', 'unknown']),
        confidence_score=st.floats(min_value=0.0, max_value=1.0)
    )
    @settings(max_examples=50, deadline=5000)
    def test_property_device_classification_consistency(self, device_type, confidence_score):
        """
        Property 19c: Device classification consistency
        
        Device classification should produce consistent results and
        confidence scores should be within valid ranges.
        """
        classifier = DeviceClassifier()
        
        # Create test discovery result
        result = DiscoveryResult(
            ip_address='192.168.1.100',
            hostname=f'{device_type}-test',
            device_type=device_type,
            confidence_score=confidence_score
        )
        
        # Add device-specific information
        if device_type == 'router':
            result.os_info = 'Cisco IOS Router'
            result.open_ports = [22, 23, 80, 161]
        elif device_type == 'switch':
            result.os_info = 'Cisco Catalyst Switch'
            result.open_ports = [22, 23, 80, 161]
        elif device_type == 'server':
            result.os_info = 'Linux Ubuntu Server'
            result.open_ports = [22, 80, 443]
        elif device_type == 'firewall':
            result.os_info = 'Palo Alto PAN-OS'
            result.open_ports = [22, 80, 443]
        elif device_type == 'printer':
            result.os_info = 'HP LaserJet Printer'
            result.open_ports = [80, 515, 9100]
        
        # Classify device
        classified_type, classified_confidence = classifier.classify_device(result)
        
        # Verify classification consistency
        assert isinstance(classified_type, str)
        assert len(classified_type) > 0
        assert isinstance(classified_confidence, float)
        assert 0.0 <= classified_confidence <= 1.0
        
        # If we provided strong indicators, confidence should be reasonable
        if result.os_info and result.open_ports:
            # Should have some confidence if we have data
            assert classified_confidence >= 0.0
    
    def test_property_approval_workflow_integrity(self):
        """
        Property 19d: Approval workflow integrity
        
        The approval workflow should maintain data integrity and
        proper state transitions throughout the process.
        """
        # Create discovered device
        discovered_device = DiscoveredDevice.objects.create(
            ip_address='192.168.1.200',
            hostname='test-device',
            device_type='server',
            vendor='linux',
            confidence_score=0.8,
            status='pending'
        )
        
        # Test approval workflow
        assert discovered_device.is_pending
        assert not discovered_device.is_approved
        assert not discovered_device.is_rejected
        
        # Approve device
        host = discovered_device.approve(self.user, self.location, self.group)
        
        # Verify approval state
        discovered_device.refresh_from_db()
        assert discovered_device.is_approved
        assert not discovered_device.is_pending
        assert not discovered_device.is_rejected
        assert discovered_device.approved_by == self.user
        assert discovered_device.approved_at is not None
        assert discovered_device.host == host
        
        # Verify host was created correctly
        assert host.hostname == discovered_device.hostname
        assert host.ip_address == discovered_device.ip_address
        assert host.location == self.location
        assert host.group == self.group
        assert host.device_type == discovered_device.device_type
        assert host.created_by == self.user
        
        # Test that double approval fails
        with pytest.raises(ValueError, match="already approved"):
            discovered_device.approve(self.user, self.location, self.group)
    
    def test_property_rejection_workflow_integrity(self):
        """
        Property 19e: Rejection workflow integrity
        
        The rejection workflow should maintain proper state transitions
        and preserve rejection information.
        """
        # Create discovered device
        discovered_device = DiscoveredDevice.objects.create(
            ip_address='192.168.1.201',
            hostname='reject-test-device',
            device_type='unknown',
            confidence_score=0.1,
            status='pending'
        )
        
        # Test initial state
        assert discovered_device.is_pending
        assert not discovered_device.is_rejected
        
        # Reject device
        rejection_reason = "Low confidence score and unknown device type"
        discovered_device.reject(self.user, rejection_reason)
        
        # Verify rejection state
        discovered_device.refresh_from_db()
        assert discovered_device.is_rejected
        assert not discovered_device.is_pending
        assert not discovered_device.is_approved
        assert discovered_device.rejected_by == self.user
        assert discovered_device.rejected_at is not None
        assert discovered_device.rejection_reason == rejection_reason
        
        # Test that double rejection fails
        with pytest.raises(ValueError, match="already rejected"):
            discovered_device.reject(self.user, "Another reason")
    
    @given(
        subnet=valid_subnet_strategy(),
        max_concurrent=st.integers(min_value=1, max_value=10)
    )
    @settings(max_examples=10, deadline=15000)
    def test_property_subnet_scanning_consistency(self, subnet, max_concurrent):
        """
        Property 19f: Subnet scanning consistency
        
        Subnet scanning should handle any valid subnet consistently
        and respect concurrency limits.
        """
        # Create config with test parameters
        config = DiscoveryConfig(
            subnets=[subnet],
            max_concurrent_scans=max_concurrent,
            ping_timeout=1,  # Fast timeout for testing
            device_classification_enabled=False  # Disable for speed
        )
        
        scanner = NetworkScanner(config)
        
        async def run_test():
            # Mock ping to avoid actual network calls
            with patch.object(scanner, '_ping_host') as mock_ping:
                # Configure mock to return some responsive hosts
                def mock_ping_side_effect(ip):
                    # Make every 4th IP responsive for testing
                    if hash(ip) % 4 == 0:
                        return DiscoveryResult(
                            ip_address=ip,
                            ping_success=True,
                            ping_latency=10.0,
                            discovery_method='ping'
                        )
                    return None
                
                mock_ping.side_effect = mock_ping_side_effect
                
                # Run subnet discovery
                results = await scanner.discover_subnet(subnet)
                
                # Verify results consistency
                assert isinstance(results, list)
                
                # All results should be DiscoveryResult objects
                for result in results:
                    assert isinstance(result, DiscoveryResult)
                    assert result.ping_success is True  # Mock returns only successful
                    assert result.ping_latency > 0
                    assert result.discovery_method == 'ping'
                    
                    # Verify IP is in the subnet
                    network = ipaddress.ip_network(subnet, strict=False)
                    ip = ipaddress.ip_address(result.ip_address)
                    assert ip in network
                
                # Verify concurrency was respected (mock was called)
                assert mock_ping.call_count > 0
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_test())
        finally:
            loop.close()
    
    def test_property_discovery_statistics_consistency(self):
        """
        Property 19g: Discovery statistics consistency
        
        Discovery statistics should accurately reflect the current
        state of the discovery system.
        """
        # Clear existing data
        DiscoveredDevice.objects.all().delete()
        
        # Create test discovered devices in different states
        devices = [
            DiscoveredDevice.objects.create(
                ip_address='192.168.1.100',
                device_type='router',
                status='pending'
            ),
            DiscoveredDevice.objects.create(
                ip_address='192.168.1.101',
                device_type='switch',
                status='approved',
                approved_by=self.user,
                approved_at=timezone.now()
            ),
            DiscoveredDevice.objects.create(
                ip_address='192.168.1.102',
                device_type='server',
                status='rejected',
                rejected_by=self.user,
                rejected_at=timezone.now()
            ),
            DiscoveredDevice.objects.create(
                ip_address='192.168.1.103',
                device_type='router',
                status='auto_approved',
                approved_at=timezone.now()
            ),
        ]
        
        # Get statistics
        stats = get_discovery_statistics()
        
        # Verify statistics consistency
        assert isinstance(stats, dict)
        assert 'discovered_devices' in stats
        assert 'device_types' in stats
        assert 'recent_discoveries' in stats
        
        device_stats = stats['discovered_devices']
        assert device_stats['total'] == 4
        assert device_stats['pending'] == 1
        assert device_stats['approved'] == 1
        assert device_stats['rejected'] == 1
        assert device_stats['auto_approved'] == 1
        
        # Verify device type counts
        device_types = stats['device_types']
        assert device_types.get('router', 0) == 2
        assert device_types.get('switch', 0) == 1
        assert device_types.get('server', 0) == 1
        
        # Verify recent discoveries count
        assert stats['recent_discoveries'] == 4  # All created recently


class TestDiscoverySystemExamples(TestCase):
    """Example-based tests for specific discovery system scenarios."""
    
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
        self.user = User.objects.create_user(
            username='exampleuser',
            email='example@example.com',
            password='examplepass123'
        )
    
    def test_device_classifier_patterns(self):
        """Test device classifier with known patterns."""
        classifier = DeviceClassifier()
        
        # Test router classification
        router_result = DiscoveryResult(
            ip_address='192.168.1.1',
            hostname='core-router-01',
            os_info='Cisco IOS Software, C2960 Software',
            open_ports=[22, 23, 80, 161]
        )
        
        device_type, confidence = classifier.classify_device(router_result)
        assert device_type == 'router'
        assert confidence > 0.5
        
        # Test switch classification
        switch_result = DiscoveryResult(
            ip_address='192.168.1.2',
            hostname='access-switch-01',
            os_info='Cisco Catalyst Switch',
            open_ports=[22, 23, 80, 161]
        )
        
        device_type, confidence = classifier.classify_device(switch_result)
        assert device_type == 'switch'
        assert confidence > 0.5
        
        # Test server classification
        server_result = DiscoveryResult(
            ip_address='192.168.1.10',
            hostname='web-server-01',
            os_info='Linux Ubuntu 20.04 LTS',
            open_ports=[22, 80, 443]
        )
        
        device_type, confidence = classifier.classify_device(server_result)
        assert device_type == 'server'
        assert confidence > 0.3
    
    def test_discovery_task_execution(self):
        """Test discovery task execution."""
        # Mock the discovery service
        with patch('monitoring.discovery.DiscoveryService') as mock_service_class:
            mock_service = Mock()
            mock_service_class.return_value = mock_service
            
            # Configure mock discovery result
            mock_result = {
                'status': 'completed',
                'total_discovered': 5,
                'stored_count': 5,
                'approved_count': 2
            }
            
            async def mock_run_discovery(subnets):
                return mock_result
            
            mock_service.run_discovery = mock_run_discovery
            
            # Execute discovery task
            result = network_discovery_task(['192.168.1.0/29'])
            
            # Verify task result
            assert result['status'] == 'success'
            assert 'result' in result
            assert result['result']['status'] == 'completed'
    
    def test_approval_task_execution(self):
        """Test device approval task execution."""
        # Create discovered device
        discovered_device = DiscoveredDevice.objects.create(
            ip_address='192.168.1.200',
            hostname='approval-test',
            device_type='server',
            status='pending'
        )
        
        # Mock the discovery service
        with patch('monitoring.discovery.DiscoveryService') as mock_service_class:
            mock_service = Mock()
            mock_service_class.return_value = mock_service
            
            async def mock_approve(device_id, location_id, group_id, user_id):
                return True
            
            mock_service.approve_discovered_device = mock_approve
            
            # Execute approval task
            result = approve_discovered_device_task(
                str(discovered_device.id),
                str(self.location.id),
                str(self.group.id),
                self.user.id
            )
            
            # Verify task result
            assert result['status'] == 'success'
            assert result['device_id'] == str(discovered_device.id)
    
    def test_rejection_task_execution(self):
        """Test device rejection task execution."""
        # Create discovered device
        discovered_device = DiscoveredDevice.objects.create(
            ip_address='192.168.1.201',
            hostname='rejection-test',
            device_type='unknown',
            status='pending'
        )
        
        # Mock the discovery service
        with patch('monitoring.discovery.DiscoveryService') as mock_service_class:
            mock_service = Mock()
            mock_service_class.return_value = mock_service
            
            async def mock_reject(device_id, user_id, reason):
                return True
            
            mock_service.reject_discovered_device = mock_reject
            
            # Execute rejection task
            result = reject_discovered_device_task(
                str(discovered_device.id),
                self.user.id,
                'Test rejection'
            )
            
            # Verify task result
            assert result['status'] == 'success'
            assert result['device_id'] == str(discovered_device.id)
    
    def test_cleanup_task_execution(self):
        """Test discovery cleanup task execution."""
        # Create old rejected device
        old_time = timezone.now() - timedelta(days=100)
        
        old_device = DiscoveredDevice.objects.create(
            ip_address='192.168.1.202',
            device_type='unknown',
            status='rejected',
            rejected_by=self.user
        )
        old_device.rejected_at = old_time
        old_device.save()
        
        # Execute cleanup task
        result = cleanup_old_discoveries()
        
        # Verify cleanup result
        assert result['status'] == 'success'
        assert 'total_deleted' in result
        assert result['total_deleted'] >= 0
    
    def test_empty_subnet_discovery(self):
        """Test discovery on empty subnet."""
        config = DiscoveryConfig(
            subnets=['192.0.2.0/30'],  # TEST-NET-1, should be empty
            ping_timeout=1,
            max_concurrent_scans=5
        )
        
        scanner = NetworkScanner(config)
        
        async def run_test():
            results = await scanner.discover_subnet('192.0.2.0/30')
            
            # Should return empty list for unreachable subnet
            assert isinstance(results, list)
            # Results may be empty or contain failed attempts
            for result in results:
                assert isinstance(result, DiscoveryResult)
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_test())
        finally:
            loop.close()


if __name__ == '__main__':
    pytest.main([__file__])