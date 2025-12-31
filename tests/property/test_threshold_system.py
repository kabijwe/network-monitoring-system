"""
Property-based tests for threshold management system.

This module tests Property 20: Threshold configuration flexibility
from the design document.
"""

import pytest
from hypothesis import given, strategies as st, assume, settings
from hypothesis.extra.django import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from decimal import Decimal
import uuid

from monitoring.models import Host, Location, DeviceGroup, Alert
from monitoring.ping_monitor import PingThresholds

User = get_user_model()


class TestThresholdProperties(TestCase):
    """Test threshold configuration flexibility properties."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username=f'testuser-{uuid.uuid4().hex[:8]}',
            email=f'test-{uuid.uuid4().hex[:8]}@example.com',
            password='testpass123'
        )
        
        self.location = Location.objects.create(
            name=f'Test Location {uuid.uuid4().hex[:8]}',
            created_by=self.user
        )
        
        self.group = DeviceGroup.objects.create(
            name=f'Test Group {uuid.uuid4().hex[:8]}',
            created_by=self.user
        )
    
    @given(
        warning_latency=st.floats(min_value=1.0, max_value=1000.0),
        critical_latency=st.floats(min_value=1.0, max_value=2000.0),
        warning_loss=st.floats(min_value=0.1, max_value=50.0),
        critical_loss=st.floats(min_value=0.1, max_value=100.0),
        timeout=st.integers(min_value=1, max_value=30),
        packet_count=st.integers(min_value=1, max_value=10)
    )
    @settings(max_examples=50, deadline=None)
    def test_ping_threshold_configuration_flexibility(
        self, warning_latency, critical_latency, warning_loss, 
        critical_loss, timeout, packet_count
    ):
        """
        Property 20: Threshold configuration flexibility
        
        Test that ping thresholds can be configured with various valid values
        and that the configuration is properly stored and retrieved.
        """
        # Ensure critical thresholds are higher than warning thresholds
        assume(critical_latency >= warning_latency)
        assume(critical_loss >= warning_loss)
        
        # Create host with custom thresholds
        host = Host.objects.create(
            hostname=f'test-host-{uuid.uuid4().hex[:8]}',
            ip_address=f'192.168.1.{hash(str(uuid.uuid4())) % 200 + 10}',
            location=self.location,
            group=self.group,
            ping_warning_latency=warning_latency,
            ping_critical_latency=critical_latency,
            ping_warning_packet_loss=warning_loss,
            ping_critical_packet_loss=critical_loss,
            ping_timeout=timeout,
            ping_packet_count=packet_count,
            created_by=self.user
        )
        
        # Verify thresholds are stored correctly
        assert host.ping_warning_latency == warning_latency
        assert host.ping_critical_latency == critical_latency
        assert host.ping_warning_packet_loss == warning_loss
        assert host.ping_critical_packet_loss == critical_loss
        assert host.ping_timeout == timeout
        assert host.ping_packet_count == packet_count
        
        # Verify threshold object creation
        thresholds = host.get_ping_thresholds()
        assert isinstance(thresholds, PingThresholds)
        assert thresholds.warning_latency == warning_latency
        assert thresholds.critical_latency == critical_latency
        assert thresholds.warning_packet_loss == warning_loss
        assert thresholds.critical_packet_loss == critical_loss
        assert thresholds.timeout == timeout
        assert thresholds.packet_count == packet_count
        
        # Verify database persistence
        host.refresh_from_db()
        assert host.ping_warning_latency == warning_latency
        assert host.ping_critical_latency == critical_latency
    
    @given(
        latency_values=st.lists(
            st.floats(min_value=0.1, max_value=1000.0),
            min_size=3,
            max_size=10
        )
    )
    @settings(max_examples=30, deadline=None)
    def test_threshold_ordering_consistency(self, latency_values):
        """
        Property 20: Threshold configuration flexibility
        
        Test that threshold ordering is maintained (warning < critical).
        """
        # Sort values to ensure proper ordering
        sorted_values = sorted(latency_values)
        warning_latency = sorted_values[0]
        critical_latency = sorted_values[-1]
        
        host = Host.objects.create(
            hostname=f'test-host-{uuid.uuid4().hex[:8]}',
            ip_address=f'192.168.1.{hash(str(uuid.uuid4())) % 200 + 10}',
            location=self.location,
            group=self.group,
            ping_warning_latency=warning_latency,
            ping_critical_latency=critical_latency,
            created_by=self.user
        )
        
        # Verify ordering is maintained
        assert host.ping_warning_latency <= host.ping_critical_latency
        
        # Test with intermediate values
        for value in sorted_values[1:-1]:
            host.ping_warning_latency = value
            host.save()
            
            # Warning should still be <= critical
            assert host.ping_warning_latency <= host.ping_critical_latency
    
    @given(
        base_latency=st.floats(min_value=10.0, max_value=100.0),
        multiplier=st.floats(min_value=1.1, max_value=5.0)
    )
    @settings(max_examples=30, deadline=None)
    def test_threshold_update_consistency(self, base_latency, multiplier):
        """
        Property 20: Threshold configuration flexibility
        
        Test that threshold updates are applied consistently.
        """
        host = Host.objects.create(
            hostname=f'test-host-{uuid.uuid4().hex[:8]}',
            ip_address=f'192.168.1.{hash(str(uuid.uuid4())) % 200 + 10}',
            location=self.location,
            group=self.group,
            ping_warning_latency=base_latency,
            ping_critical_latency=base_latency * multiplier,
            created_by=self.user
        )
        
        original_warning = host.ping_warning_latency
        original_critical = host.ping_critical_latency
        
        # Update thresholds
        new_warning = base_latency * 1.5
        new_critical = base_latency * multiplier * 1.2
        
        host.ping_warning_latency = new_warning
        host.ping_critical_latency = new_critical
        host.save()
        
        # Verify updates are persisted
        host.refresh_from_db()
        assert host.ping_warning_latency == new_warning
        assert host.ping_critical_latency == new_critical
        
        # Verify old values are not retained
        assert host.ping_warning_latency != original_warning
        assert host.ping_critical_latency != original_critical
        
        # Verify threshold object reflects updates
        thresholds = host.get_ping_thresholds()
        assert thresholds.warning_latency == new_warning
        assert thresholds.critical_latency == new_critical
    
    @given(
        timeout_values=st.lists(
            st.integers(min_value=1, max_value=60),
            min_size=3,
            max_size=8
        ),
        packet_counts=st.lists(
            st.integers(min_value=1, max_value=20),
            min_size=3,
            max_size=8
        )
    )
    @settings(max_examples=20, deadline=None)
    def test_monitoring_parameter_flexibility(self, timeout_values, packet_counts):
        """
        Property 20: Threshold configuration flexibility
        
        Test that monitoring parameters (timeout, packet count) can be configured flexibly.
        """
        # Test various timeout and packet count combinations
        for i, (timeout, packet_count) in enumerate(zip(timeout_values, packet_counts)):
            host = Host.objects.create(
                hostname=f'test-host-{i}-{uuid.uuid4().hex[:8]}',
                ip_address=f'192.168.2.{100 + i}',
                location=self.location,
                group=self.group,
                ping_timeout=timeout,
                ping_packet_count=packet_count,
                created_by=self.user
            )
            
            # Verify parameters are stored correctly
            assert host.ping_timeout == timeout
            assert host.ping_packet_count == packet_count
            
            # Verify threshold object includes parameters
            thresholds = host.get_ping_thresholds()
            assert thresholds.timeout == timeout
            assert thresholds.packet_count == packet_count
            
            # Verify parameters are within valid ranges
            assert 1 <= host.ping_timeout <= 60
            assert 1 <= host.ping_packet_count <= 20
    
    def test_default_threshold_values(self):
        """Test that hosts have sensible default threshold values."""
        host = Host.objects.create(
            hostname='test-default-host',
            ip_address='192.168.1.100',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        # Verify default values are set
        assert host.ping_warning_latency == 100.0
        assert host.ping_critical_latency == 500.0
        assert host.ping_warning_packet_loss == 5.0
        assert host.ping_critical_packet_loss == 20.0
        assert host.ping_timeout == 5
        assert host.ping_packet_count == 4
        
        # Verify threshold object has defaults
        thresholds = host.get_ping_thresholds()
        assert thresholds.warning_latency == 100.0
        assert thresholds.critical_latency == 500.0
    
    def test_threshold_validation_constraints(self):
        """Test that threshold values maintain logical constraints."""
        host = Host.objects.create(
            hostname='test-validation-host',
            ip_address='192.168.1.101',
            location=self.location,
            group=self.group,
            ping_warning_latency=50.0,
            ping_critical_latency=200.0,
            ping_warning_packet_loss=2.0,
            ping_critical_packet_loss=10.0,
            created_by=self.user
        )
        
        # Verify constraints are maintained
        assert host.ping_warning_latency < host.ping_critical_latency
        assert host.ping_warning_packet_loss < host.ping_critical_packet_loss
        
        # Test threshold object constraints
        thresholds = host.get_ping_thresholds()
        assert thresholds.warning_latency < thresholds.critical_latency
        assert thresholds.warning_packet_loss < thresholds.critical_packet_loss