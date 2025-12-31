"""
Property-based tests for alerting system.

This module tests Properties 32 and 38: Real-time alert generation and Alert history tracking
from the design document.
"""

import pytest
from hypothesis import given, strategies as st, assume, settings
from hypothesis.extra.django import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
import uuid

from monitoring.models import (
    Host, Location, DeviceGroup, Alert, NotificationProfile, 
    NotificationLog, EscalationRule
)

User = get_user_model()


class TestAlertingProperties(TestCase):
    """Test real-time alert generation and history tracking properties."""
    
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
        
        self.host = Host.objects.create(
            hostname=f'test-host-{uuid.uuid4().hex[:8]}',
            ip_address='192.168.1.100',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
    
    @given(
        alert_count=st.integers(min_value=1, max_value=10),
        severity=st.sampled_from(['info', 'warning', 'critical']),
        check_type=st.sampled_from(['ping', 'snmp', 'service', 'custom'])
    )
    @settings(max_examples=30, deadline=None)
    def test_real_time_alert_generation(self, alert_count, severity, check_type):
        """
        Property 32: Real-time alert generation
        
        Test that alerts are generated immediately when conditions are met
        and that each alert has proper metadata and timestamps.
        """
        alerts_created = []
        
        # Create alerts with various configurations
        for i in range(alert_count):
            title = f'Test Alert {i} - {uuid.uuid4().hex[:8]}'
            alert = Alert.objects.create(
                host=self.host,
                title=title,
                description=f'Test alert description for {title}',
                severity=severity,
                check_type=check_type,
                metric_name='test_metric',
                threshold_value=100.0,
                current_value=150.0
            )
            alerts_created.append(alert)
        
        # Verify all alerts were created immediately
        assert len(alerts_created) == alert_count
        
        # Verify each alert has proper properties
        for i, alert in enumerate(alerts_created):
            # Verify basic properties
            assert alert.host == self.host
            assert alert.severity in ['info', 'warning', 'critical']
            assert alert.status == 'active'  # Default status
            assert alert.check_type in ['ping', 'snmp', 'service', 'custom']
            
            # Verify timestamps are set
            assert alert.first_seen is not None
            assert alert.last_seen is not None
            assert alert.first_seen <= alert.last_seen
            
            # Verify timestamps are recent (within last minute)
            now = timezone.now()
            assert (now - alert.first_seen).total_seconds() < 60
            assert (now - alert.last_seen).total_seconds() < 60
            
            # Verify alert is not acknowledged by default
            assert not alert.acknowledged_by
            assert not alert.acknowledged_at
            assert alert.acknowledgment_comment == ''
            
            # Verify alert is not resolved by default
            assert not alert.resolved_at
    
    @given(
        num_alerts=st.integers(min_value=1, max_value=20),
        severity_distribution=st.lists(
            st.sampled_from(['info', 'warning', 'critical']),
            min_size=1,
            max_size=20
        )
    )
    @settings(max_examples=20, deadline=None)
    def test_alert_history_tracking(self, num_alerts, severity_distribution):
        """
        Property 38: Alert history tracking
        
        Test that alert history is properly maintained including status changes,
        acknowledgments, and resolution tracking.
        """
        alerts = []
        
        # Create multiple alerts
        for i in range(min(num_alerts, len(severity_distribution))):
            severity = severity_distribution[i]
            alert = Alert.objects.create(
                host=self.host,
                title=f'History Test Alert {i}',
                description=f'Alert for history tracking test {i}',
                severity=severity,
                check_type='ping',
                metric_name='latency',
                threshold_value=100.0,
                current_value=200.0 + i * 10
            )
            alerts.append(alert)
        
        # Track initial state
        initial_count = len(alerts)
        assert Alert.objects.filter(host=self.host).count() >= initial_count
        
        # Test acknowledgment history
        for i, alert in enumerate(alerts[:len(alerts)//2]):  # Acknowledge half
            original_first_seen = alert.first_seen
            original_last_seen = alert.last_seen
            
            # Acknowledge the alert
            alert.acknowledge(self.user, f'Acknowledged alert {i}')
            
            # Verify acknowledgment is tracked
            assert alert.status == 'acknowledged'
            assert alert.acknowledged_by == self.user
            assert alert.acknowledged_at is not None
            assert alert.acknowledgment_comment == f'Acknowledged alert {i}'
            
            # Verify original timestamps are preserved
            assert alert.first_seen == original_first_seen
            
            # Verify acknowledgment timestamp is recent
            now = timezone.now()
            assert (now - alert.acknowledged_at).total_seconds() < 60
        
        # Test resolution history
        for i, alert in enumerate(alerts[len(alerts)//2:]):  # Resolve the other half
            original_first_seen = alert.first_seen
            original_acknowledged_at = alert.acknowledged_at
            
            # Resolve the alert
            alert.resolve()
            
            # Verify resolution is tracked
            assert alert.status == 'resolved'
            assert alert.resolved_at is not None
            
            # Verify original timestamps are preserved
            assert alert.first_seen == original_first_seen
            assert alert.acknowledged_at == original_acknowledged_at
            
            # Verify resolution timestamp is recent
            now = timezone.now()
            assert (now - alert.resolved_at).total_seconds() < 60
        
        # Verify alert history is queryable
        active_alerts = Alert.objects.filter(host=self.host, status='active')
        acknowledged_alerts = Alert.objects.filter(host=self.host, status='acknowledged')
        resolved_alerts = Alert.objects.filter(host=self.host, status='resolved')
        
        # Verify counts match our operations
        assert acknowledged_alerts.count() == len(alerts) // 2
        assert resolved_alerts.count() == len(alerts) - len(alerts) // 2
        
        # Verify all alerts are still in database (history preserved)
        total_alerts = Alert.objects.filter(host=self.host).count()
        assert total_alerts >= initial_count
    
    @given(
        alert_count=st.integers(min_value=2, max_value=10),
        time_intervals=st.lists(
            st.integers(min_value=1, max_value=300),  # seconds
            min_size=2,
            max_size=10
        )
    )
    @settings(max_examples=15, deadline=None)
    def test_alert_temporal_ordering(self, alert_count, time_intervals):
        """
        Property 32: Real-time alert generation
        
        Test that alerts maintain proper temporal ordering and timestamps.
        """
        alerts = []
        base_time = timezone.now()
        
        # Create alerts with simulated time progression
        for i in range(min(alert_count, len(time_intervals))):
            # Simulate time progression
            simulated_time = base_time + timedelta(seconds=sum(time_intervals[:i+1]))
            
            alert = Alert.objects.create(
                host=self.host,
                title=f'Temporal Alert {i}',
                description=f'Alert created at sequence {i}',
                severity='warning',
                check_type='ping'
            )
            
            # Manually set timestamps to simulate time progression
            Alert.objects.filter(id=alert.id).update(
                first_seen=simulated_time,
                last_seen=simulated_time
            )
            alert.refresh_from_db()
            alerts.append(alert)
        
        # Verify temporal ordering
        for i in range(1, len(alerts)):
            prev_alert = alerts[i-1]
            curr_alert = alerts[i]
            
            # Current alert should be created after previous
            assert curr_alert.first_seen >= prev_alert.first_seen
            
            # Verify ordering in database queries
            newer_alerts = Alert.objects.filter(
                host=self.host,
                first_seen__gt=prev_alert.first_seen
            )
            assert curr_alert in newer_alerts
    
    @given(
        alert_count=st.integers(min_value=3, max_value=15),
        severity=st.sampled_from(['info', 'warning', 'critical'])
    )
    @settings(max_examples=20, deadline=None)
    def test_alert_severity_and_metrics_tracking(self, alert_count, severity):
        """
        Property 32: Real-time alert generation
        
        Test that alert severity and metric information is properly tracked.
        """
        alerts = []
        
        # Create alerts with various severities and metrics
        for i in range(alert_count):
            metric_value = 100.0 + i * 10.0  # Increasing metric values
            threshold = metric_value * 0.8  # Set threshold below current value
            
            alert = Alert.objects.create(
                host=self.host,
                title=f'Metric Alert {i}',
                description=f'Alert with severity {severity}',
                severity=severity,
                check_type='snmp',
                metric_name='cpu_usage',
                threshold_value=threshold,
                current_value=metric_value
            )
            alerts.append(alert)
        
        # Verify all alerts have the same severity
        for alert in alerts:
            assert alert.severity == severity
        
        # Verify metric information is preserved
        for i, alert in enumerate(alerts):
            expected_metric_value = 100.0 + i * 10.0
            expected_threshold = expected_metric_value * 0.8
            
            assert alert.current_value == expected_metric_value
            assert alert.threshold_value == expected_threshold
            assert alert.metric_name == 'cpu_usage'
            
            # Verify threshold violation (current > threshold)
            assert alert.current_value > alert.threshold_value
        
        # Verify alert count
        assert len(alerts) == alert_count
    
    @given(
        status_transitions=st.lists(
            st.sampled_from(['acknowledge', 'resolve']),
            min_size=1,
            max_size=5
        )
    )
    @settings(max_examples=20, deadline=None)
    def test_alert_status_transition_history(self, status_transitions):
        """
        Property 38: Alert history tracking
        
        Test that alert status transitions are properly tracked and maintained.
        """
        alert = Alert.objects.create(
            host=self.host,
            title='Status Transition Test Alert',
            description='Testing status transitions',
            severity='critical',
            check_type='ping'
        )
        
        # Track initial state
        assert alert.status == 'active'
        initial_first_seen = alert.first_seen
        
        # Apply status transitions
        for i, transition in enumerate(status_transitions):
            if transition == 'acknowledge' and alert.status == 'active':
                alert.acknowledge(self.user, f'Acknowledgment {i}')
                
                # Verify acknowledgment state
                assert alert.status == 'acknowledged'
                assert alert.acknowledged_by == self.user
                assert alert.acknowledged_at is not None
                assert f'Acknowledgment {i}' in alert.acknowledgment_comment
                
            elif transition == 'resolve' and alert.status in ['active', 'acknowledged']:
                alert.resolve()
                
                # Verify resolution state
                assert alert.status == 'resolved'
                assert alert.resolved_at is not None
        
        # Verify history preservation
        alert.refresh_from_db()
        
        # Original timestamp should be preserved
        assert alert.first_seen == initial_first_seen
        
        # Verify final state is consistent
        if 'resolve' in status_transitions:
            assert alert.status == 'resolved'
            assert alert.resolved_at is not None
        elif 'acknowledge' in status_transitions:
            assert alert.status in ['acknowledged', 'resolved']
            assert alert.acknowledged_at is not None
    
    def test_alert_uniqueness_and_deduplication(self):
        """
        Property 32: Real-time alert generation
        
        Test that duplicate alerts can be tracked and managed properly.
        """
        # Create initial alert
        alert1 = Alert.objects.create(
            host=self.host,
            title='Duplicate Test Alert',
            description='First instance',
            severity='warning',
            check_type='ping',
            metric_name='latency'
        )
        
        # Create similar alert (potential duplicate)
        alert2 = Alert.objects.create(
            host=self.host,
            title='Duplicate Test Alert',
            description='Second instance',
            severity='warning',
            check_type='ping',
            metric_name='latency'
        )
        
        # Verify both alerts exist (no automatic deduplication)
        alerts = Alert.objects.filter(
            host=self.host,
            title='Duplicate Test Alert'
        )
        assert alerts.count() == 2
        
        # Verify they have different timestamps
        assert alert1.first_seen != alert2.first_seen
        assert alert1.id != alert2.id
        
        # Verify they can be distinguished by description
        descriptions = [alert.description for alert in alerts]
        assert 'First instance' in descriptions
        assert 'Second instance' in descriptions
    
    def test_alert_host_relationship_integrity(self):
        """
        Property 32: Real-time alert generation
        
        Test that alert-host relationships are maintained properly.
        """
        # Create additional host
        host2 = Host.objects.create(
            hostname='test-host-2',
            ip_address='192.168.1.101',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        # Create alerts for different hosts
        alert1 = Alert.objects.create(
            host=self.host,
            title='Host 1 Alert',
            description='Alert for first host',
            severity='info',
            check_type='ping'
        )
        
        alert2 = Alert.objects.create(
            host=host2,
            title='Host 2 Alert',
            description='Alert for second host',
            severity='critical',
            check_type='snmp'
        )
        
        # Verify host relationships
        assert alert1.host == self.host
        assert alert2.host == host2
        assert alert1.host != alert2.host
        
        # Verify alerts are properly associated with hosts
        host1_alerts = Alert.objects.filter(host=self.host)
        host2_alerts = Alert.objects.filter(host=host2)
        
        assert alert1 in host1_alerts
        assert alert2 in host2_alerts
        assert alert1 not in host2_alerts
        assert alert2 not in host1_alerts
        
        # Verify alert counts per host
        assert host1_alerts.count() >= 1
        assert host2_alerts.count() >= 1