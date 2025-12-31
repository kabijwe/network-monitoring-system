"""
Property-based tests for acknowledgment system.

This module tests Properties 39, 43, and 44: Mandatory acknowledgment comments,
Acknowledgment history tracking, and Bulk acknowledgment operations
from the design document.
"""

import pytest
from hypothesis import given, strategies as st, assume, settings
from hypothesis.extra.django import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
import uuid

from monitoring.models import Host, Location, DeviceGroup, Alert

User = get_user_model()


class TestAcknowledgmentProperties(TestCase):
    """Test acknowledgment system properties."""
    
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
        comment_texts=st.lists(
            st.text(min_size=1, max_size=500, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd', 'Zs'))),
            min_size=1,
            max_size=10
        )
    )
    @settings(max_examples=30, deadline=None)
    def test_mandatory_acknowledgment_comments(self, comment_texts):
        """
        Property 39: Mandatory acknowledgment comments
        
        Test that acknowledgment comments are properly stored and tracked.
        """
        alerts = []
        
        # Create alerts to acknowledge
        for i, comment_text in enumerate(comment_texts):
            alert = Alert.objects.create(
                host=self.host,
                title=f'Test Alert {i}',
                description=f'Alert for acknowledgment test {i}',
                severity='warning',
                check_type='ping'
            )
            alerts.append(alert)
        
        # Acknowledge alerts with comments
        for i, (alert, comment) in enumerate(zip(alerts, comment_texts)):
            # Verify alert is initially not acknowledged
            assert not alert.acknowledged_by
            assert not alert.acknowledged_at
            assert alert.acknowledgment_comment == ''
            assert alert.status == 'active'
            
            # Acknowledge with comment
            clean_comment = comment.strip() or f'Default comment {i}'
            alert.acknowledge(self.user, clean_comment)
            
            # Verify acknowledgment is recorded
            assert alert.status == 'acknowledged'
            assert alert.acknowledged_by == self.user
            assert alert.acknowledged_at is not None
            assert alert.acknowledgment_comment == clean_comment
            
            # Verify acknowledgment timestamp is recent
            now = timezone.now()
            assert (now - alert.acknowledged_at).total_seconds() < 60
        
        # Verify all acknowledgments are persisted
        for i, alert in enumerate(alerts):
            alert.refresh_from_db()
            expected_comment = comment_texts[i].strip() or f'Default comment {i}'
            
            assert alert.status == 'acknowledged'
            assert alert.acknowledged_by == self.user
            assert alert.acknowledgment_comment == expected_comment
    
    @given(
        alert_count=st.integers(min_value=2, max_value=15),
        acknowledgment_sequence=st.lists(
            st.booleans(),
            min_size=2,
            max_size=15
        )
    )
    @settings(max_examples=20, deadline=None)
    def test_acknowledgment_history_tracking(self, alert_count, acknowledgment_sequence):
        """
        Property 43: Acknowledgment history tracking
        
        Test that acknowledgment history is properly maintained and queryable.
        """
        alerts = []
        
        # Create alerts
        for i in range(min(alert_count, len(acknowledgment_sequence))):
            alert = Alert.objects.create(
                host=self.host,
                title=f'History Alert {i}',
                description=f'Alert for history tracking {i}',
                severity='critical',
                check_type='snmp'
            )
            alerts.append(alert)
        
        acknowledged_alerts = []
        unacknowledged_alerts = []
        
        # Process acknowledgment sequence
        for i, (alert, should_acknowledge) in enumerate(zip(alerts, acknowledgment_sequence)):
            if should_acknowledge:
                original_first_seen = alert.first_seen
                
                # Acknowledge the alert
                comment = f'Acknowledged by test sequence {i}'
                alert.acknowledge(self.user, comment)
                
                # Verify acknowledgment tracking
                assert alert.status == 'acknowledged'
                assert alert.acknowledged_by == self.user
                assert alert.acknowledged_at is not None
                assert alert.acknowledgment_comment == comment
                
                # Verify original timestamps preserved
                assert alert.first_seen == original_first_seen
                
                acknowledged_alerts.append(alert)
            else:
                # Leave unacknowledged
                assert alert.status == 'active'
                assert not alert.acknowledged_by
                assert not alert.acknowledged_at
                
                unacknowledged_alerts.append(alert)
        
        # Verify acknowledgment history queries
        db_acknowledged = Alert.objects.filter(
            host=self.host,
            status='acknowledged'
        )
        
        db_unacknowledged = Alert.objects.filter(
            host=self.host,
            status='active'
        )
        
        # Verify counts match
        assert db_acknowledged.count() == len(acknowledged_alerts)
        assert db_unacknowledged.count() == len(unacknowledged_alerts)
        
        # Verify specific alerts are in correct categories
        for alert in acknowledged_alerts:
            assert alert in db_acknowledged
            assert alert not in db_unacknowledged
        
        for alert in unacknowledged_alerts:
            assert alert in db_unacknowledged
            assert alert not in db_acknowledged
        
        # Verify acknowledgment metadata is queryable
        acknowledged_by_user = Alert.objects.filter(
            host=self.host,
            acknowledged_by=self.user
        )
        assert acknowledged_by_user.count() == len(acknowledged_alerts)
        
        # Verify acknowledgment timestamps are ordered
        if len(acknowledged_alerts) > 1:
            timestamps = [alert.acknowledged_at for alert in acknowledged_alerts]
            sorted_timestamps = sorted(timestamps)
            # Timestamps should be in chronological order (within test execution time)
            for i in range(1, len(timestamps)):
                time_diff = (timestamps[i] - timestamps[i-1]).total_seconds()
                assert time_diff >= 0  # Later acknowledgments should have later timestamps
    
    @given(
        batch_sizes=st.lists(
            st.integers(min_value=1, max_value=10),
            min_size=1,
            max_size=5
        )
    )
    @settings(max_examples=15, deadline=None)
    def test_bulk_acknowledgment_operations(self, batch_sizes):
        """
        Property 44: Bulk acknowledgment operations
        
        Test that multiple alerts can be acknowledged in bulk operations.
        """
        all_alerts = []
        batch_info = []
        
        # Create batches of alerts
        for batch_idx, batch_size in enumerate(batch_sizes):
            batch_alerts = []
            
            for i in range(batch_size):
                alert = Alert.objects.create(
                    host=self.host,
                    title=f'Bulk Alert B{batch_idx}-{i}',
                    description=f'Alert in batch {batch_idx}, item {i}',
                    severity='warning',
                    check_type='ping'
                )
                batch_alerts.append(alert)
                all_alerts.append(alert)
            
            batch_info.append({
                'alerts': batch_alerts,
                'size': batch_size,
                'batch_idx': batch_idx
            })
        
        # Perform bulk acknowledgment operations
        total_acknowledged = 0
        
        for batch in batch_info:
            batch_alerts = batch['alerts']
            batch_idx = batch['batch_idx']
            
            # Verify all alerts are initially unacknowledged
            for alert in batch_alerts:
                assert alert.status == 'active'
                assert not alert.acknowledged_by
            
            # Bulk acknowledge all alerts in this batch
            bulk_comment = f'Bulk acknowledgment for batch {batch_idx}'
            
            for alert in batch_alerts:
                alert.acknowledge(self.user, bulk_comment)
                total_acknowledged += 1
            
            # Verify batch acknowledgment
            for alert in batch_alerts:
                assert alert.status == 'acknowledged'
                assert alert.acknowledged_by == self.user
                assert alert.acknowledgment_comment == bulk_comment
                assert alert.acknowledged_at is not None
        
        # Verify total acknowledgment count
        assert total_acknowledged == len(all_alerts)
        
        # Verify database consistency
        db_acknowledged_count = Alert.objects.filter(
            host=self.host,
            status='acknowledged'
        ).count()
        
        assert db_acknowledged_count == total_acknowledged
        
        # Verify all alerts are acknowledged
        for alert in all_alerts:
            alert.refresh_from_db()
            assert alert.status == 'acknowledged'
            assert alert.acknowledged_by == self.user
            assert alert.acknowledged_at is not None
            assert alert.acknowledgment_comment != ''
    
    @given(
        comment_length=st.integers(min_value=1, max_value=1000)
    )
    @settings(max_examples=20, deadline=None)
    def test_acknowledgment_comment_persistence(self, comment_length):
        """
        Property 39: Mandatory acknowledgment comments
        
        Test that acknowledgment comments of various lengths are properly stored.
        """
        # Generate comment of specified length
        comment = 'A' * comment_length
        
        alert = Alert.objects.create(
            host=self.host,
            title='Comment Persistence Test',
            description='Testing comment storage',
            severity='info',
            check_type='custom'
        )
        
        # Acknowledge with long comment
        alert.acknowledge(self.user, comment)
        
        # Verify comment is stored correctly
        assert alert.acknowledgment_comment == comment
        assert len(alert.acknowledgment_comment) == comment_length
        
        # Verify persistence across database operations
        alert.refresh_from_db()
        assert alert.acknowledgment_comment == comment
        assert len(alert.acknowledgment_comment) == comment_length
    
    def test_acknowledgment_user_tracking(self):
        """
        Property 43: Acknowledgment history tracking
        
        Test that acknowledgment user information is properly tracked.
        """
        # Create additional users
        user2 = User.objects.create_user(
            username=f'testuser2-{uuid.uuid4().hex[:8]}',
            email=f'test2-{uuid.uuid4().hex[:8]}@example.com',
            password='testpass123'
        )
        
        user3 = User.objects.create_user(
            username=f'testuser3-{uuid.uuid4().hex[:8]}',
            email=f'test3-{uuid.uuid4().hex[:8]}@example.com',
            password='testpass123'
        )
        
        # Create alerts for different users to acknowledge
        alert1 = Alert.objects.create(
            host=self.host,
            title='User Tracking Alert 1',
            description='Alert for user 1',
            severity='warning',
            check_type='ping'
        )
        
        alert2 = Alert.objects.create(
            host=self.host,
            title='User Tracking Alert 2',
            description='Alert for user 2',
            severity='critical',
            check_type='snmp'
        )
        
        alert3 = Alert.objects.create(
            host=self.host,
            title='User Tracking Alert 3',
            description='Alert for user 3',
            severity='info',
            check_type='service'
        )
        
        # Acknowledge with different users
        alert1.acknowledge(self.user, 'Acknowledged by user 1')
        alert2.acknowledge(user2, 'Acknowledged by user 2')
        alert3.acknowledge(user3, 'Acknowledged by user 3')
        
        # Verify user tracking
        assert alert1.acknowledged_by == self.user
        assert alert2.acknowledged_by == user2
        assert alert3.acknowledged_by == user3
        
        # Verify user-specific queries
        user1_acknowledgments = Alert.objects.filter(acknowledged_by=self.user)
        user2_acknowledgments = Alert.objects.filter(acknowledged_by=user2)
        user3_acknowledgments = Alert.objects.filter(acknowledged_by=user3)
        
        assert alert1 in user1_acknowledgments
        assert alert2 in user2_acknowledgments
        assert alert3 in user3_acknowledgments
        
        assert alert1 not in user2_acknowledgments
        assert alert1 not in user3_acknowledgments
        assert alert2 not in user1_acknowledgments
        assert alert2 not in user3_acknowledgments
        assert alert3 not in user1_acknowledgments
        assert alert3 not in user2_acknowledgments
    
    def test_acknowledgment_status_transitions(self):
        """
        Property 43: Acknowledgment history tracking
        
        Test that acknowledgment status transitions are properly handled.
        """
        alert = Alert.objects.create(
            host=self.host,
            title='Status Transition Test',
            description='Testing status transitions',
            severity='critical',
            check_type='ping'
        )
        
        # Initial state
        assert alert.status == 'active'
        assert not alert.acknowledged_by
        assert not alert.acknowledged_at
        
        # Acknowledge
        alert.acknowledge(self.user, 'Initial acknowledgment')
        
        # Verify acknowledged state
        assert alert.status == 'acknowledged'
        assert alert.acknowledged_by == self.user
        assert alert.acknowledged_at is not None
        acknowledged_time = alert.acknowledged_at
        
        # Resolve the alert
        alert.resolve()
        
        # Verify resolved state preserves acknowledgment info
        assert alert.status == 'resolved'
        assert alert.acknowledged_by == self.user
        assert alert.acknowledged_at == acknowledged_time  # Should be preserved
        assert alert.resolved_at is not None
        
        # Verify acknowledgment history is maintained
        alert.refresh_from_db()
        assert alert.acknowledged_by == self.user
        assert alert.acknowledged_at == acknowledged_time
        assert alert.acknowledgment_comment == 'Initial acknowledgment'