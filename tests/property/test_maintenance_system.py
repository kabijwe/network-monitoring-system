"""
Property-based tests for maintenance window system.

This module tests Properties 36 and 42: Maintenance window alert suppression
and Maintenance window management from the design document.
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


class TestMaintenanceProperties(TestCase):
    """Test maintenance window system properties."""
    
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
        maintenance_durations=st.lists(
            st.integers(min_value=1, max_value=1440),  # 1 minute to 24 hours
            min_size=1,
            max_size=10
        ),
        maintenance_comments=st.lists(
            st.text(min_size=1, max_size=200, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd', 'Zs'))),
            min_size=1,
            max_size=10
        )
    )
    @settings(max_examples=20, deadline=None)
    def test_maintenance_window_alert_suppression(self, maintenance_durations, maintenance_comments):
        """
        Property 36: Maintenance window alert suppression
        
        Test that alerts are properly suppressed during maintenance windows.
        """
        hosts = []
        
        # Create hosts with maintenance windows
        for i, (duration, comment) in enumerate(zip(maintenance_durations, maintenance_comments)):
            host = Host.objects.create(
                hostname=f'maintenance-host-{i}-{uuid.uuid4().hex[:8]}',
                ip_address=f'192.168.1.{100 + i}',
                location=self.location,
                group=self.group,
                created_by=self.user
            )
            
            # Set maintenance window
            now = timezone.now()
            maintenance_start = now - timedelta(minutes=5)  # Started 5 minutes ago
            maintenance_end = now + timedelta(minutes=duration)
            
            host.in_maintenance = True
            host.maintenance_start = maintenance_start
            host.maintenance_end = maintenance_end
            host.maintenance_comment = comment.strip() or f'Maintenance {i}'
            host.save()
            
            hosts.append(host)
        
        # Test alert suppression for each host
        for i, host in enumerate(hosts):
            # Verify maintenance window is active
            assert host.in_maintenance
            assert host.maintenance_start is not None
            assert host.maintenance_end is not None
            assert host.maintenance_start <= timezone.now() <= host.maintenance_end
            
            # Create alert during maintenance
            alert = Alert.objects.create(
                host=host,
                title=f'Maintenance Alert {i}',
                description=f'Alert during maintenance for host {i}',
                severity='critical',
                check_type='ping'
            )
            
            # Verify alert is created but host status reflects maintenance
            assert alert.host == host
            assert alert.severity == 'critical'
            
            # Verify host needs_acknowledgment respects maintenance
            host.status = 'down'  # Simulate down status
            host.acknowledged = False
            assert not host.needs_acknowledgment()  # Should be False due to maintenance
            
            # Verify maintenance comment is preserved
            expected_comment = maintenance_comments[i].strip() or f'Maintenance {i}'
            assert host.maintenance_comment == expected_comment
    
    @given(
        host_count=st.integers(min_value=2, max_value=8),
        maintenance_status=st.lists(
            st.booleans(),
            min_size=2,
            max_size=8
        )
    )
    @settings(max_examples=15, deadline=None)
    def test_maintenance_window_management(self, host_count, maintenance_status):
        """
        Property 42: Maintenance window management
        
        Test that maintenance windows can be properly managed and scheduled.
        """
        hosts = []
        
        # Create hosts with different maintenance states
        for i in range(min(host_count, len(maintenance_status))):
            host = Host.objects.create(
                hostname=f'mgmt-host-{i}-{uuid.uuid4().hex[:8]}',
                ip_address=f'192.168.2.{100 + i}',
                location=self.location,
                group=self.group,
                created_by=self.user
            )
            
            is_in_maintenance = maintenance_status[i]
            
            if is_in_maintenance:
                # Set up maintenance window
                now = timezone.now()
                host.in_maintenance = True
                host.maintenance_start = now - timedelta(minutes=10)
                host.maintenance_end = now + timedelta(hours=2)
                host.maintenance_comment = f'Scheduled maintenance for host {i}'
            else:
                # No maintenance
                host.in_maintenance = False
                host.maintenance_start = None
                host.maintenance_end = None
                host.maintenance_comment = ''
            
            host.save()
            hosts.append(host)
        
        # Verify maintenance state management
        maintenance_hosts = []
        active_hosts = []
        
        for i, host in enumerate(hosts):
            expected_maintenance = maintenance_status[i]
            
            # Verify maintenance state
            assert host.in_maintenance == expected_maintenance
            
            if expected_maintenance:
                # Verify maintenance window fields
                assert host.maintenance_start is not None
                assert host.maintenance_end is not None
                assert host.maintenance_start < host.maintenance_end
                assert host.maintenance_comment != ''
                
                # Verify maintenance window timing
                now = timezone.now()
                assert host.maintenance_start <= now <= host.maintenance_end
                
                maintenance_hosts.append(host)
            else:
                # Verify no maintenance fields
                assert host.maintenance_start is None
                assert host.maintenance_end is None
                assert host.maintenance_comment == ''
                
                active_hosts.append(host)
        
        # Verify database queries for maintenance management
        db_maintenance_hosts = Host.objects.filter(in_maintenance=True)
        db_active_hosts = Host.objects.filter(in_maintenance=False)
        
        assert db_maintenance_hosts.count() == len(maintenance_hosts)
        assert db_active_hosts.count() == len(active_hosts)
        
        # Verify specific hosts are in correct categories
        for host in maintenance_hosts:
            assert host in db_maintenance_hosts
            assert host not in db_active_hosts
        
        for host in active_hosts:
            assert host in db_active_hosts
            assert host not in db_maintenance_hosts
    
    @given(
        maintenance_duration_hours=st.integers(min_value=1, max_value=48)
    )
    @settings(max_examples=20, deadline=None)
    def test_maintenance_window_timing(self, maintenance_duration_hours):
        """
        Property 42: Maintenance window management
        
        Test that maintenance window timing is properly handled.
        """
        host = Host.objects.create(
            hostname=f'timing-host-{uuid.uuid4().hex[:8]}',
            ip_address='192.168.3.100',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        # Set up maintenance window
        now = timezone.now()
        maintenance_start = now - timedelta(minutes=30)  # Started 30 minutes ago
        maintenance_end = now + timedelta(hours=maintenance_duration_hours)
        
        host.in_maintenance = True
        host.maintenance_start = maintenance_start
        host.maintenance_end = maintenance_end
        host.maintenance_comment = f'Maintenance for {maintenance_duration_hours} hours'
        host.save()
        
        # Verify timing constraints
        assert host.maintenance_start < host.maintenance_end
        assert host.maintenance_start <= now <= host.maintenance_end
        
        # Calculate expected duration
        expected_duration = maintenance_end - maintenance_start
        actual_duration_hours = expected_duration.total_seconds() / 3600
        
        # Should be approximately the requested duration plus 0.5 hours (30 minutes start offset)
        expected_total_hours = maintenance_duration_hours + 0.5
        assert abs(actual_duration_hours - expected_total_hours) < 0.1  # Allow small floating point differences
        
        # Verify maintenance window is currently active
        assert host.in_maintenance
        assert maintenance_start <= timezone.now() <= maintenance_end
    
    def test_maintenance_window_status_interaction(self):
        """
        Property 36: Maintenance window alert suppression
        
        Test that maintenance windows properly interact with host status.
        """
        host = Host.objects.create(
            hostname=f'status-host-{uuid.uuid4().hex[:8]}',
            ip_address='192.168.3.101',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        # Initially not in maintenance
        assert not host.in_maintenance
        assert host.needs_acknowledgment() == False  # Status is 'unknown' by default
        
        # Set host to down status
        host.status = 'down'
        host.acknowledged = False
        host.save()
        
        # Should need acknowledgment when not in maintenance
        assert host.needs_acknowledgment()
        
        # Put host in maintenance
        now = timezone.now()
        host.in_maintenance = True
        host.maintenance_start = now
        host.maintenance_end = now + timedelta(hours=2)
        host.maintenance_comment = 'Testing status interaction'
        host.save()
        
        # Should not need acknowledgment during maintenance
        assert not host.needs_acknowledgment()
        
        # Remove from maintenance
        host.in_maintenance = False
        host.maintenance_start = None
        host.maintenance_end = None
        host.maintenance_comment = ''
        host.save()
        
        # Should need acknowledgment again
        assert host.needs_acknowledgment()
    
    def test_maintenance_window_persistence(self):
        """
        Property 42: Maintenance window management
        
        Test that maintenance window data is properly persisted.
        """
        host = Host.objects.create(
            hostname=f'persist-host-{uuid.uuid4().hex[:8]}',
            ip_address='192.168.3.102',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        # Set maintenance window
        now = timezone.now()
        maintenance_start = now
        maintenance_end = now + timedelta(hours=4)
        maintenance_comment = 'Persistence test maintenance window'
        
        host.in_maintenance = True
        host.maintenance_start = maintenance_start
        host.maintenance_end = maintenance_end
        host.maintenance_comment = maintenance_comment
        host.save()
        
        # Verify data is saved
        host.refresh_from_db()
        assert host.in_maintenance
        assert host.maintenance_start == maintenance_start
        assert host.maintenance_end == maintenance_end
        assert host.maintenance_comment == maintenance_comment
        
        # Update maintenance window
        new_end = now + timedelta(hours=6)
        new_comment = 'Updated maintenance window'
        
        host.maintenance_end = new_end
        host.maintenance_comment = new_comment
        host.save()
        
        # Verify updates are persisted
        host.refresh_from_db()
        assert host.maintenance_start == maintenance_start  # Unchanged
        assert host.maintenance_end == new_end  # Updated
        assert host.maintenance_comment == new_comment  # Updated
        
        # Clear maintenance window
        host.in_maintenance = False
        host.maintenance_start = None
        host.maintenance_end = None
        host.maintenance_comment = ''
        host.save()
        
        # Verify clearing is persisted
        host.refresh_from_db()
        assert not host.in_maintenance
        assert host.maintenance_start is None
        assert host.maintenance_end is None
        assert host.maintenance_comment == ''
    
    def test_multiple_hosts_maintenance_independence(self):
        """
        Property 42: Maintenance window management
        
        Test that maintenance windows for different hosts are independent.
        """
        # Create multiple hosts
        host1 = Host.objects.create(
            hostname='independent-host-1',
            ip_address='192.168.3.110',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        host2 = Host.objects.create(
            hostname='independent-host-2',
            ip_address='192.168.3.111',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        host3 = Host.objects.create(
            hostname='independent-host-3',
            ip_address='192.168.3.112',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        # Set different maintenance states
        now = timezone.now()
        
        # Host 1: In maintenance
        host1.in_maintenance = True
        host1.maintenance_start = now
        host1.maintenance_end = now + timedelta(hours=2)
        host1.maintenance_comment = 'Host 1 maintenance'
        host1.save()
        
        # Host 2: Not in maintenance
        host2.in_maintenance = False
        host2.save()
        
        # Host 3: Different maintenance window
        host3.in_maintenance = True
        host3.maintenance_start = now + timedelta(hours=1)
        host3.maintenance_end = now + timedelta(hours=5)
        host3.maintenance_comment = 'Host 3 maintenance'
        host3.save()
        
        # Verify independence
        assert host1.in_maintenance
        assert not host2.in_maintenance
        assert host3.in_maintenance
        
        assert host1.maintenance_comment == 'Host 1 maintenance'
        assert host2.maintenance_comment == ''
        assert host3.maintenance_comment == 'Host 3 maintenance'
        
        # Verify different timing
        assert host1.maintenance_start != host3.maintenance_start
        assert host1.maintenance_end != host3.maintenance_end
        
        # Modify one host's maintenance
        host1.maintenance_comment = 'Updated Host 1 maintenance'
        host1.save()
        
        # Verify other hosts are unaffected
        host2.refresh_from_db()
        host3.refresh_from_db()
        
        assert host2.maintenance_comment == ''
        assert host3.maintenance_comment == 'Host 3 maintenance'  # Unchanged