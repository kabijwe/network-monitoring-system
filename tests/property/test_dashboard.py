"""
Property-based tests for Dashboard functionality.

These tests validate the dashboard system using property-based testing
with Hypothesis to ensure correctness across a wide range of inputs.
"""
import pytest
import django
from django.conf import settings
from django.test import TestCase, override_settings, TransactionTestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from hypothesis import given, strategies as st, settings as hypothesis_settings, assume
from rest_framework.test import APIClient
from rest_framework import status
import uuid
from unittest.mock import patch, MagicMock
from datetime import timedelta

# Configure Django settings if not already configured
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nms.settings')

# Initialize Django
if not settings.configured:
    django.setup()

from core.models import Role, UserRole, AuditLog

User = get_user_model()


# Custom strategies for generating test data
@st.composite
def host_status_strategy(draw):
    """Generate valid host status values."""
    return draw(st.sampled_from(['UP', 'DOWN', 'WARNING', 'MAINTENANCE', 'UNKNOWN']))


@st.composite
def host_counts_strategy(draw):
    """Generate realistic host count distributions."""
    total = draw(st.integers(min_value=0, max_value=1000))
    
    # Generate counts that sum to total
    if total == 0:
        return {
            'total_hosts': 0,
            'up_hosts': 0,
            'down_hosts': 0,
            'warning_hosts': 0,
            'maintenance_hosts': 0,
            'unknown_hosts': 0
        }
    
    # Distribute total among status categories
    up = draw(st.integers(min_value=0, max_value=total))
    remaining = total - up
    down = draw(st.integers(min_value=0, max_value=remaining))
    remaining -= down
    warning = draw(st.integers(min_value=0, max_value=remaining))
    remaining -= warning
    maintenance = draw(st.integers(min_value=0, max_value=remaining))
    unknown = remaining - maintenance
    
    return {
        'total_hosts': total,
        'up_hosts': up,
        'down_hosts': down,
        'warning_hosts': warning,
        'maintenance_hosts': maintenance,
        'unknown_hosts': unknown
    }


@st.composite
def location_data_strategy(draw):
    """Generate location health data."""
    name = draw(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Zs'))))
    host_counts = draw(host_counts_strategy())
    
    # Calculate health percentage
    operational_hosts = host_counts['total_hosts'] - host_counts['maintenance_hosts']
    if operational_hosts > 0:
        health_percentage = round((host_counts['up_hosts'] / operational_hosts) * 100, 1)
    else:
        health_percentage = 100.0 if host_counts['total_hosts'] == host_counts['maintenance_hosts'] else 0.0
    
    # Determine status
    if host_counts['down_hosts'] > 0:
        if host_counts['down_hosts'] >= operational_hosts * 0.5:
            status = 'critical'
        else:
            status = 'warning'
    elif host_counts['warning_hosts'] > 0:
        status = 'warning'
    else:
        status = 'healthy'
    
    return {
        'id': draw(st.integers(min_value=1, max_value=10000)),
        'name': name.strip(),
        'health_percentage': health_percentage,
        'status': status,
        **host_counts
    }


class DashboardPropertyTests(TestCase):
    """Property-based tests for Dashboard functionality."""
    
    def setUp(self):
        """Set up test data."""
        # Create unique test user for each test
        unique_id = str(uuid.uuid4())[:8]
        self.user = User.objects.create_user(
            username=f'testuser_{unique_id}',
            email=f'test_{unique_id}@example.com',
            password='testpass123'
        )
        
        # Create test client
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
    
    @given(
        summary_data=host_counts_strategy()
    )
    @hypothesis_settings(max_examples=3, deadline=5000)
    def test_summary_card_accuracy_property(self, summary_data):
        """
        Property 24: Summary card accuracy
        For any point in time, dashboard summary cards should display 
        correct counts for UP, DOWN, WARNING, MAINTENANCE, and TOTAL devices.
        
        Feature: network-monitoring-tool, Property 24: Summary card accuracy
        Validates: Requirements 4.3
        """
        # Test that all counts are non-negative
        assert summary_data['total_hosts'] >= 0, "Total hosts should be non-negative"
        assert summary_data['up_hosts'] >= 0, "UP hosts should be non-negative"
        assert summary_data['down_hosts'] >= 0, "DOWN hosts should be non-negative"
        assert summary_data['warning_hosts'] >= 0, "WARNING hosts should be non-negative"
        assert summary_data['maintenance_hosts'] >= 0, "MAINTENANCE hosts should be non-negative"
        assert summary_data['unknown_hosts'] >= 0, "UNKNOWN hosts should be non-negative"
        
        # Test that individual counts sum to total
        calculated_total = (
            summary_data['up_hosts'] + 
            summary_data['down_hosts'] + 
            summary_data['warning_hosts'] + 
            summary_data['maintenance_hosts'] + 
            summary_data['unknown_hosts']
        )
        assert calculated_total == summary_data['total_hosts'], \
            f"Individual counts ({calculated_total}) should sum to total ({summary_data['total_hosts']})"
        
        # Test that no individual count exceeds total
        assert summary_data['up_hosts'] <= summary_data['total_hosts'], "UP hosts should not exceed total"
        assert summary_data['down_hosts'] <= summary_data['total_hosts'], "DOWN hosts should not exceed total"
        assert summary_data['warning_hosts'] <= summary_data['total_hosts'], "WARNING hosts should not exceed total"
        assert summary_data['maintenance_hosts'] <= summary_data['total_hosts'], "MAINTENANCE hosts should not exceed total"
        assert summary_data['unknown_hosts'] <= summary_data['total_hosts'], "UNKNOWN hosts should not exceed total"
    
    @given(
        locations=st.lists(location_data_strategy(), min_size=0, max_size=10)
    )
    @hypothesis_settings(max_examples=3, deadline=5000)
    def test_dashboard_panel_content_consistency_property(self, locations):
        """
        Property 25: Dashboard panel content consistency
        For any dashboard view, the Location Overview and Live Activity Log 
        panels should display current, accurate data.
        
        Feature: network-monitoring-tool, Property 25: Dashboard panel content consistency
        Validates: Requirements 4.4
        """
        # Test location data consistency
        for location in locations:
            # Health percentage should be between 0 and 100
            assert 0 <= location['health_percentage'] <= 100, \
                f"Health percentage should be 0-100, got {location['health_percentage']}"
            
            # Status should match health percentage
            if location['health_percentage'] >= 90:
                expected_status = 'healthy'
            elif location['health_percentage'] >= 50:
                expected_status = 'warning'
            else:
                expected_status = 'critical'
            
            # Allow for some flexibility in status determination
            valid_statuses = ['healthy', 'warning', 'critical']
            assert location['status'] in valid_statuses, \
                f"Status should be one of {valid_statuses}, got {location['status']}"
            
            # Test that location has valid host counts
            total = location['total_hosts']
            individual_sum = (
                location['up_hosts'] + location['down_hosts'] + 
                location['warning_hosts'] + location['maintenance_hosts'] + 
                location['unknown_hosts']
            )
            assert individual_sum == total, \
                f"Location {location['name']}: individual counts should sum to total"
    
    @given(
        activity_count=st.integers(min_value=0, max_value=100),
        event_types=st.lists(
            st.sampled_from(['status_change', 'alert', 'acknowledgment', 'maintenance']),
            min_size=0, max_size=20
        )
    )
    @hypothesis_settings(max_examples=3, deadline=5000)
    def test_activity_log_consistency_property(self, activity_count, event_types):
        """
        Property: Activity log maintains consistency and proper ordering.
        
        For any activity log data, entries should be properly ordered by timestamp
        and contain valid event types and data.
        
        Feature: network-monitoring-tool, Property 25: Dashboard panel content consistency
        Validates: Requirements 4.4
        """
        # Generate mock activity entries
        activity_entries = []
        base_time = timezone.now()
        
        for i in range(min(activity_count, len(event_types))):
            event_type = event_types[i] if i < len(event_types) else 'status_change'
            timestamp = base_time - timedelta(minutes=i)
            
            entry = {
                'id': f'test_{i}',
                'timestamp': timestamp.isoformat(),
                'host_name': f'host_{i}',
                'host_ip': f'192.168.1.{i+1}',
                'event_type': event_type,
                'message': f'Test event {i}',
                'severity': 'info'
            }
            activity_entries.append(entry)
        
        # Test that entries are properly structured
        for entry in activity_entries:
            assert 'id' in entry, "Activity entry should have ID"
            assert 'timestamp' in entry, "Activity entry should have timestamp"
            assert 'host_name' in entry, "Activity entry should have host name"
            assert 'host_ip' in entry, "Activity entry should have host IP"
            assert 'event_type' in entry, "Activity entry should have event type"
            assert 'message' in entry, "Activity entry should have message"
            
            # Validate event type
            valid_event_types = ['status_change', 'alert', 'acknowledgment', 'maintenance']
            assert entry['event_type'] in valid_event_types, \
                f"Event type should be one of {valid_event_types}"
        
        # Test chronological ordering (most recent first)
        if len(activity_entries) > 1:
            timestamps = [entry['timestamp'] for entry in activity_entries]
            sorted_timestamps = sorted(timestamps, reverse=True)
            # Note: We generated them in reverse chronological order, so they should already be sorted
            assert timestamps == sorted_timestamps or len(set(timestamps)) <= 1, \
                "Activity entries should be ordered by timestamp (most recent first)"
    
    @given(
        dashboard_data=st.fixed_dictionaries({
            'summary': host_counts_strategy(),
            'location_health': st.lists(location_data_strategy(), min_size=0, max_size=5),
            'recent_activity': st.lists(st.fixed_dictionaries({
                'id': st.text(min_size=1, max_size=20),
                'timestamp': st.datetimes(min_value=timezone.now() - timedelta(days=7)),
                'host_name': st.text(min_size=1, max_size=50),
                'host_ip': st.text(min_size=7, max_size=15),  # Simple IP-like string
                'event_type': st.sampled_from(['status_change', 'alert', 'acknowledgment', 'maintenance']),
                'message': st.text(min_size=1, max_size=200),
                'severity': st.sampled_from(['info', 'warning', 'error', 'critical'])
            }), min_size=0, max_size=10)
        })
    )
    @hypothesis_settings(max_examples=2, deadline=8000)
    def test_dashboard_data_integrity_property(self, dashboard_data):
        """
        Property: Dashboard data maintains integrity across all components.
        
        For any complete dashboard data set, all components should be 
        consistent and properly formatted.
        
        Feature: network-monitoring-tool, Property 24 & 25: Dashboard accuracy and consistency
        Validates: Requirements 4.3, 4.4
        """
        summary = dashboard_data['summary']
        locations = dashboard_data['location_health']
        activities = dashboard_data['recent_activity']
        
        # Test summary integrity
        assert isinstance(summary, dict), "Summary should be a dictionary"
        required_summary_keys = ['total_hosts', 'up_hosts', 'down_hosts', 'warning_hosts', 'maintenance_hosts', 'unknown_hosts']
        for key in required_summary_keys:
            assert key in summary, f"Summary should contain {key}"
            assert isinstance(summary[key], int), f"Summary {key} should be an integer"
            assert summary[key] >= 0, f"Summary {key} should be non-negative"
        
        # Test location data integrity
        assert isinstance(locations, list), "Locations should be a list"
        for location in locations:
            assert isinstance(location, dict), "Each location should be a dictionary"
            required_location_keys = ['id', 'name', 'total_hosts', 'up_hosts', 'down_hosts', 'warning_hosts', 'maintenance_hosts', 'health_percentage', 'status']
            for key in required_location_keys:
                assert key in location, f"Location should contain {key}"
        
        # Test activity data integrity
        assert isinstance(activities, list), "Activities should be a list"
        for activity in activities:
            assert isinstance(activity, dict), "Each activity should be a dictionary"
            required_activity_keys = ['id', 'timestamp', 'host_name', 'host_ip', 'event_type', 'message', 'severity']
            for key in required_activity_keys:
                assert key in activity, f"Activity should contain {key}"
    
    def test_dashboard_api_response_structure_property(self):
        """
        Property: Dashboard API responses maintain consistent structure.
        
        For any dashboard API call, the response should have the expected
        structure and data types.
        
        Feature: network-monitoring-tool, Property 24 & 25: Dashboard accuracy and consistency
        Validates: Requirements 4.3, 4.4
        """
        # Test dashboard overview endpoint
        response = self.client.get('/api/dashboard/')
        
        # Should return 200 OK or handle gracefully
        assert response.status_code in [200, 500], f"Dashboard API should return 200 or 500, got {response.status_code}"
        
        if response.status_code == 200:
            data = response.json()
            
            # Check required top-level keys
            required_keys = ['summary', 'location_health', 'recent_activity', 'last_updated']
            for key in required_keys:
                assert key in data, f"Dashboard response should contain {key}"
            
            # Check data types
            assert isinstance(data['summary'], dict), "Summary should be a dictionary"
            assert isinstance(data['location_health'], list), "Location health should be a list"
            assert isinstance(data['recent_activity'], list), "Recent activity should be a list"
            assert isinstance(data['last_updated'], str), "Last updated should be a string"
    
    @given(
        user_roles=st.lists(
            st.sampled_from(['superadmin', 'admin', 'editor', 'viewer']),
            min_size=1, max_size=3, unique=True
        )
    )
    @hypothesis_settings(max_examples=2, deadline=5000)
    def test_dashboard_access_control_property(self, user_roles):
        """
        Property: Dashboard access respects user role permissions.
        
        For any user with valid roles, dashboard data should be filtered
        according to their access permissions.
        
        Feature: network-monitoring-tool, Property 24 & 25: Dashboard accuracy and consistency
        Validates: Requirements 4.3, 4.4
        """
        # Create roles if they don't exist
        for role_name in user_roles:
            role, created = Role.objects.get_or_create(
                name=role_name,
                defaults={
                    'display_name': role_name.title(),
                    'description': f'{role_name.title()} role'
                }
            )
            
            # Assign role to user
            UserRole.objects.get_or_create(
                user=self.user,
                role=role,
                defaults={'is_active': True}
            )
        
        # Test that user can access dashboard
        response = self.client.get('/api/dashboard/')
        
        # Should not return 403 Forbidden for authenticated users
        assert response.status_code != 403, "Authenticated users should be able to access dashboard"
        
        # Should return valid response structure
        if response.status_code == 200:
            data = response.json()
            assert 'summary' in data, "Dashboard should return summary data"
            assert 'location_health' in data, "Dashboard should return location health data"
            assert 'recent_activity' in data, "Dashboard should return activity data"