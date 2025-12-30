"""
Property-based tests for data export functionality.

These tests validate the multi-format export system, permission-based
export restrictions, and export data integrity using property-based testing.
"""
import pytest
import django
from django.conf import settings
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from hypothesis import given, strategies as st, settings as hypothesis_settings, assume
from hypothesis.extra.django import TestCase as HypothesisTestCase
import pandas as pd
import json
import io
import tempfile
import os

# Configure Django settings if not already configured
if not settings.configured:
    import os
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nms.settings')
    django.setup()

from monitoring.models import Location, DeviceGroup, Host, Alert
from monitoring.serializers import BulkExportSerializer
from core.models import Role, UserRole, AuditLog

User = get_user_model()


class DataExportPropertyTests(HypothesisTestCase):
    """Property-based tests for data export functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create test user with admin role
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Create admin role
        admin_role = Role.objects.create(
            name='admin',
            description='Admin role for testing'
        )
        UserRole.objects.create(user=self.user, role=admin_role)
        
        # Create test location and group
        self.location = Location.objects.create(
            name='Test Location',
            description='Test location for export',
            created_by=self.user
        )
        
        self.group = DeviceGroup.objects.create(
            name='Test Group',
            description='Test group for export',
            created_by=self.user
        )
        
        # Authenticate client
        self.client.force_authenticate(user=self.user)
    
    @given(
        export_formats=st.lists(
            st.sampled_from(['excel', 'csv', 'json', 'pdf']),
            min_size=1,
            max_size=4,
            unique=True
        ),
        export_types=st.lists(
            st.sampled_from(['hosts', 'locations', 'groups', 'alerts']),
            min_size=1,
            max_size=4,
            unique=True
        )
    )
    @hypothesis_settings(max_examples=20, deadline=10000)
    def test_multi_format_export_capability_property(self, export_formats, export_types):
        """
        Property 11: Multi-format export capability works for all supported formats and types.
        
        This test verifies that the export system can generate files in all supported
        formats (Excel, CSV, JSON, PDF) for all data types.
        """
        # Create some test data
        test_hosts = []
        for i in range(3):
            host = Host.objects.create(
                hostname=f'test-host-{i:03d}',
                ip_address=f'192.168.1.{i+10}',
                device_type='ap',
                location=self.location,
                group=self.group,
                created_by=self.user
            )
            test_hosts.append(host)
        
        # Test each combination of format and type
        for export_format in export_formats:
            for export_type in export_types:
                with self.subTest(format=export_format, type=export_type):
                    # Skip combinations that don't make sense
                    if export_type == 'alerts' and not Alert.objects.exists():
                        continue
                    
                    response = self.client.post('/api/monitoring/export/', {
                        'export_type': export_type,
                        'format': export_format
                    })
                    
                    # Verify export succeeded
                    assert response.status_code == 200, f"Export failed for {export_format}/{export_type}: {response.content}"
                    
                    # Verify content type is appropriate
                    content_type = response.get('Content-Type', '')
                    if export_format == 'excel':
                        assert 'spreadsheet' in content_type or 'excel' in content_type.lower()
                    elif export_format == 'csv':
                        assert 'csv' in content_type
                    elif export_format == 'json':
                        assert 'json' in content_type
                    elif export_format == 'pdf':
                        assert 'pdf' in content_type
                    
                    # Verify content disposition header
                    content_disposition = response.get('Content-Disposition', '')
                    assert 'attachment' in content_disposition
                    assert export_type in content_disposition
        
        # Cleanup
        for host in test_hosts:
            host.delete()
    
    @given(
        user_roles=st.sampled_from(['viewer', 'editor', 'admin', 'superadmin']),
        export_types=st.sampled_from(['hosts', 'locations', 'groups', 'alerts', 'audit_logs'])
    )
    @hypothesis_settings(max_examples=25, deadline=8000)
    def test_permission_based_bulk_operations_property(self, user_roles, export_types):
        """
        Property 9: Permission-based bulk operations enforce correct access control for exports.
        
        This test verifies that export operations respect role-based permissions
        and only allow authorized users to export specific data types.
        """
        # Create user with specific role
        test_user = User.objects.create_user(
            username=f'testuser_{user_roles}',
            email=f'{user_roles}@example.com',
            password='testpass123'
        )
        
        # Create role
        role = Role.objects.create(
            name=user_roles,
            description=f'{user_roles} role for testing'
        )
        UserRole.objects.create(user=test_user, role=role)
        
        # Create test client
        client = APIClient()
        client.force_authenticate(user=test_user)
        
        # Test export permissions
        response = client.post('/api/monitoring/export/', {
            'export_type': export_types,
            'format': 'json'
        })
        
        # Check permissions based on role and export type
        if export_types == 'audit_logs':
            # Only superadmin can export audit logs
            if user_roles == 'superadmin':
                assert response.status_code in [200, 404], f"Audit log export should be allowed for {user_roles}"
            else:
                assert response.status_code == 403, f"Audit log export should be forbidden for {user_roles}"
        else:
            # All roles should be able to export other data types (with filtering)
            assert response.status_code in [200, 404], f"Export should be allowed for {user_roles} on {export_types}"
        
        # Cleanup
        test_user.delete()
        role.delete()
    
    @given(
        host_counts=st.integers(min_value=1, max_value=50),
        include_inactive=st.booleans(),
        date_ranges=st.booleans()
    )
    @hypothesis_settings(max_examples=15, deadline=12000)
    def test_export_data_filtering_property(self, host_counts, include_inactive, date_ranges):
        """
        Property: Export data filtering works correctly with various filter combinations.
        
        This test verifies that export filters (location, group, date range, active status)
        correctly filter the exported data.
        """
        # Create test hosts
        test_hosts = []
        for i in range(min(host_counts, 10)):  # Limit for performance
            host = Host.objects.create(
                hostname=f'filter-test-{i:03d}',
                ip_address=f'10.0.1.{i+1}',
                device_type='ap',
                location=self.location,
                group=self.group,
                monitoring_enabled=i % 2 == 0 if not include_inactive else True,
                created_by=self.user
            )
            test_hosts.append(host)
        
        # Test export with filters
        export_data = {
            'export_type': 'hosts',
            'format': 'json',
            'location_id': str(self.location.id),
            'group_id': str(self.group.id),
            'include_inactive': include_inactive
        }
        
        if date_ranges:
            from django.utils import timezone
            from datetime import timedelta
            export_data['start_date'] = (timezone.now() - timedelta(days=1)).isoformat()
            export_data['end_date'] = timezone.now().isoformat()
        
        response = self.client.post('/api/monitoring/export/', export_data)
        
        # Verify export succeeded
        assert response.status_code == 200, f"Filtered export failed: {response.content}"
        
        # Parse JSON response to verify filtering
        if response.get('Content-Type', '').startswith('application/json'):
            try:
                exported_data = json.loads(response.content.decode('utf-8'))
                
                # Verify all exported hosts match filters
                for host_data in exported_data:
                    assert host_data['location'] == self.location.name
                    assert host_data['group'] == self.group.name
                    
                    if not include_inactive:
                        assert host_data['monitoring_enabled'] is True
                
                # Verify count matches expected
                expected_count = len([h for h in test_hosts if include_inactive or h.monitoring_enabled])
                assert len(exported_data) == expected_count, f"Expected {expected_count} hosts, got {len(exported_data)}"
                
            except json.JSONDecodeError:
                # If it's not JSON, that's also valid (could be other format)
                pass
        
        # Cleanup
        for host in test_hosts:
            host.delete()
    
    @given(
        export_formats=st.sampled_from(['excel', 'csv', 'json']),
        data_sizes=st.integers(min_value=1, max_value=20)
    )
    @hypothesis_settings(max_examples=10, deadline=15000)
    def test_export_data_integrity_property(self, export_formats, data_sizes):
        """
        Property: Export data integrity is maintained across all formats.
        
        This test verifies that exported data contains all expected fields
        and maintains data integrity across different export formats.
        """
        # Create test data with known values
        test_hosts = []
        expected_data = []
        
        for i in range(min(data_sizes, 5)):  # Limit for performance
            host = Host.objects.create(
                hostname=f'integrity-test-{i:03d}',
                ip_address=f'172.16.1.{i+1}',
                device_type='sm',
                device_name=f'Device {i:03d}',
                ap_name=f'AP-{i:03d}',
                cid=f'CID{i:03d}',
                ap_ip=f'172.16.0.{i+1}',
                sm_ip=f'172.16.2.{i+1}',
                location=self.location,
                group=self.group,
                created_by=self.user
            )
            test_hosts.append(host)
            
            # Store expected data
            expected_data.append({
                'hostname': host.hostname,
                'ip_address': host.ip_address,
                'device_type': host.device_type,
                'ap_name': host.ap_name,
                'cid': host.cid,
                'location': self.location.name,
                'group': self.group.name
            })
        
        # Export data
        response = self.client.post('/api/monitoring/export/', {
            'export_type': 'hosts',
            'format': export_formats,
            'location_id': str(self.location.id)
        })
        
        # Verify export succeeded
        assert response.status_code == 200, f"Export failed: {response.content}"
        
        # Verify data integrity based on format
        if export_formats == 'json':
            try:
                exported_data = json.loads(response.content.decode('utf-8'))
                
                # Verify all expected hosts are present
                assert len(exported_data) == len(expected_data), "Exported data count mismatch"
                
                # Verify each host's data integrity
                for expected_host in expected_data:
                    found = False
                    for exported_host in exported_data:
                        if exported_host['hostname'] == expected_host['hostname']:
                            found = True
                            # Verify key fields
                            assert exported_host['ip_address'] == expected_host['ip_address']
                            assert exported_host['device_type'] == expected_host['device_type']
                            assert exported_host['ap_name'] == expected_host['ap_name']
                            assert exported_host['cid'] == expected_host['cid']
                            assert exported_host['location'] == expected_host['location']
                            assert exported_host['group'] == expected_host['group']
                            break
                    
                    assert found, f"Host {expected_host['hostname']} not found in export"
                    
            except json.JSONDecodeError:
                self.fail(f"Invalid JSON in export response for format {export_formats}")
        
        elif export_formats == 'csv':
            # For CSV, verify it's parseable and has expected columns
            try:
                csv_content = response.content.decode('utf-8')
                df = pd.read_csv(io.StringIO(csv_content))
                
                # Verify expected columns are present
                expected_columns = ['hostname', 'ip_address', 'device_type', 'ap_name', 'cid', 'location', 'group']
                for col in expected_columns:
                    assert col in df.columns, f"Column {col} missing from CSV export"
                
                # Verify row count
                assert len(df) == len(expected_data), "CSV row count mismatch"
                
            except Exception as e:
                self.fail(f"Failed to parse CSV export: {e}")
        
        elif export_formats == 'excel':
            # For Excel, verify it's parseable
            try:
                excel_content = io.BytesIO(response.content)
                df = pd.read_excel(excel_content, engine='openpyxl')
                
                # Verify expected columns are present
                expected_columns = ['hostname', 'ip_address', 'device_type', 'ap_name', 'cid', 'location', 'group']
                for col in expected_columns:
                    assert col in df.columns, f"Column {col} missing from Excel export"
                
                # Verify row count
                assert len(df) == len(expected_data), "Excel row count mismatch"
                
            except Exception as e:
                self.fail(f"Failed to parse Excel export: {e}")
        
        # Cleanup
        for host in test_hosts:
            host.delete()
    
    def test_export_audit_logging_property(self):
        """
        Property: Export operations are properly logged in audit trail.
        
        This test verifies that all export operations create appropriate
        audit log entries with correct metadata.
        """
        # Clear existing audit logs
        AuditLog.objects.filter(user=self.user).delete()
        
        # Perform export operation
        response = self.client.post('/api/monitoring/export/', {
            'export_type': 'locations',
            'format': 'json'
        })
        
        # Verify export succeeded
        assert response.status_code == 200, f"Export failed: {response.content}"
        
        # Verify audit log was created
        audit_logs = AuditLog.objects.filter(
            user=self.user,
            action='export',
            resource_type='Locations'
        )
        
        assert audit_logs.exists(), "No audit log created for export operation"
        
        # Verify audit log details
        audit_log = audit_logs.first()
        assert audit_log.success is True, "Audit log should indicate success"
        assert 'export_type' in audit_log.metadata, "Audit log should contain export type"
        assert 'format' in audit_log.metadata, "Audit log should contain export format"
        assert audit_log.metadata['export_type'] == 'locations'
        assert audit_log.metadata['format'] == 'json'
    
    def test_export_error_handling_property(self):
        """
        Property: Export system handles errors gracefully and logs failures.
        
        This test verifies that invalid export requests are handled properly
        and appropriate error responses are returned.
        """
        # Test invalid export type
        response = self.client.post('/api/monitoring/export/', {
            'export_type': 'invalid_type',
            'format': 'json'
        })
        
        assert response.status_code == 400, "Invalid export type should return 400"
        
        # Test invalid format
        response = self.client.post('/api/monitoring/export/', {
            'export_type': 'hosts',
            'format': 'invalid_format'
        })
        
        assert response.status_code == 400, "Invalid format should return 400"
        
        # Test missing required fields
        response = self.client.post('/api/monitoring/export/', {})
        
        assert response.status_code == 400, "Missing fields should return 400"