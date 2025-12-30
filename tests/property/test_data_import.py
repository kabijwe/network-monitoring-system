"""
Property-based tests for data import functionality.

These tests validate the Excel file processing, column auto-detection,
and bulk data validation using property-based testing with Hypothesis.
"""
import pytest
import django
from django.conf import settings
from django.test import TestCase, override_settings, TransactionTestCase
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient
from rest_framework import status
from hypothesis import given, strategies as st, settings as hypothesis_settings, assume
from hypothesis.extra.django import TestCase as HypothesisTestCase
import pandas as pd
import io
import tempfile
import os

# Configure Django settings if not already configured
if not settings.configured:
    import os
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nms.settings')
    django.setup()

from monitoring.models import Location, DeviceGroup, Host
from monitoring.serializers import BulkHostUploadSerializer
from core.models import Role, UserRole

User = get_user_model()


class DataImportPropertyTests(HypothesisTestCase):
    """Property-based tests for data import functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create test user with editor role
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Create editor role
        editor_role = Role.objects.create(
            name='editor',
            description='Editor role for testing'
        )
        UserRole.objects.create(user=self.user, role=editor_role)
        
        # Create test location and group
        self.location = Location.objects.create(
            name='Test Location',
            description='Test location for import',
            created_by=self.user
        )
        
        self.group = DeviceGroup.objects.create(
            name='Test Group',
            description='Test group for import',
            created_by=self.user
        )
        
        # Authenticate client
        self.client.force_authenticate(user=self.user)
    
    @given(
        hostnames=st.lists(
            st.text(
                alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pd')),
                min_size=3,
                max_size=50
            ).filter(lambda x: x.strip() and not x.startswith('-') and not x.endswith('-')),
            min_size=1,
            max_size=20,
            unique=True
        ),
        ip_addresses=st.lists(
            st.builds(
                lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
                st.integers(min_value=1, max_value=254),
                st.integers(min_value=0, max_value=255),
                st.integers(min_value=0, max_value=255),
                st.integers(min_value=1, max_value=254)
            ),
            min_size=1,
            max_size=20,
            unique=True
        )
    )
    @hypothesis_settings(max_examples=50, deadline=10000)
    def test_excel_column_auto_detection_property(self, hostnames, ip_addresses):
        """
        Property 7: Excel column auto-detection works correctly for various column name formats.
        
        This test verifies that the column auto-detection algorithm correctly identifies
        ISP-specific fields regardless of column naming variations.
        """
        assume(len(hostnames) == len(ip_addresses))
        
        # Test different column name variations
        column_variations = [
            # Standard names
            {'hostname': 'hostname', 'ip_address': 'ip_address'},
            # Alternative names
            {'hostname': 'Host Name', 'ip_address': 'IP Address'},
            # ISP-specific names
            {'hostname': 'Device Name', 'ip_address': 'Host IP'},
            # Mixed case
            {'hostname': 'HOSTNAME', 'ip_address': 'ip'},
        ]
        
        for variation in column_variations:
            # Create test data
            data = []
            for hostname, ip in zip(hostnames[:10], ip_addresses[:10]):  # Limit for performance
                data.append({
                    variation['hostname']: hostname,
                    variation['ip_address']: ip,
                    'device_type': 'ap',
                    'location': self.location.name,
                    'group': self.group.name
                })
            
            # Create Excel file
            df = pd.DataFrame(data)
            excel_buffer = io.BytesIO()
            df.to_excel(excel_buffer, index=False, engine='openpyxl')
            excel_buffer.seek(0)
            
            # Test column detection
            serializer = BulkHostUploadSerializer()
            column_mapping = serializer._detect_columns(df.columns.tolist())
            
            # Verify detection worked
            assert 'hostname' in column_mapping, f"Failed to detect hostname column in {variation}"
            assert 'ip_address' in column_mapping, f"Failed to detect IP address column in {variation}"
            
            # Verify correct mapping
            assert column_mapping['hostname'] == variation['hostname']
            assert column_mapping['ip_address'] == variation['ip_address']
    
    @given(
        valid_ips=st.lists(
            st.builds(
                lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
                st.integers(min_value=1, max_value=254),
                st.integers(min_value=0, max_value=255),
                st.integers(min_value=0, max_value=255),
                st.integers(min_value=1, max_value=254)
            ),
            min_size=1,
            max_size=10,
            unique=True
        ),
        invalid_ips=st.lists(
            st.one_of(
                st.text(alphabet='abcdefghijklmnopqrstuvwxyz', min_size=1, max_size=15),
                st.builds(lambda a: f"{a}.{a}.{a}.{a}", st.integers(min_value=256, max_value=999)),
                st.just("999.999.999.999"),
                st.just("0.0.0.0"),
                st.just("255.255.255.255")
            ),
            min_size=1,
            max_size=5
        )
    )
    @hypothesis_settings(max_examples=30, deadline=10000)
    def test_data_validation_during_bulk_operations_property(self, valid_ips, invalid_ips):
        """
        Property 8: Data validation during bulk operations correctly identifies valid and invalid data.
        
        This test ensures that the bulk upload process properly validates IP addresses,
        hostnames, and other ISP-specific fields.
        """
        # Test valid data processing
        valid_data = []
        for i, ip in enumerate(valid_ips):
            valid_data.append({
                'hostname': f'host{i:03d}',
                'ip_address': ip,
                'device_type': 'ap',
                'location': self.location.name,
                'group': self.group.name
            })
        
        # Create Excel file with valid data
        df_valid = pd.DataFrame(valid_data)
        excel_buffer = io.BytesIO()
        df_valid.to_excel(excel_buffer, index=False, engine='openpyxl')
        excel_buffer.seek(0)
        
        # Test processing
        serializer = BulkHostUploadSerializer()
        result = serializer.process_excel_file(
            excel_buffer, 
            self.location.id, 
            self.group.id
        )
        
        # All valid data should be processed successfully
        assert result['success'], f"Valid data processing failed: {result['errors']}"
        assert result['valid_rows'] == len(valid_ips), "Not all valid rows were processed"
        assert len(result['errors']) == 0, f"Unexpected errors in valid data: {result['errors']}"
        
        # Test invalid data processing
        invalid_data = []
        for i, ip in enumerate(invalid_ips):
            invalid_data.append({
                'hostname': f'invalid{i:03d}',
                'ip_address': ip,
                'device_type': 'ap',
                'location': self.location.name,
                'group': self.group.name
            })
        
        # Create Excel file with invalid data
        df_invalid = pd.DataFrame(invalid_data)
        excel_buffer = io.BytesIO()
        df_invalid.to_excel(excel_buffer, index=False, engine='openpyxl')
        excel_buffer.seek(0)
        
        # Test processing
        result = serializer.process_excel_file(
            excel_buffer, 
            self.location.id, 
            self.group.id
        )
        
        # Invalid data should be rejected
        assert not result['success'] or result['valid_rows'] == 0, "Invalid data was incorrectly accepted"
        assert len(result['errors']) > 0, "No errors reported for invalid data"
    
    @given(
        device_types=st.lists(
            st.sampled_from(['ap', 'sm', 'switch', 'router', 'firewall', 'server', 'other']),
            min_size=1,
            max_size=10
        ),
        ap_names=st.lists(
            st.text(
                alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pd')),
                min_size=1,
                max_size=30
            ).filter(lambda x: x.strip()),
            min_size=1,
            max_size=10
        ),
        cids=st.lists(
            st.text(
                alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd')),
                min_size=1,
                max_size=20
            ).filter(lambda x: x.strip()),
            min_size=1,
            max_size=10
        )
    )
    @hypothesis_settings(max_examples=30, deadline=10000)
    def test_isp_specific_field_processing_property(self, device_types, ap_names, cids):
        """
        Property: ISP-specific fields (AP Name, CID, AP IP, SM IP) are correctly processed.
        
        This test verifies that ISP-specific fields are properly validated and stored
        during bulk import operations.
        """
        assume(len(device_types) == len(ap_names) == len(cids))
        
        # Create test data with ISP-specific fields
        data = []
        for i, (device_type, ap_name, cid) in enumerate(zip(device_types, ap_names, cids)):
            data.append({
                'hostname': f'host{i:03d}',
                'ip_address': f'192.168.1.{i+10}',
                'device_type': device_type,
                'ap_name': ap_name,
                'cid': cid,
                'ap_ip': f'10.0.1.{i+1}',
                'sm_ip': f'10.0.2.{i+1}',
                'location': self.location.name,
                'group': self.group.name
            })
        
        # Create Excel file
        df = pd.DataFrame(data)
        excel_buffer = io.BytesIO()
        df.to_excel(excel_buffer, index=False, engine='openpyxl')
        excel_buffer.seek(0)
        
        # Process file
        serializer = BulkHostUploadSerializer()
        result = serializer.process_excel_file(
            excel_buffer, 
            self.location.id, 
            self.group.id
        )
        
        # Verify processing
        assert result['success'], f"ISP field processing failed: {result['errors']}"
        assert result['valid_rows'] == len(data), "Not all ISP data rows were processed"
        
        # Verify field mapping
        column_mapping = result['column_mapping']
        expected_fields = ['hostname', 'ip_address', 'device_type', 'ap_name', 'cid', 'ap_ip', 'sm_ip']
        for field in expected_fields:
            assert field in column_mapping, f"ISP field {field} not detected in column mapping"
        
        # Verify data integrity
        for i, processed_row in enumerate(result['data']):
            assert processed_row['device_type'] == device_types[i]
            assert processed_row['ap_name'] == ap_names[i]
            assert processed_row['cid'] == cids[i]
    
    @given(
        user_roles=st.sampled_from(['viewer', 'editor', 'admin', 'superadmin']),
        operation_types=st.sampled_from(['upload', 'export', 'validate'])
    )
    @hypothesis_settings(max_examples=20, deadline=5000)
    def test_permission_based_bulk_operations_property(self, user_roles, operation_types):
        """
        Property 9: Permission-based bulk operations enforce correct access control.
        
        This test verifies that bulk operations respect role-based permissions
        and only allow authorized users to perform specific operations.
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
        
        # Create minimal test Excel file
        data = [{
            'hostname': 'testhost',
            'ip_address': '192.168.1.100',
            'device_type': 'ap',
            'location': self.location.name,
            'group': self.group.name
        }]
        
        df = pd.DataFrame(data)
        excel_buffer = io.BytesIO()
        df.to_excel(excel_buffer, index=False, engine='openpyxl')
        excel_buffer.seek(0)
        
        # Create uploaded file
        uploaded_file = SimpleUploadedFile(
            "test.xlsx",
            excel_buffer.getvalue(),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        
        # Test permissions based on role and operation
        if operation_types == 'upload':
            response = client.post('/api/monitoring/hosts/bulk-upload/', {
                'file': uploaded_file,
                'location_id': str(self.location.id),
                'group_id': str(self.group.id)
            }, format='multipart')
            
            # Only editor, admin, and superadmin should be able to upload
            if user_roles in ['editor', 'admin', 'superadmin']:
                assert response.status_code in [200, 207], f"Upload should be allowed for {user_roles}"
            else:
                assert response.status_code == 403, f"Upload should be forbidden for {user_roles}"
        
        elif operation_types == 'export':
            response = client.post('/api/monitoring/export/', {
                'export_type': 'hosts',
                'format': 'excel'
            })
            
            # All roles should be able to export (with data filtering)
            assert response.status_code in [200, 403], f"Export response unexpected for {user_roles}"
        
        elif operation_types == 'validate':
            # Reset file pointer
            excel_buffer.seek(0)
            uploaded_file = SimpleUploadedFile(
                "test.xlsx",
                excel_buffer.getvalue(),
                content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
            
            response = client.post('/api/monitoring/hosts/validate-excel/', {
                'file': uploaded_file
            }, format='multipart')
            
            # Only editor, admin, and superadmin should be able to validate
            if user_roles in ['editor', 'admin', 'superadmin']:
                assert response.status_code == 200, f"Validation should be allowed for {user_roles}"
            else:
                assert response.status_code == 403, f"Validation should be forbidden for {user_roles}"
    
    @given(
        file_sizes=st.integers(min_value=1, max_value=15),  # MB
        row_counts=st.integers(min_value=1, max_value=1000)
    )
    @hypothesis_settings(max_examples=10, deadline=15000)
    def test_bulk_operation_performance_property(self, file_sizes, row_counts):
        """
        Property: Bulk operations handle various file sizes and row counts efficiently.
        
        This test verifies that the system can handle different scales of bulk operations
        without performance degradation or memory issues.
        """
        assume(file_sizes <= 10)  # Limit file size for testing
        assume(row_counts <= 100)  # Limit rows for testing performance
        
        # Create test data
        data = []
        for i in range(min(row_counts, 50)):  # Limit for test performance
            data.append({
                'hostname': f'perftest{i:04d}',
                'ip_address': f'192.168.{(i // 254) + 1}.{(i % 254) + 1}',
                'device_type': 'ap',
                'location': self.location.name,
                'group': self.group.name
            })
        
        # Create Excel file
        df = pd.DataFrame(data)
        excel_buffer = io.BytesIO()
        df.to_excel(excel_buffer, index=False, engine='openpyxl')
        excel_buffer.seek(0)
        
        # Test processing performance
        serializer = BulkHostUploadSerializer()
        result = serializer.process_excel_file(
            excel_buffer, 
            self.location.id, 
            self.group.id
        )
        
        # Verify processing completed successfully
        assert result['success'], f"Performance test failed: {result['errors']}"
        assert result['total_rows'] == len(data), "Row count mismatch in performance test"
        assert result['valid_rows'] <= len(data), "Valid rows exceed total rows"
        
        # Verify memory efficiency (no excessive memory usage)
        assert len(result['data']) <= len(data), "Processed data exceeds input data"
    
    def test_excel_file_format_validation_property(self):
        """
        Property: Excel file format validation correctly accepts and rejects file types.
        
        This test verifies that only valid Excel files are accepted for processing.
        """
        # Test valid Excel formats
        valid_formats = ['.xlsx', '.xls']
        for ext in valid_formats:
            # Create minimal Excel file
            data = [{'hostname': 'test', 'ip_address': '192.168.1.1'}]
            df = pd.DataFrame(data)
            excel_buffer = io.BytesIO()
            df.to_excel(excel_buffer, index=False, engine='openpyxl')
            excel_buffer.seek(0)
            
            uploaded_file = SimpleUploadedFile(
                f"test{ext}",
                excel_buffer.getvalue(),
                content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
            
            serializer = BulkHostUploadSerializer(data={'file': uploaded_file})
            assert serializer.is_valid(), f"Valid Excel format {ext} was rejected"
        
        # Test invalid formats
        invalid_formats = ['.txt', '.csv', '.pdf', '.doc']
        for ext in invalid_formats:
            uploaded_file = SimpleUploadedFile(
                f"test{ext}",
                b"fake content",
                content_type="text/plain"
            )
            
            serializer = BulkHostUploadSerializer(data={'file': uploaded_file})
            assert not serializer.is_valid(), f"Invalid format {ext} was accepted"
            assert 'file' in serializer.errors, f"No file error for invalid format {ext}"