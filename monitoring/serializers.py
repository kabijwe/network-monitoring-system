"""
Serializers for monitoring models and bulk operations.
"""
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import (
    Location, DeviceGroup, Host, MonitoringMetric, Alert, PingResult,
    NotificationProfile, NotificationLog, EscalationRule
)
import pandas as pd
import openpyxl
from io import BytesIO
import uuid

User = get_user_model()


class LocationSerializer(serializers.ModelSerializer):
    """Serializer for Location model."""
    
    class Meta:
        model = Location
        fields = [
            'id', 'name', 'description', 'address', 'latitude', 'longitude',
            'parent', 'created_at', 'updated_at', 'created_by'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'created_by']
    
    def create(self, validated_data):
        """Create location with current user as creator."""
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class DeviceGroupSerializer(serializers.ModelSerializer):
    """Serializer for DeviceGroup model."""
    
    class Meta:
        model = DeviceGroup
        fields = [
            'id', 'name', 'description', 'color', 'icon', 'parent',
            'created_at', 'updated_at', 'created_by'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'created_by']
    
    def create(self, validated_data):
        """Create device group with current user as creator."""
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class HostSerializer(serializers.ModelSerializer):
    """Serializer for Host model with ISP-specific fields."""
    
    location_name = serializers.CharField(source='location.name', read_only=True)
    group_name = serializers.CharField(source='group.name', read_only=True)
    
    class Meta:
        model = Host
        fields = [
            'id', 'hostname', 'ip_address', 'device_name', 'device_type',
            'ap_name', 'cid', 'ap_ip', 'sm_ip', 'location', 'location_name',
            'group', 'group_name', 'monitoring_enabled', 'ping_enabled',
            'snmp_enabled', 'snmp_community', 'snmp_version', 'status',
            'last_seen', 'last_check', 'acknowledged', 'acknowledged_by',
            'acknowledged_at', 'acknowledgment_comment', 'in_maintenance',
            'maintenance_start', 'maintenance_end', 'maintenance_comment',
            'created_at', 'updated_at', 'created_by'
        ]
        read_only_fields = [
            'id', 'last_seen', 'last_check', 'acknowledged_by',
            'acknowledged_at', 'created_at', 'updated_at', 'created_by'
        ]
    
    def create(self, validated_data):
        """Create host with current user as creator."""
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class BulkHostUploadSerializer(serializers.Serializer):
    """Serializer for bulk host upload from Excel files."""
    
    file = serializers.FileField()
    location_id = serializers.UUIDField(required=False, allow_null=True)
    group_id = serializers.UUIDField(required=False, allow_null=True)
    
    def validate_file(self, value):
        """Validate uploaded file is Excel format."""
        if not value.name.endswith(('.xlsx', '.xls')):
            raise serializers.ValidationError(
                "File must be in Excel format (.xlsx or .xls)"
            )
        
        # Check file size (max 10MB)
        if value.size > 10 * 1024 * 1024:
            raise serializers.ValidationError(
                "File size must be less than 10MB"
            )
        
        return value
    
    def validate_location_id(self, value):
        """Validate location exists."""
        if value and not Location.objects.filter(id=value).exists():
            raise serializers.ValidationError("Location does not exist")
        return value
    
    def validate_group_id(self, value):
        """Validate device group exists."""
        if value and not DeviceGroup.objects.filter(id=value).exists():
            raise serializers.ValidationError("Device group does not exist")
        return value
    
    def process_excel_file(self, file, location_id=None, group_id=None):
        """
        Process Excel file and return validation results.
        
        Returns:
            dict: {
                'success': bool,
                'data': list of host data,
                'errors': list of validation errors,
                'column_mapping': dict of detected columns,
                'total_rows': int,
                'valid_rows': int
            }
        """
        try:
            # Read Excel file
            df = pd.read_excel(file, engine='openpyxl')
            
            # Auto-detect column mapping
            column_mapping = self._detect_columns(df.columns.tolist())
            
            # Process rows
            results = {
                'success': True,
                'data': [],
                'errors': [],
                'column_mapping': column_mapping,
                'total_rows': len(df),
                'valid_rows': 0
            }
            
            # Get default location and group if provided
            default_location = None
            default_group = None
            
            if location_id:
                try:
                    default_location = Location.objects.get(id=location_id)
                except Location.DoesNotExist:
                    results['errors'].append("Default location not found")
                    results['success'] = False
                    return results
            
            if group_id:
                try:
                    default_group = DeviceGroup.objects.get(id=group_id)
                except DeviceGroup.DoesNotExist:
                    results['errors'].append("Default device group not found")
                    results['success'] = False
                    return results
            
            # Process each row
            for index, row in df.iterrows():
                row_num = index + 2  # Excel row number (1-indexed + header)
                
                try:
                    host_data = self._process_row(
                        row, column_mapping, row_num, 
                        default_location, default_group
                    )
                    
                    if host_data:
                        results['data'].append(host_data)
                        results['valid_rows'] += 1
                        
                except Exception as e:
                    results['errors'].append(f"Row {row_num}: {str(e)}")
            
            # If no valid rows, mark as failed
            if results['valid_rows'] == 0:
                results['success'] = False
                results['errors'].append("No valid rows found in the file")
            
            return results
            
        except Exception as e:
            return {
                'success': False,
                'data': [],
                'errors': [f"Failed to process Excel file: {str(e)}"],
                'column_mapping': {},
                'total_rows': 0,
                'valid_rows': 0
            }
    
    def _detect_columns(self, columns):
        """Auto-detect column mapping based on column names."""
        column_mapping = {}
        
        # Define column patterns for auto-detection
        patterns = {
            'hostname': ['hostname', 'host', 'device_name', 'name', 'device name'],
            'ip_address': ['ip', 'ip_address', 'ip address', 'ipaddress', 'host_ip'],
            'device_name': ['device_name', 'device name', 'description', 'alias'],
            'device_type': ['device_type', 'device type', 'type', 'category'],
            'ap_name': ['ap_name', 'ap name', 'access_point', 'access point', 'ap'],
            'cid': ['cid', 'customer_id', 'customer id', 'client_id'],
            'ap_ip': ['ap_ip', 'ap ip', 'access_point_ip', 'access point ip'],
            'sm_ip': ['sm_ip', 'sm ip', 'subscriber_ip', 'subscriber ip', 'client_ip'],
            'location': ['location', 'site', 'area', 'region'],
            'group': ['group', 'device_group', 'device group', 'category'],
            'snmp_community': ['snmp_community', 'snmp community', 'community'],
            'snmp_version': ['snmp_version', 'snmp version', 'version']
        }
        
        # Convert column names to lowercase for matching
        lower_columns = [col.lower().strip() for col in columns]
        
        # Match patterns
        for field, pattern_list in patterns.items():
            for pattern in pattern_list:
                if pattern.lower() in lower_columns:
                    column_index = lower_columns.index(pattern.lower())
                    column_mapping[field] = columns[column_index]
                    break
        
        return column_mapping
    
    def _process_row(self, row, column_mapping, row_num, default_location, default_group):
        """Process a single row from the Excel file."""
        host_data = {}
        
        # Required fields
        required_fields = ['hostname', 'ip_address']
        
        # Extract data based on column mapping
        for field, column_name in column_mapping.items():
            if column_name in row.index:
                value = row[column_name]
                
                # Skip empty values
                if pd.isna(value) or str(value).strip() == '':
                    continue
                
                # Clean and validate the value
                if field == 'ip_address':
                    # Basic IP validation
                    ip_str = str(value).strip()
                    if not self._is_valid_ip(ip_str):
                        raise ValueError(f"Invalid IP address: {ip_str}")
                    host_data[field] = ip_str
                
                elif field in ['ap_ip', 'sm_ip']:
                    # Optional IP fields
                    ip_str = str(value).strip()
                    if ip_str and not self._is_valid_ip(ip_str):
                        raise ValueError(f"Invalid {field}: {ip_str}")
                    host_data[field] = ip_str if ip_str else None
                
                elif field == 'device_type':
                    # Validate device type
                    device_type = str(value).lower().strip()
                    valid_types = ['ap', 'sm', 'switch', 'router', 'firewall', 'server', 'other']
                    if device_type not in valid_types:
                        # Try to map common variations
                        type_mapping = {
                            'access point': 'ap',
                            'accesspoint': 'ap',
                            'subscriber module': 'sm',
                            'subscriber': 'sm',
                            'client': 'sm'
                        }
                        device_type = type_mapping.get(device_type, 'other')
                    host_data[field] = device_type
                
                elif field == 'snmp_version':
                    # Validate SNMP version
                    version = str(value).strip()
                    if version not in ['1', '2c', '3']:
                        version = '2c'  # Default
                    host_data[field] = version
                
                else:
                    # String fields
                    host_data[field] = str(value).strip()
        
        # Check required fields
        for field in required_fields:
            if field not in host_data or not host_data[field]:
                raise ValueError(f"Missing required field: {field}")
        
        # Set defaults
        host_data.setdefault('device_name', host_data.get('hostname', ''))
        host_data.setdefault('device_type', 'other')
        host_data.setdefault('monitoring_enabled', True)
        host_data.setdefault('ping_enabled', True)
        host_data.setdefault('snmp_enabled', False)
        host_data.setdefault('snmp_community', 'public')
        host_data.setdefault('snmp_version', '2c')
        host_data.setdefault('status', 'unknown')
        
        # Handle location and group
        if 'location' in host_data:
            # Try to find location by name
            location_name = host_data.pop('location')
            try:
                location = Location.objects.get(name__iexact=location_name)
                host_data['location'] = location
            except Location.DoesNotExist:
                if default_location:
                    host_data['location'] = default_location
                else:
                    raise ValueError(f"Location '{location_name}' not found")
        elif default_location:
            host_data['location'] = default_location
        else:
            raise ValueError("No location specified")
        
        if 'group' in host_data:
            # Try to find group by name
            group_name = host_data.pop('group')
            try:
                group = DeviceGroup.objects.get(name__iexact=group_name)
                host_data['group'] = group
            except DeviceGroup.DoesNotExist:
                if default_group:
                    host_data['group'] = default_group
                else:
                    raise ValueError(f"Device group '{group_name}' not found")
        elif default_group:
            host_data['group'] = default_group
        else:
            raise ValueError("No device group specified")
        
        return host_data
    
    def _is_valid_ip(self, ip_str):
        """Basic IP address validation."""
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            return True
        except (ValueError, AttributeError):
            return False
    
    def create_hosts(self, validated_data, user):
        """Create hosts from processed data."""
        results = {
            'success': True,
            'created': 0,
            'errors': [],
            'duplicates': []
        }
        
        for host_data in validated_data:
            try:
                # Check for duplicates
                existing = Host.objects.filter(
                    hostname=host_data['hostname'],
                    ip_address=host_data['ip_address']
                ).first()
                
                if existing:
                    results['duplicates'].append({
                        'hostname': host_data['hostname'],
                        'ip_address': host_data['ip_address'],
                        'message': 'Host already exists'
                    })
                    continue
                
                # Create host
                host_data['created_by'] = user
                host = Host.objects.create(**host_data)
                results['created'] += 1
                
            except Exception as e:
                results['errors'].append({
                    'hostname': host_data.get('hostname', 'Unknown'),
                    'error': str(e)
                })
        
        if results['created'] == 0 and not results['duplicates']:
            results['success'] = False
        
        return results


class MonitoringMetricSerializer(serializers.ModelSerializer):
    """Serializer for MonitoringMetric model."""
    
    host_hostname = serializers.CharField(source='host.hostname', read_only=True)
    
    class Meta:
        model = MonitoringMetric
        fields = [
            'id', 'host', 'host_hostname', 'metric_type', 'metric_name',
            'value', 'unit', 'interface', 'additional_data', 'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']


class AlertSerializer(serializers.ModelSerializer):
    """Serializer for Alert model."""
    
    host_hostname = serializers.CharField(source='host.hostname', read_only=True)
    acknowledged_by_username = serializers.CharField(source='acknowledged_by.username', read_only=True)
    
    class Meta:
        model = Alert
        fields = [
            'id', 'host', 'host_hostname', 'title', 'description', 'severity',
            'status', 'check_type', 'metric_name', 'threshold_value',
            'current_value', 'first_seen', 'last_seen', 'resolved_at',
            'acknowledged_by', 'acknowledged_by_username', 'acknowledged_at',
            'acknowledgment_comment', 'notifications_sent', 'last_notification'
        ]
        read_only_fields = [
            'id', 'first_seen', 'last_seen', 'resolved_at',
            'acknowledged_by', 'acknowledged_at', 'notifications_sent',
            'last_notification'
        ]


class PingResultSerializer(serializers.ModelSerializer):
    """
    Serializer for PingResult model.
    """
    host_hostname = serializers.CharField(source='host.hostname', read_only=True)
    host_ip = serializers.CharField(source='host.ip_address', read_only=True)
    
    class Meta:
        model = PingResult
        fields = [
            'id', 'host', 'host_hostname', 'host_ip', 'success', 'latency',
            'packet_loss', 'packets_sent', 'packets_received', 'status',
            'status_reason', 'error_message', 'timestamp', 'check_duration'
        ]
        read_only_fields = ['id', 'timestamp']


class BulkExportSerializer(serializers.Serializer):
    """Serializer for bulk data export."""
    
    EXPORT_FORMATS = [
        ('excel', 'Excel (.xlsx)'),
        ('csv', 'CSV'),
        ('json', 'JSON'),
        ('pdf', 'PDF')
    ]
    
    EXPORT_TYPES = [
        ('hosts', 'Hosts'),
        ('locations', 'Locations'),
        ('groups', 'Device Groups'),
        ('alerts', 'Alerts'),
        ('metrics', 'Metrics'),
        ('audit_logs', 'Audit Logs')
    ]
    
    export_type = serializers.ChoiceField(choices=EXPORT_TYPES)
    format = serializers.ChoiceField(choices=EXPORT_FORMATS, default='excel')
    location_id = serializers.UUIDField(required=False, allow_null=True)
    group_id = serializers.UUIDField(required=False, allow_null=True)
    start_date = serializers.DateTimeField(required=False, allow_null=True)
    end_date = serializers.DateTimeField(required=False, allow_null=True)
    include_inactive = serializers.BooleanField(default=False)


class NotificationProfileSerializer(serializers.ModelSerializer):
    """Serializer for NotificationProfile model."""
    
    users_count = serializers.SerializerMethodField()
    locations_count = serializers.SerializerMethodField()
    groups_count = serializers.SerializerMethodField()
    enabled_channels = serializers.SerializerMethodField()
    
    class Meta:
        model = NotificationProfile
        fields = [
            'id', 'name', 'description', 'users', 'locations', 'groups',
            'is_default', 'enabled', 'min_severity', 'email_enabled',
            'email_address', 'telegram_enabled', 'telegram_chat_id',
            'slack_enabled', 'slack_channel', 'teams_enabled', 'teams_webhook',
            'sms_enabled', 'sms_number', 'quiet_hours_start', 'quiet_hours_end',
            'quiet_hours_timezone', 'escalation_enabled', 'escalation_interval_minutes',
            'max_escalation_level', 'created_at', 'updated_at', 'created_by',
            'users_count', 'locations_count', 'groups_count', 'enabled_channels'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'created_by']
    
    def get_users_count(self, obj):
        """Get count of assigned users."""
        return obj.users.count()
    
    def get_locations_count(self, obj):
        """Get count of assigned locations."""
        return obj.locations.count()
    
    def get_groups_count(self, obj):
        """Get count of assigned groups."""
        return obj.groups.count()
    
    def get_enabled_channels(self, obj):
        """Get list of enabled notification channels."""
        return obj.get_enabled_channels()
    
    def create(self, validated_data):
        """Create notification profile with current user as creator."""
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class NotificationLogSerializer(serializers.ModelSerializer):
    """Serializer for NotificationLog model."""
    
    alert_title = serializers.CharField(source='alert.title', read_only=True)
    profile_name = serializers.CharField(source='profile.name', read_only=True)
    
    class Meta:
        model = NotificationLog
        fields = [
            'id', 'alert', 'alert_title', 'profile', 'profile_name',
            'channel', 'recipient', 'subject', 'message', 'status',
            'sent_at', 'error_message', 'retry_count', 'max_retries',
            'escalation_level', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class EscalationRuleSerializer(serializers.ModelSerializer):
    """Serializer for EscalationRule model."""
    
    level_1_profiles_count = serializers.SerializerMethodField()
    level_2_profiles_count = serializers.SerializerMethodField()
    level_3_profiles_count = serializers.SerializerMethodField()
    
    class Meta:
        model = EscalationRule
        fields = [
            'id', 'name', 'description', 'enabled', 'priority',
            'condition_type', 'condition_config', 'escalation_interval_minutes',
            'max_escalation_level', 'level_1_profiles', 'level_2_profiles',
            'level_3_profiles', 'created_at', 'updated_at', 'created_by',
            'level_1_profiles_count', 'level_2_profiles_count', 'level_3_profiles_count'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'created_by']
    
    def get_level_1_profiles_count(self, obj):
        """Get count of level 1 profiles."""
        return obj.level_1_profiles.count()
    
    def get_level_2_profiles_count(self, obj):
        """Get count of level 2 profiles."""
        return obj.level_2_profiles.count()
    
    def get_level_3_profiles_count(self, obj):
        """Get count of level 3 profiles."""
        return obj.level_3_profiles.count()
    
    def create(self, validated_data):
        """Create escalation rule with current user as creator."""
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)