"""
Views for monitoring models and bulk operations.
"""
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth import get_user_model
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.db.models import Q
from datetime import datetime, timedelta
import pandas as pd
import json
import io
import uuid
import asyncio
import logging

from .models import Location, DeviceGroup, Host, MonitoringMetric, Alert, PingResult, NotificationProfile, NotificationLog, EscalationRule
from .serializers import (
    LocationSerializer, DeviceGroupSerializer, HostSerializer,
    BulkHostUploadSerializer, MonitoringMetricSerializer, AlertSerializer,
    BulkExportSerializer, PingResultSerializer, NotificationProfileSerializer,
    NotificationLogSerializer, EscalationRuleSerializer
)
from core.permissions import IsEditor, IsViewer, CanManageDevices, CanExportData
from core.models import AuditLog
from .ping_service import PingMonitoringService

User = get_user_model()
logger = logging.getLogger(__name__)


class LocationListCreateView(generics.ListCreateAPIView):
    """List and create locations."""
    
    queryset = Location.objects.all()
    serializer_class = LocationSerializer
    permission_classes = [CanManageDevices]
    
    def get_queryset(self):
        """Filter locations based on user permissions."""
        queryset = super().get_queryset()
        
        # Add filtering by name if provided
        name = self.request.query_params.get('name')
        if name:
            queryset = queryset.filter(name__icontains=name)
        
        return queryset.order_by('name')


class LocationDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a location."""
    
    queryset = Location.objects.all()
    serializer_class = LocationSerializer
    permission_classes = [CanManageDevices]


class DeviceGroupListCreateView(generics.ListCreateAPIView):
    """List and create device groups."""
    
    queryset = DeviceGroup.objects.all()
    serializer_class = DeviceGroupSerializer
    permission_classes = [CanManageDevices]
    
    def get_queryset(self):
        """Filter device groups based on user permissions."""
        queryset = super().get_queryset()
        
        # Add filtering by name if provided
        name = self.request.query_params.get('name')
        if name:
            queryset = queryset.filter(name__icontains=name)
        
        return queryset.order_by('name')


class DeviceGroupDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a device group."""
    
    queryset = DeviceGroup.objects.all()
    serializer_class = DeviceGroupSerializer
    permission_classes = [CanManageDevices]


class HostListCreateView(generics.ListCreateAPIView):
    """List and create hosts."""
    
    queryset = Host.objects.all()
    serializer_class = HostSerializer
    permission_classes = [CanManageDevices]
    
    def get_queryset(self):
        """Filter hosts based on user permissions and query parameters."""
        queryset = super().get_queryset().select_related('location', 'group', 'created_by')
        
        # Filter by location
        location_id = self.request.query_params.get('location')
        if location_id:
            queryset = queryset.filter(location_id=location_id)
        
        # Filter by group
        group_id = self.request.query_params.get('group')
        if group_id:
            queryset = queryset.filter(group_id=group_id)
        
        # Filter by device type
        device_type = self.request.query_params.get('device_type')
        if device_type:
            queryset = queryset.filter(device_type=device_type)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Search by hostname or IP
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(hostname__icontains=search) |
                Q(ip_address__icontains=search) |
                Q(device_name__icontains=search) |
                Q(ap_name__icontains=search)
            )
        
        return queryset.order_by('hostname')


class HostDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a host."""
    
    queryset = Host.objects.all()
    serializer_class = HostSerializer
    permission_classes = [CanManageDevices]


class BulkHostUploadView(APIView):
    """Bulk upload hosts from Excel file."""
    
    permission_classes = [IsEditor]
    parser_classes = [MultiPartParser, FormParser]
    
    def post(self, request):
        """Process Excel file upload and create hosts."""
        serializer = BulkHostUploadSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'errors': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Process the Excel file
        file = serializer.validated_data['file']
        location_id = serializer.validated_data.get('location_id')
        group_id = serializer.validated_data.get('group_id')
        
        # Process file and validate data
        process_result = serializer.process_excel_file(file, location_id, group_id)
        
        if not process_result['success']:
            # Log failed upload attempt
            AuditLog.objects.create(
                user=request.user,
                username=request.user.username,
                action='import',
                resource_type='Host',
                description=f'Failed bulk host upload: {len(process_result["errors"])} errors',
                metadata={
                    'filename': file.name,
                    'total_rows': process_result['total_rows'],
                    'errors': process_result['errors'][:10]  # First 10 errors
                },
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False,
                error_message='; '.join(process_result['errors'][:3])
            )
            
            return Response({
                'success': False,
                'message': 'File processing failed',
                'errors': process_result['errors'],
                'column_mapping': process_result['column_mapping'],
                'total_rows': process_result['total_rows'],
                'valid_rows': process_result['valid_rows']
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create hosts from validated data
        create_result = serializer.create_hosts(process_result['data'], request.user)
        
        # Log successful upload
        AuditLog.objects.create(
            user=request.user,
            username=request.user.username,
            action='import',
            resource_type='Host',
            description=f'Bulk host upload: {create_result["created"]} hosts created',
            metadata={
                'filename': file.name,
                'total_rows': process_result['total_rows'],
                'valid_rows': process_result['valid_rows'],
                'created': create_result['created'],
                'duplicates': len(create_result['duplicates']),
                'errors': len(create_result['errors'])
            },
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=create_result['success']
        )
        
        return Response({
            'success': create_result['success'],
            'message': f'Successfully processed {process_result["total_rows"]} rows',
            'column_mapping': process_result['column_mapping'],
            'total_rows': process_result['total_rows'],
            'valid_rows': process_result['valid_rows'],
            'created': create_result['created'],
            'duplicates': create_result['duplicates'],
            'errors': create_result['errors']
        }, status=status.HTTP_200_OK if create_result['success'] else status.HTTP_207_MULTI_STATUS)
    
    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


@api_view(['POST'])
@permission_classes([IsEditor])
def validate_excel_file(request):
    """Validate Excel file without creating hosts."""
    if 'file' not in request.FILES:
        return Response(
            {'error': 'No file provided'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    file = request.FILES['file']
    location_id = request.data.get('location_id')
    group_id = request.data.get('group_id')
    
    # Validate file format
    if not file.name.endswith(('.xlsx', '.xls')):
        return Response(
            {'error': 'File must be in Excel format (.xlsx or .xls)'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Process file for validation only
    serializer = BulkHostUploadSerializer()
    result = serializer.process_excel_file(file, location_id, group_id)
    
    return Response({
        'valid': result['success'],
        'column_mapping': result['column_mapping'],
        'total_rows': result['total_rows'],
        'valid_rows': result['valid_rows'],
        'errors': result['errors'],
        'preview': result['data'][:5] if result['data'] else []  # First 5 rows
    })


class BulkExportView(APIView):
    """Bulk export data in various formats."""
    
    permission_classes = [CanExportData]
    
    def post(self, request):
        """Export data based on specified criteria."""
        serializer = BulkExportSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'errors': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        export_type = serializer.validated_data['export_type']
        export_format = serializer.validated_data['format']
        
        try:
            # Get data based on export type
            data = self._get_export_data(serializer.validated_data, request.user)
            
            # Generate export file
            if export_format == 'excel':
                response = self._export_excel(data, export_type)
            elif export_format == 'csv':
                response = self._export_csv(data, export_type)
            elif export_format == 'json':
                response = self._export_json(data, export_type)
            elif export_format == 'pdf':
                response = self._export_pdf(data, export_type)
            else:
                return Response(
                    {'error': 'Unsupported export format'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Log export action
            AuditLog.objects.create(
                user=request.user,
                username=request.user.username,
                action='export',
                resource_type=export_type.title(),
                description=f'Exported {len(data)} {export_type} records as {export_format.upper()}',
                metadata={
                    'export_type': export_type,
                    'format': export_format,
                    'record_count': len(data)
                },
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=True
            )
            
            return response
            
        except Exception as e:
            # Log failed export
            AuditLog.objects.create(
                user=request.user,
                username=request.user.username,
                action='export',
                resource_type=export_type.title(),
                description=f'Failed to export {export_type} as {export_format.upper()}',
                metadata={
                    'export_type': export_type,
                    'format': export_format,
                    'error': str(e)
                },
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False,
                error_message=str(e)
            )
            
            return Response(
                {'error': f'Export failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_export_data(self, validated_data, user):
        """Get data for export based on criteria."""
        export_type = validated_data['export_type']
        location_id = validated_data.get('location_id')
        group_id = validated_data.get('group_id')
        start_date = validated_data.get('start_date')
        end_date = validated_data.get('end_date')
        include_inactive = validated_data.get('include_inactive', False)
        
        if export_type == 'hosts':
            queryset = Host.objects.all().select_related('location', 'group', 'created_by')
            
            if location_id:
                queryset = queryset.filter(location_id=location_id)
            if group_id:
                queryset = queryset.filter(group_id=group_id)
            if not include_inactive:
                queryset = queryset.filter(monitoring_enabled=True)
            
            return [
                {
                    'hostname': host.hostname,
                    'ip_address': host.ip_address,
                    'device_name': host.device_name,
                    'device_type': host.device_type,
                    'ap_name': host.ap_name,
                    'cid': host.cid,
                    'ap_ip': host.ap_ip,
                    'sm_ip': host.sm_ip,
                    'location': host.location.name,
                    'group': host.group.name,
                    'status': host.status,
                    'monitoring_enabled': host.monitoring_enabled,
                    'ping_enabled': host.ping_enabled,
                    'snmp_enabled': host.snmp_enabled,
                    'snmp_community': host.snmp_community,
                    'snmp_version': host.snmp_version,
                    'last_seen': host.last_seen,
                    'last_check': host.last_check,
                    'created_at': host.created_at,
                    'created_by': host.created_by.username if host.created_by else ''
                }
                for host in queryset
            ]
        
        elif export_type == 'locations':
            queryset = Location.objects.all()
            return [
                {
                    'name': loc.name,
                    'description': loc.description,
                    'address': loc.address,
                    'latitude': loc.latitude,
                    'longitude': loc.longitude,
                    'parent': loc.parent.name if loc.parent else '',
                    'created_at': loc.created_at,
                    'created_by': loc.created_by.username if loc.created_by else ''
                }
                for loc in queryset
            ]
        
        elif export_type == 'groups':
            queryset = DeviceGroup.objects.all()
            return [
                {
                    'name': group.name,
                    'description': group.description,
                    'color': group.color,
                    'icon': group.icon,
                    'parent': group.parent.name if group.parent else '',
                    'created_at': group.created_at,
                    'created_by': group.created_by.username if group.created_by else ''
                }
                for group in queryset
            ]
        
        elif export_type == 'alerts':
            queryset = Alert.objects.all().select_related('host', 'acknowledged_by')
            
            if location_id:
                queryset = queryset.filter(host__location_id=location_id)
            if group_id:
                queryset = queryset.filter(host__group_id=group_id)
            if start_date:
                queryset = queryset.filter(first_seen__gte=start_date)
            if end_date:
                queryset = queryset.filter(first_seen__lte=end_date)
            
            return [
                {
                    'host': alert.host.hostname,
                    'title': alert.title,
                    'description': alert.description,
                    'severity': alert.severity,
                    'status': alert.status,
                    'check_type': alert.check_type,
                    'first_seen': alert.first_seen,
                    'last_seen': alert.last_seen,
                    'resolved_at': alert.resolved_at,
                    'acknowledged_by': alert.acknowledged_by.username if alert.acknowledged_by else '',
                    'acknowledged_at': alert.acknowledged_at,
                    'acknowledgment_comment': alert.acknowledgment_comment
                }
                for alert in queryset
            ]
        
        elif export_type == 'audit_logs':
            # Only superadmin can export audit logs
            if not (user.is_superuser or user.user_roles.filter(role__name='superadmin').exists()):
                raise PermissionError("Insufficient permissions to export audit logs")
            
            queryset = AuditLog.objects.all().select_related('user')
            
            if start_date:
                queryset = queryset.filter(timestamp__gte=start_date)
            if end_date:
                queryset = queryset.filter(timestamp__lte=end_date)
            
            return [
                {
                    'username': log.username,
                    'action': log.action,
                    'resource_type': log.resource_type,
                    'resource_id': log.resource_id,
                    'description': log.description,
                    'ip_address': log.ip_address,
                    'timestamp': log.timestamp,
                    'success': log.success,
                    'error_message': log.error_message
                }
                for log in queryset[:1000]  # Limit to 1000 records
            ]
        
        else:
            return []
    
    def _export_excel(self, data, export_type):
        """Export data as Excel file."""
        if not data:
            # Create empty DataFrame
            df = pd.DataFrame()
        else:
            df = pd.DataFrame(data)
        
        # Create Excel file in memory
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name=export_type.title(), index=False)
        
        output.seek(0)
        
        # Create response
        response = HttpResponse(
            output.getvalue(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{export_type}_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx"'
        
        return response
    
    def _export_csv(self, data, export_type):
        """Export data as CSV file."""
        if not data:
            df = pd.DataFrame()
        else:
            df = pd.DataFrame(data)
        
        # Create CSV in memory
        output = io.StringIO()
        df.to_csv(output, index=False)
        
        # Create response
        response = HttpResponse(output.getvalue(), content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{export_type}_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        return response
    
    def _export_json(self, data, export_type):
        """Export data as JSON file."""
        # Create response
        response = HttpResponse(
            json.dumps(data, indent=2, default=str),
            content_type='application/json'
        )
        response['Content-Disposition'] = f'attachment; filename="{export_type}_{timezone.now().strftime("%Y%m%d_%H%M%S")}.json"'
        
        return response
    
    def _export_pdf(self, data, export_type):
        """Export data as PDF file (basic implementation)."""
        # For now, return JSON with PDF content type
        # In a full implementation, you would use a library like ReportLab
        response = HttpResponse(
            json.dumps(data, indent=2, default=str),
            content_type='application/pdf'
        )
        response['Content-Disposition'] = f'attachment; filename="{export_type}_{timezone.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
        
        return response
    
    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class MonitoringMetricListView(generics.ListAPIView):
    """List monitoring metrics."""
    
    queryset = MonitoringMetric.objects.all()
    serializer_class = MonitoringMetricSerializer
    permission_classes = [IsViewer]
    
    def get_queryset(self):
        """Filter metrics based on query parameters."""
        queryset = super().get_queryset().select_related('host')
        
        # Filter by host
        host_id = self.request.query_params.get('host')
        if host_id:
            queryset = queryset.filter(host_id=host_id)
        
        # Filter by metric type
        metric_type = self.request.query_params.get('metric_type')
        if metric_type:
            queryset = queryset.filter(metric_type=metric_type)
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                queryset = queryset.filter(timestamp__gte=start_dt)
            except ValueError:
                pass
        
        end_date = self.request.query_params.get('end_date')
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                queryset = queryset.filter(timestamp__lte=end_dt)
            except ValueError:
                pass
        
        return queryset.order_by('-timestamp')


class AlertListView(generics.ListAPIView):
    """List alerts."""
    
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [IsViewer]
    
    def get_queryset(self):
        """Filter alerts based on query parameters."""
        queryset = super().get_queryset().select_related('host', 'acknowledged_by')
        
        # Filter by host
        host_id = self.request.query_params.get('host')
        if host_id:
            queryset = queryset.filter(host_id=host_id)
        
        # Filter by severity
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by location
        location_id = self.request.query_params.get('location')
        if location_id:
            queryset = queryset.filter(host__location_id=location_id)
        
        # Filter by group
        group_id = self.request.query_params.get('group')
        if group_id:
            queryset = queryset.filter(host__group_id=group_id)
        
        return queryset.order_by('-first_seen')


@api_view(['GET'])
@permission_classes([IsViewer])
def dashboard_stats(request):
    """Get dashboard statistics."""
    # Host statistics
    total_hosts = Host.objects.count()
    active_hosts = Host.objects.filter(monitoring_enabled=True).count()
    up_hosts = Host.objects.filter(status='up').count()
    down_hosts = Host.objects.filter(status='down').count()
    warning_hosts = Host.objects.filter(status='warning').count()
    
    # Alert statistics
    active_alerts = Alert.objects.filter(status='active').count()
    critical_alerts = Alert.objects.filter(status='active', severity='critical').count()
    warning_alerts = Alert.objects.filter(status='active', severity='warning').count()
    
    # Location statistics
    total_locations = Location.objects.count()
    
    # Group statistics
    total_groups = DeviceGroup.objects.count()
    
    return Response({
        'hosts': {
            'total': total_hosts,
            'active': active_hosts,
            'up': up_hosts,
            'down': down_hosts,
            'warning': warning_hosts,
            'uptime_percentage': (up_hosts / active_hosts * 100) if active_hosts > 0 else 0
        },
        'alerts': {
            'active': active_alerts,
            'critical': critical_alerts,
            'warning': warning_alerts
        },
        'infrastructure': {
            'locations': total_locations,
            'groups': total_groups
        },
        'timestamp': timezone.now()
    })


# Ping Monitoring Views

class PingHostView(APIView):
    """
    Ping a specific host and return the result.
    """
    permission_classes = [IsViewer]
    
    def post(self, request, host_id):
        """Ping a specific host."""
        try:
            host = Host.objects.get(id=host_id)
        except Host.DoesNotExist:
            return Response(
                {'error': 'Host not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if not host.ping_enabled or not host.monitoring_enabled:
            return Response(
                {'error': 'Ping monitoring is disabled for this host'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Use the simple synchronous ping implementation
            from .simple_ping import ping_host_simple
            ping_result = ping_host_simple(host)
            
            if ping_result:
                serializer = PingResultSerializer(ping_result)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response(
                    {'message': 'Ping monitoring skipped (host in maintenance or disabled)'},
                    status=status.HTTP_200_OK
                )
                
        except Exception as e:
            logger.error(f"Error pinging host {host.hostname}: {e}")
            return Response(
                {'error': f'Ping failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PingMultipleHostsView(APIView):
    """
    Ping multiple hosts concurrently.
    """
    permission_classes = [IsViewer]
    
    def post(self, request):
        """Ping multiple hosts by IDs."""
        host_ids = request.data.get('host_ids', [])
        
        if not host_ids:
            return Response(
                {'error': 'host_ids list is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        hosts = Host.objects.filter(id__in=host_ids)
        
        if not hosts.exists():
            return Response(
                {'error': 'No valid hosts found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            # Use simple ping for multiple hosts (sequential for now)
            from .simple_ping import ping_host_simple
            ping_results = []
            
            for host in hosts:
                result = ping_host_simple(host)
                if result:
                    ping_results.append(result)
            
            serializer = PingResultSerializer(ping_results, many=True)
            return Response({
                'results': serializer.data,
                'total_hosts': len(hosts),
                'pinged_hosts': len(ping_results)
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error pinging multiple hosts: {e}")
            return Response(
                {'error': f'Ping operation failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PingAllHostsView(APIView):
    """
    Ping all hosts that have ping monitoring enabled.
    """
    permission_classes = [IsEditor]  # More restrictive since this affects all hosts
    
    def post(self, request):
        """Ping all enabled hosts."""
        try:
            # Use simple ping for all hosts (sequential for now)
            from .simple_ping import ping_host_simple
            from .models import Host
            
            hosts = Host.objects.filter(
                monitoring_enabled=True,
                ping_enabled=True
            ).select_related('location', 'group')
            
            ping_results = []
            for host in hosts:
                result = ping_host_simple(host)
                if result:
                    ping_results.append(result)
            
            # Group results by status
            status_counts = {}
            for result in ping_results:
                status_counts[result.status] = status_counts.get(result.status, 0) + 1
            
            return Response({
                'message': f'Ping monitoring completed for {len(ping_results)} hosts',
                'total_hosts': len(ping_results),
                'status_distribution': status_counts,
                'timestamp': timezone.now()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error pinging all hosts: {e}")
            return Response(
                {'error': f'Ping operation failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class HostPingResultsView(generics.ListAPIView):
    """
    Get ping results for a specific host.
    """
    serializer_class = PingResultSerializer
    permission_classes = [IsViewer]
    
    def get_queryset(self):
        """Get ping results for the specified host."""
        host_id = self.kwargs['host_id']
        try:
            host = Host.objects.get(id=host_id)
        except Host.DoesNotExist:
            return PingResult.objects.none()
        
        queryset = PingResult.objects.filter(host=host)
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                queryset = queryset.filter(timestamp__gte=start_dt)
            except ValueError:
                pass
        
        end_date = self.request.query_params.get('end_date')
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                queryset = queryset.filter(timestamp__lte=end_dt)
            except ValueError:
                pass
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        return queryset.order_by('-timestamp')


class HostPingSummaryView(APIView):
    """
    Get ping summary statistics for a host.
    """
    permission_classes = [IsViewer]
    
    def get(self, request, host_id):
        """Get ping summary for a specific host."""
        try:
            host = Host.objects.get(id=host_id)
        except Host.DoesNotExist:
            return Response(
                {'error': 'Host not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get hours parameter (default 24)
        hours = int(request.query_params.get('hours', 24))
        
        try:
            service = PingMonitoringService()
            summary = service.get_host_ping_summary(host, hours)
            
            return Response(summary, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': f'Failed to get ping summary: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# Notification Management Views

class NotificationProfileListCreateView(generics.ListCreateAPIView):
    """
    List and create notification profiles.
    """
    serializer_class = NotificationProfileSerializer
    permission_classes = [IsEditor]
    
    def get_queryset(self):
        """Get notification profiles with optional filtering."""
        queryset = NotificationProfile.objects.all().prefetch_related(
            'users', 'locations', 'groups'
        )
        
        # Filter by enabled status
        enabled = self.request.query_params.get('enabled')
        if enabled is not None:
            queryset = queryset.filter(enabled=enabled.lower() == 'true')
        
        # Filter by default status
        is_default = self.request.query_params.get('is_default')
        if is_default is not None:
            queryset = queryset.filter(is_default=is_default.lower() == 'true')
        
        # Search by name
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(name__icontains=search)
        
        return queryset.order_by('name')


class NotificationProfileDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete a notification profile.
    """
    queryset = NotificationProfile.objects.all().prefetch_related(
        'users', 'locations', 'groups'
    )
    serializer_class = NotificationProfileSerializer
    permission_classes = [IsEditor]


class NotificationLogListView(generics.ListAPIView):
    """
    List notification logs with filtering.
    """
    serializer_class = NotificationLogSerializer
    permission_classes = [IsViewer]
    
    def get_queryset(self):
        """Get notification logs with optional filtering."""
        queryset = NotificationLog.objects.all().select_related(
            'alert', 'profile'
        )
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by channel
        channel = self.request.query_params.get('channel')
        if channel:
            queryset = queryset.filter(channel=channel)
        
        # Filter by alert
        alert_id = self.request.query_params.get('alert')
        if alert_id:
            queryset = queryset.filter(alert_id=alert_id)
        
        # Filter by profile
        profile_id = self.request.query_params.get('profile')
        if profile_id:
            queryset = queryset.filter(profile_id=profile_id)
        
        # Filter by escalation level
        escalation_level = self.request.query_params.get('escalation_level')
        if escalation_level is not None:
            queryset = queryset.filter(escalation_level=escalation_level)
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                queryset = queryset.filter(created_at__gte=start_dt)
            except ValueError:
                pass
        
        end_date = self.request.query_params.get('end_date')
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                queryset = queryset.filter(created_at__lte=end_dt)
            except ValueError:
                pass
        
        return queryset.order_by('-created_at')


class EscalationRuleListCreateView(generics.ListCreateAPIView):
    """
    List and create escalation rules.
    """
    serializer_class = EscalationRuleSerializer
    permission_classes = [IsEditor]
    
    def get_queryset(self):
        """Get escalation rules with optional filtering."""
        queryset = EscalationRule.objects.all().prefetch_related(
            'level_1_profiles', 'level_2_profiles', 'level_3_profiles'
        )
        
        # Filter by enabled status
        enabled = self.request.query_params.get('enabled')
        if enabled is not None:
            queryset = queryset.filter(enabled=enabled.lower() == 'true')
        
        # Filter by condition type
        condition_type = self.request.query_params.get('condition_type')
        if condition_type:
            queryset = queryset.filter(condition_type=condition_type)
        
        # Search by name
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(name__icontains=search)
        
        return queryset.order_by('-priority', 'name')


class EscalationRuleDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete an escalation rule.
    """
    queryset = EscalationRule.objects.all().prefetch_related(
        'level_1_profiles', 'level_2_profiles', 'level_3_profiles'
    )
    serializer_class = EscalationRuleSerializer
    permission_classes = [IsEditor]


@api_view(['POST'])
@permission_classes([IsEditor])
def test_notification_channel(request):
    """
    Test a notification channel with a test message.
    """
    channel = request.data.get('channel')
    recipient = request.data.get('recipient')
    
    if not channel or not recipient:
        return Response(
            {'error': 'Channel and recipient are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        from .notification_service import test_notification_channel
        
        success = test_notification_channel(channel, recipient)
        
        if success:
            return Response(
                {'message': f'Test notification sent successfully via {channel}'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': f'Failed to send test notification via {channel}'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    except Exception as e:
        logger.error(f"Error testing notification channel {channel}: {e}")
        return Response(
            {'error': f'Failed to test notification channel: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsViewer])
def notification_channel_status(request):
    """
    Get status of all notification channels.
    """
    try:
        from .notification_service import get_notification_status
        
        status_info = get_notification_status()
        
        return Response(status_info, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error getting notification channel status: {e}")
        return Response(
            {'error': f'Failed to get channel status: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsEditor])
def send_test_alert_notification(request):
    """
    Send a test alert notification to verify the notification system.
    """
    alert_id = request.data.get('alert_id')
    escalation_level = request.data.get('escalation_level', 0)
    
    if not alert_id:
        return Response(
            {'error': 'Alert ID is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        alert = Alert.objects.get(id=alert_id)
        
        from .notification_service import send_alert_notification
        
        results = send_alert_notification(alert, escalation_level)
        
        return Response({
            'message': 'Test alert notification sent',
            'results': results,
            'alert_title': alert.title,
            'escalation_level': escalation_level
        }, status=status.HTTP_200_OK)
        
    except Alert.DoesNotExist:
        return Response(
            {'error': 'Alert not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Error sending test alert notification: {e}")
        return Response(
            {'error': f'Failed to send test notification: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsViewer])
def notification_statistics(request):
    """
    Get notification statistics for dashboard.
    """
    try:
        from django.db.models import Count, Q, Avg
        from datetime import timedelta
        
        # Get notification statistics
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        # Notification counts by status
        status_counts = NotificationLog.objects.values('status').annotate(
            count=Count('id')
        ).order_by('status')
        
        # Notification counts by channel
        channel_counts = NotificationLog.objects.values('channel').annotate(
            count=Count('id')
        ).order_by('channel')
        
        # Recent notification activity
        recent_notifications = NotificationLog.objects.filter(
            created_at__gte=last_24h
        ).count()
        
        # Failed notifications in last 24h
        failed_notifications = NotificationLog.objects.filter(
            status='failed',
            created_at__gte=last_24h
        ).count()
        
        # Retry statistics
        retry_stats = NotificationLog.objects.filter(
            retry_count__gt=0
        ).aggregate(
            total_retries=Count('id'),
            avg_retries=Avg('retry_count')
        )
        
        # Escalation statistics
        escalation_stats = NotificationLog.objects.filter(
            escalation_level__gt=0
        ).values('escalation_level').annotate(
            count=Count('id')
        ).order_by('escalation_level')
        
        # Active notification profiles
        active_profiles = NotificationProfile.objects.filter(enabled=True).count()
        
        # Active escalation rules
        active_rules = EscalationRule.objects.filter(enabled=True).count()
        
        return Response({
            'status_distribution': {item['status']: item['count'] for item in status_counts},
            'channel_distribution': {item['channel']: item['count'] for item in channel_counts},
            'recent_notifications_24h': recent_notifications,
            'failed_notifications_24h': failed_notifications,
            'retry_statistics': retry_stats,
            'escalation_distribution': {f"level_{item['escalation_level']}": item['count'] for item in escalation_stats},
            'active_profiles': active_profiles,
            'active_escalation_rules': active_rules,
            'total_notifications': NotificationLog.objects.count()
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error getting notification statistics: {e}")
        return Response(
            {'error': f'Failed to get notification statistics: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )