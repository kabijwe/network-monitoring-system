"""
Dashboard API views for Network Monitoring System.

Provides endpoints for dashboard data including summary statistics,
location health overview, and recent activity logs.
"""

from django.db.models import Count, Q, Case, When, IntegerField
from django.utils import timezone
from datetime import timedelta
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from core.models import AuditLog

# Import monitoring models with error handling
try:
    from monitoring.models import Host, Location, DeviceGroup, Alert, MonitoringResult
    MONITORING_MODELS_AVAILABLE = True
except ImportError:
    MONITORING_MODELS_AVAILABLE = False


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_overview(request):
    """
    Get complete dashboard data including summary, location health, and recent activity.
    """
    try:
        if not MONITORING_MODELS_AVAILABLE:
            return Response({
                'summary': get_empty_summary(),
                'location_health': [],
                'recent_activity': [],
                'last_updated': timezone.now().isoformat(),
                'message': 'Monitoring models not yet available'
            })
        
        # Get user's accessible locations and groups
        user_locations = request.user.get_accessible_locations()
        user_groups = request.user.get_accessible_groups()
        
        # Filter hosts based on user permissions
        hosts_queryset = Host.objects.filter(
            location__in=user_locations,
            group__in=user_groups
        )
        
        # Get summary statistics
        summary = get_dashboard_summary(hosts_queryset)
        
        # Get location health data
        location_health = get_location_health(user_locations, hosts_queryset)
        
        # Get recent activity
        recent_activity = get_recent_activity(hosts_queryset, limit=50)
        
        return Response({
            'summary': summary,
            'location_health': location_health,
            'recent_activity': recent_activity,
            'last_updated': timezone.now().isoformat()
        })
        
    except Exception as e:
        return Response(
            {'error': f'Failed to fetch dashboard data: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_summary(request):
    """
    Get dashboard summary statistics.
    """
    try:
        if not MONITORING_MODELS_AVAILABLE:
            return Response(get_empty_summary())
        
        # Get user's accessible locations and groups
        user_locations = request.user.get_accessible_locations()
        user_groups = request.user.get_accessible_groups()
        
        # Filter hosts based on user permissions
        hosts_queryset = Host.objects.filter(
            location__in=user_locations,
            group__in=user_groups
        )
        
        summary = get_dashboard_summary(hosts_queryset)
        
        return Response(summary)
        
    except Exception as e:
        return Response(
            {'error': f'Failed to fetch summary data: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def location_health(request):
    """
    Get location health overview.
    """
    try:
        if not MONITORING_MODELS_AVAILABLE:
            return Response([])
        
        # Get user's accessible locations and groups
        user_locations = request.user.get_accessible_locations()
        user_groups = request.user.get_accessible_groups()
        
        # Filter hosts based on user permissions
        hosts_queryset = Host.objects.filter(
            location__in=user_locations,
            group__in=user_groups
        )
        
        location_health_data = get_location_health(user_locations, hosts_queryset)
        
        return Response(location_health_data)
        
    except Exception as e:
        return Response(
            {'error': f'Failed to fetch location health data: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def recent_activity(request):
    """
    Get recent activity log entries.
    """
    try:
        limit = int(request.GET.get('limit', 50))
        limit = min(limit, 200)  # Cap at 200 entries
        
        if not MONITORING_MODELS_AVAILABLE:
            return Response([])
        
        # Get user's accessible locations and groups
        user_locations = request.user.get_accessible_locations()
        user_groups = request.user.get_accessible_groups()
        
        # Filter hosts based on user permissions
        hosts_queryset = Host.objects.filter(
            location__in=user_locations,
            group__in=user_groups
        )
        
        activity_data = get_recent_activity(hosts_queryset, limit=limit)
        
        return Response(activity_data)
        
    except Exception as e:
        return Response(
            {'error': f'Failed to fetch activity data: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


def get_empty_summary():
    """
    Return empty summary data when monitoring models are not available.
    """
    return {
        'total_hosts': 0,
        'up_hosts': 0,
        'down_hosts': 0,
        'warning_hosts': 0,
        'maintenance_hosts': 0,
        'unknown_hosts': 0,
    }


def get_dashboard_summary(hosts_queryset):
    """
    Calculate dashboard summary statistics.
    """
    # Get status counts
    status_counts = hosts_queryset.aggregate(
        total_hosts=Count('id'),
        up_hosts=Count(Case(When(status='UP', then=1), output_field=IntegerField())),
        down_hosts=Count(Case(When(status='DOWN', then=1), output_field=IntegerField())),
        warning_hosts=Count(Case(When(status='WARNING', then=1), output_field=IntegerField())),
        maintenance_hosts=Count(Case(When(status='MAINTENANCE', then=1), output_field=IntegerField())),
        unknown_hosts=Count(Case(When(status='UNKNOWN', then=1), output_field=IntegerField()))
    )
    
    return {
        'total_hosts': status_counts['total_hosts'] or 0,
        'up_hosts': status_counts['up_hosts'] or 0,
        'down_hosts': status_counts['down_hosts'] or 0,
        'warning_hosts': status_counts['warning_hosts'] or 0,
        'maintenance_hosts': status_counts['maintenance_hosts'] or 0,
        'unknown_hosts': status_counts['unknown_hosts'] or 0,
    }


def get_location_health(user_locations, hosts_queryset):
    """
    Calculate location health statistics.
    """
    location_health_data = []
    
    for location in user_locations:
        # Get hosts in this location
        location_hosts = hosts_queryset.filter(location=location)
        
        # Calculate status counts for this location
        status_counts = location_hosts.aggregate(
            total_hosts=Count('id'),
            up_hosts=Count(Case(When(status='UP', then=1), output_field=IntegerField())),
            down_hosts=Count(Case(When(status='DOWN', then=1), output_field=IntegerField())),
            warning_hosts=Count(Case(When(status='WARNING', then=1), output_field=IntegerField())),
            maintenance_hosts=Count(Case(When(status='MAINTENANCE', then=1), output_field=IntegerField()))
        )
        
        total_hosts = status_counts['total_hosts'] or 0
        up_hosts = status_counts['up_hosts'] or 0
        down_hosts = status_counts['down_hosts'] or 0
        warning_hosts = status_counts['warning_hosts'] or 0
        maintenance_hosts = status_counts['maintenance_hosts'] or 0
        
        # Calculate health percentage (UP hosts / (total - maintenance))
        operational_hosts = total_hosts - maintenance_hosts
        if operational_hosts > 0:
            health_percentage = round((up_hosts / operational_hosts) * 100, 1)
        else:
            health_percentage = 100.0 if total_hosts == maintenance_hosts else 0.0
        
        # Determine overall status
        if down_hosts > 0:
            if down_hosts >= operational_hosts * 0.5:  # 50% or more down
                overall_status = 'critical'
            else:
                overall_status = 'warning'
        elif warning_hosts > 0:
            overall_status = 'warning'
        else:
            overall_status = 'healthy'
        
        location_health_data.append({
            'id': location.id,
            'name': location.name,
            'total_hosts': total_hosts,
            'up_hosts': up_hosts,
            'down_hosts': down_hosts,
            'warning_hosts': warning_hosts,
            'maintenance_hosts': maintenance_hosts,
            'health_percentage': health_percentage,
            'status': overall_status
        })
    
    # Sort by health percentage (worst first)
    location_health_data.sort(key=lambda x: x['health_percentage'])
    
    return location_health_data


def get_recent_activity(hosts_queryset, limit=50):
    """
    Get recent activity log entries for accessible hosts.
    """
    if not MONITORING_MODELS_AVAILABLE:
        return []
    
    # Get host IDs for filtering
    host_ids = list(hosts_queryset.values_list('id', flat=True))
    
    # Get recent alerts
    try:
        recent_alerts = Alert.objects.filter(
            host_id__in=host_ids
        ).select_related('host').order_by('-timestamp')[:limit//2]
    except:
        recent_alerts = []
    
    # Get recent audit logs related to hosts
    recent_audit_logs = AuditLog.objects.filter(
        Q(resource_type='host') & Q(resource_id__in=[str(hid) for hid in host_ids])
    ).order_by('-timestamp')[:limit//2]
    
    activity_entries = []
    
    # Process alerts
    for alert in recent_alerts:
        activity_entries.append({
            'id': f'alert_{alert.id}',
            'timestamp': alert.timestamp.isoformat(),
            'host_name': alert.host.device_name,
            'host_ip': str(alert.host.ip_address),
            'event_type': 'alert',
            'message': alert.message,
            'severity': alert.severity.lower() if alert.severity else 'info',
            'user': None
        })
    
    # Process audit logs
    for log in recent_audit_logs:
        event_type = 'status_change'
        message = log.description
        old_status = None
        new_status = None
        
        # Try to extract status change information
        if 'status' in log.changes:
            old_status = log.changes['status'].get('old')
            new_status = log.changes['status'].get('new')
            message = f"Status changed from {old_status} to {new_status}"
        elif log.action == 'acknowledge':
            event_type = 'acknowledgment'
            message = f"Alert acknowledged: {log.changes.get('comment', 'No comment')}"
        elif 'maintenance' in log.action.lower():
            event_type = 'maintenance'
            message = log.description
        
        # Get host information
        try:
            host = Host.objects.get(id=log.resource_id)
            host_name = host.device_name
            host_ip = str(host.ip_address)
        except (Host.DoesNotExist, ValueError):
            host_name = log.resource_name or f"Host {log.resource_id}"
            host_ip = "Unknown"
        
        activity_entries.append({
            'id': f'audit_{log.id}',
            'timestamp': log.timestamp.isoformat(),
            'host_name': host_name,
            'host_ip': host_ip,
            'event_type': event_type,
            'old_status': old_status,
            'new_status': new_status,
            'message': message,
            'user': log.user.username if log.user else None,
            'severity': 'info'
        })
    
    # Sort all entries by timestamp (most recent first)
    activity_entries.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Return only the requested number of entries
    return activity_entries[:limit]