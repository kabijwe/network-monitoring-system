"""
URL configuration for monitoring app.
"""
from django.urls import path
from . import views

app_name = 'monitoring'

urlpatterns = [
    # Location endpoints
    path('locations/', views.LocationListCreateView.as_view(), name='location-list'),
    path('locations/<uuid:pk>/', views.LocationDetailView.as_view(), name='location-detail'),
    
    # Device Group endpoints
    path('groups/', views.DeviceGroupListCreateView.as_view(), name='group-list'),
    path('groups/<uuid:pk>/', views.DeviceGroupDetailView.as_view(), name='group-detail'),
    
    # Host endpoints
    path('hosts/', views.HostListCreateView.as_view(), name='host-list'),
    path('hosts/<uuid:pk>/', views.HostDetailView.as_view(), name='host-detail'),
    
    # Bulk operations
    path('hosts/bulk-upload/', views.BulkHostUploadView.as_view(), name='host-bulk-upload'),
    path('hosts/validate-excel/', views.validate_excel_file, name='validate-excel'),
    path('export/', views.BulkExportView.as_view(), name='bulk-export'),
    
    # Ping Monitoring
    path('hosts/<uuid:host_id>/ping/', views.PingHostView.as_view(), name='ping-host'),
    path('ping/multiple/', views.PingMultipleHostsView.as_view(), name='ping-multiple'),
    path('ping/all/', views.PingAllHostsView.as_view(), name='ping-all'),
    path('hosts/<uuid:host_id>/ping-results/', views.HostPingResultsView.as_view(), name='host-ping-results'),
    path('hosts/<uuid:host_id>/ping-summary/', views.HostPingSummaryView.as_view(), name='host-ping-summary'),
    
    # Monitoring data
    path('metrics/', views.MonitoringMetricListView.as_view(), name='metric-list'),
    path('alerts/', views.AlertListView.as_view(), name='alert-list'),
    
    # Dashboard
    path('dashboard/stats/', views.dashboard_stats, name='dashboard-stats'),
    
    # Notification management
    path('notification-profiles/', views.NotificationProfileListCreateView.as_view(), name='notification-profile-list'),
    path('notification-profiles/<uuid:pk>/', views.NotificationProfileDetailView.as_view(), name='notification-profile-detail'),
    path('notification-logs/', views.NotificationLogListView.as_view(), name='notification-log-list'),
    path('escalation-rules/', views.EscalationRuleListCreateView.as_view(), name='escalation-rule-list'),
    path('escalation-rules/<uuid:pk>/', views.EscalationRuleDetailView.as_view(), name='escalation-rule-detail'),
    path('notifications/test-channel/', views.test_notification_channel, name='test-notification-channel'),
    path('notifications/channel-status/', views.notification_channel_status, name='notification-channel-status'),
    path('notifications/test-alert/', views.send_test_alert_notification, name='test-alert-notification'),
    path('notifications/statistics/', views.notification_statistics, name='notification-statistics'),
]