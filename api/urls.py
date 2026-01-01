"""
URL configuration for main API endpoints.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import dashboard_views

app_name = 'api'

# Create router for ViewSets
router = DefaultRouter()

# ViewSets will be registered here as they are created
# router.register(r'hosts', HostViewSet)
# router.register(r'alerts', AlertViewSet)

urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),
    
    # Dashboard endpoints
    path('dashboard/', dashboard_views.dashboard_overview, name='dashboard_overview'),
    path('dashboard/summary/', dashboard_views.dashboard_summary, name='dashboard_summary'),
    path('dashboard/locations/', dashboard_views.location_health, name='location_health'),
    path('dashboard/activity/', dashboard_views.recent_activity, name='recent_activity'),
    
    # Additional API endpoints will be added here
]