"""
URL configuration for main API endpoints.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter

app_name = 'api'

# Create router for ViewSets
router = DefaultRouter()

# ViewSets will be registered here as they are created
# router.register(r'hosts', HostViewSet)
# router.register(r'alerts', AlertViewSet)

urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),
    
    # Additional API endpoints will be added here
]