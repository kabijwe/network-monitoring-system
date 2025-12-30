"""
URL configuration for Network Monitoring System (NMS).

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),
    
    # API endpoints
    path('api/v1/', include('api.urls')),
    
    # Authentication endpoints
    path('api/auth/', include('core.urls')),
    
    # Monitoring endpoints
    path('api/monitoring/', include('monitoring.urls')),
    
    # Prometheus metrics
    path('metrics/', include('django_prometheus.urls')),
    
    # Frontend (React app will be served here)
    path('', include('frontend.urls')),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Admin site customization
admin.site.site_header = "Network Monitoring System"
admin.site.site_title = "NMS Admin"
admin.site.index_title = "Welcome to NMS Administration"