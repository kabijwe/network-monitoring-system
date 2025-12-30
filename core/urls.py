"""
URL configuration for core authentication and user management.
"""
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView,
)
from .views import (
    CustomTokenObtainPairView,
    LogoutView,
    ProfileView,
    ChangePasswordView,
    AuditLogListView,
    AuditLogDetailView,
    user_info,
    check_username,
    system_status,
    audit_log_stats,
)

app_name = 'core'

urlpatterns = [
    # JWT Authentication
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # User management
    path('profile/', ProfileView.as_view(), name='profile'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('user-info/', user_info, name='user_info'),
    path('check-username/', check_username, name='check_username'),
    
    # System status
    path('status/', system_status, name='system_status'),
    
    # Audit logs
    path('audit-logs/', AuditLogListView.as_view(), name='audit_logs'),
    path('audit-logs/<int:pk>/', AuditLogDetailView.as_view(), name='audit_log_detail'),
    path('audit-logs/stats/', audit_log_stats, name='audit_log_stats'),
]