"""
Views for core authentication and user management.
"""
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model, logout
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .serializers import (
    CustomTokenObtainPairSerializer,
    UserSerializer,
    RoleSerializer,
    UserRoleSerializer,
    ChangePasswordSerializer,
    ProfileSerializer,
    AuditLogSerializer
)
from .models import Role, UserRole, AuditLog
from .permissions import IsSuperAdmin, IsAdmin

User = get_user_model()


@method_decorator(csrf_exempt, name='dispatch')
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom JWT token view with enhanced user information and audit logging.
    """
    serializer_class = CustomTokenObtainPairSerializer


class LogoutView(APIView):
    """
    Logout view that blacklists the refresh token and logs the action.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            # Get refresh token from request
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            # Log logout action
            session_key = 'api-request'  # Default for API requests
            if hasattr(request, 'session') and request.session.session_key:
                session_key = request.session.session_key
                
            AuditLog.objects.create(
                user=request.user,
                username=request.user.username,
                action='logout',
                resource_type='Authentication',
                resource_id=str(request.user.id),
                resource_name=request.user.username,
                description=f'User {request.user.username} logged out',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_key=session_key,
                success=True
            )
            
            # Update last login IP
            request.user.last_login_ip = self._get_client_ip(request)
            request.user.save(update_fields=['last_login_ip'])
            
            return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
        
        except Exception as e:
            # Log failed logout attempt
            session_key = 'api-request'  # Default for API requests
            if hasattr(request, 'session') and request.session.session_key:
                session_key = request.session.session_key
                
            AuditLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                username=request.user.username if request.user.is_authenticated else 'anonymous',
                action='logout',
                resource_type='Authentication',
                resource_id=str(request.user.id) if request.user.is_authenticated else '',
                resource_name=request.user.username if request.user.is_authenticated else 'anonymous',
                description=f'Failed logout attempt: {str(e)}',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_key=session_key,
                success=False,
                error_message=str(e)
            )
            return Response({'error': 'Logout failed'}, status=status.HTTP_400_BAD_REQUEST)
    
    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class ProfileView(generics.RetrieveUpdateAPIView):
    """
    View for retrieving and updating user profile.
    """
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        return self.request.user
    
    def perform_update(self, serializer):
        """Log profile updates."""
        old_data = ProfileSerializer(self.get_object()).data
        serializer.save()
        new_data = serializer.data
        
        # Log profile update
        changes = {}
        for field in ['email', 'first_name', 'last_name', 'phone', 'department', 'timezone']:
            if old_data.get(field) != new_data.get(field):
                changes[field] = {
                    'old': old_data.get(field),
                    'new': new_data.get(field)
                }
        
        if changes:
            session_key = 'api-request'  # Default for API requests
            if hasattr(self.request, 'session') and self.request.session.session_key:
                session_key = self.request.session.session_key
                
            AuditLog.objects.create(
                user=self.request.user,
                username=self.request.user.username,
                action='update',
                resource_type='UserProfile',
                resource_id=str(self.request.user.id),
                resource_name=self.request.user.username,
                description=f'User {self.request.user.username} updated profile',
                changes=changes,
                ip_address=self._get_client_ip(self.request),
                user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
                session_key=session_key,
                success=True
            )
    
    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class ChangePasswordView(APIView):
    """
    View for changing user password.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            # Change password
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            # Log password change
            session_key = 'api-request'  # Default for API requests
            if hasattr(request, 'session') and request.session.session_key:
                session_key = request.session.session_key
                
            AuditLog.objects.create(
                user=user,
                username=user.username,
                action='update',
                resource_type='UserPassword',
                resource_id=str(user.id),
                resource_name=user.username,
                description=f'User {user.username} changed password',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_key=session_key,
                success=True
            )
            
            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def user_info(request):
    """
    Get current user information including roles and permissions.
    """
    user = request.user
    
    # Get user roles
    user_roles = UserRole.objects.filter(
        user=user, 
        is_active=True
    ).select_related('role', 'location', 'group')
    
    # Compile permissions from all roles
    all_permissions = set()
    roles_data = []
    
    for user_role in user_roles:
        role_permissions = user_role.role.permissions
        if isinstance(role_permissions, dict):
            all_permissions.update(role_permissions.keys())
        
        roles_data.append({
            'role': user_role.role.name,
            'display_name': user_role.role.display_name,
            'location': user_role.location.name if user_role.location else None,
            'group': user_role.group.name if user_role.group else None,
            'permissions': role_permissions
        })
    
    return Response({
        'user': {
            'id': str(user.id),
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone': user.phone,
            'department': user.department,
            'employee_id': user.employee_id,
            'timezone': user.timezone,
            'mfa_enabled': user.mfa_enabled,
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser,
            'last_login': user.last_login,
            'created_at': user.created_at,
        },
        'roles': roles_data,
        'permissions': list(all_permissions),
        'has_admin_access': user.is_superuser or any(
            role.role.name in ['superadmin', 'admin'] for role in user_roles
        ),
        'can_edit': user.is_superuser or any(
            role.role.name in ['superadmin', 'admin', 'editor'] for role in user_roles
        ),
    })


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def check_username(request):
    """
    Check if username is available.
    """
    username = request.data.get('username', '').strip()
    
    if not username:
        return Response({'error': 'Username is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    exists = User.objects.filter(username=username).exists()
    
    return Response({
        'username': username,
        'available': not exists,
        'message': 'Username is available' if not exists else 'Username is already taken'
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def system_status(request):
    """
    Get system status information for authenticated users.
    """
    from django.db import connection
    from django.core.cache import cache
    import redis
    
    status_data = {
        'timestamp': timezone.now(),
        'user': request.user.username,
        'database': 'connected',
        'cache': 'connected',
        'services': {}
    }
    
    # Check database connection
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception as e:
        status_data['database'] = f'error: {str(e)}'
    
    # Check Redis cache
    try:
        cache.set('health_check', 'ok', 30)
        if cache.get('health_check') != 'ok':
            status_data['cache'] = 'error: cache test failed'
    except Exception as e:
        status_data['cache'] = f'error: {str(e)}'
    
    # Check Celery (if available)
    try:
        from celery import current_app
        inspect = current_app.control.inspect()
        stats = inspect.stats()
        if stats:
            status_data['services']['celery'] = 'connected'
        else:
            status_data['services']['celery'] = 'no workers'
    except Exception as e:
        status_data['services']['celery'] = f'error: {str(e)}'
    
    return Response(status_data)


class AuditLogListView(generics.ListAPIView):
    """
    View for listing audit logs with filtering and pagination.
    """
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdmin]  # Only admins can view audit logs
    
    def get_queryset(self):
        """Get filtered audit logs."""
        queryset = AuditLog.objects.all().select_related('user')
        
        # Filter by user
        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        username = self.request.query_params.get('username')
        if username:
            queryset = queryset.filter(username__icontains=username)
        
        # Filter by action
        action = self.request.query_params.get('action')
        if action:
            queryset = queryset.filter(action=action)
        
        # Filter by resource type
        resource_type = self.request.query_params.get('resource_type')
        if resource_type:
            queryset = queryset.filter(resource_type__icontains=resource_type)
        
        # Filter by success status
        success = self.request.query_params.get('success')
        if success is not None:
            queryset = queryset.filter(success=success.lower() == 'true')
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        if start_date:
            try:
                from datetime import datetime
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                queryset = queryset.filter(timestamp__gte=start_dt)
            except ValueError:
                pass
        
        end_date = self.request.query_params.get('end_date')
        if end_date:
            try:
                from datetime import datetime
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                queryset = queryset.filter(timestamp__lte=end_dt)
            except ValueError:
                pass
        
        # Filter by IP address
        ip_address = self.request.query_params.get('ip_address')
        if ip_address:
            queryset = queryset.filter(ip_address=ip_address)
        
        return queryset.order_by('-timestamp')


class AuditLogDetailView(generics.RetrieveAPIView):
    """
    View for retrieving a specific audit log entry.
    """
    queryset = AuditLog.objects.all().select_related('user')
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdmin]


@api_view(['GET'])
@permission_classes([IsAdmin])
def audit_log_stats(request):
    """
    Get audit log statistics.
    """
    from django.db.models import Count, Q
    from datetime import datetime, timedelta
    
    # Get date range (default to last 30 days)
    end_date = timezone.now()
    start_date = end_date - timedelta(days=30)
    
    start_param = request.query_params.get('start_date')
    if start_param:
        try:
            start_date = datetime.fromisoformat(start_param.replace('Z', '+00:00'))
        except ValueError:
            pass
    
    end_param = request.query_params.get('end_date')
    if end_param:
        try:
            end_date = datetime.fromisoformat(end_param.replace('Z', '+00:00'))
        except ValueError:
            pass
    
    # Base queryset for the date range
    base_qs = AuditLog.objects.filter(
        timestamp__gte=start_date,
        timestamp__lte=end_date
    )
    
    # Action statistics
    action_stats = base_qs.values('action').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Resource type statistics
    resource_stats = base_qs.values('resource_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # User activity statistics
    user_stats = base_qs.values('username').annotate(
        count=Count('id')
    ).order_by('-count')[:10]  # Top 10 most active users
    
    # Success/failure statistics
    success_stats = base_qs.aggregate(
        total=Count('id'),
        successful=Count('id', filter=Q(success=True)),
        failed=Count('id', filter=Q(success=False))
    )
    
    # Daily activity (last 30 days)
    daily_stats = []
    current_date = start_date.date()
    while current_date <= end_date.date():
        day_count = base_qs.filter(
            timestamp__date=current_date
        ).count()
        daily_stats.append({
            'date': current_date.isoformat(),
            'count': day_count
        })
        current_date += timedelta(days=1)
    
    return Response({
        'date_range': {
            'start': start_date.isoformat(),
            'end': end_date.isoformat()
        },
        'actions': list(action_stats),
        'resource_types': list(resource_stats),
        'top_users': list(user_stats),
        'success_rate': {
            'total': success_stats['total'],
            'successful': success_stats['successful'],
            'failed': success_stats['failed'],
            'success_percentage': (
                success_stats['successful'] / success_stats['total'] * 100
                if success_stats['total'] > 0 else 0
            )
        },
        'daily_activity': daily_stats
    })