"""
Serializers for core authentication and user management.
"""
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import Role, UserRole, AuditLog

User = get_user_model()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT token serializer that includes user information and audit logging.
    """
    
    def validate(self, attrs):
        # Get the request from context
        request = self.context.get('request')
        
        # Perform authentication
        data = super().validate(attrs)
        
        # Add user information to the response
        user = self.user
        data.update({
            'user': {
                'id': str(user.id),
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name,
                'department': user.department,
                'mfa_enabled': user.mfa_enabled,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser,
            },
            'roles': [
                {
                    'role': user_role.role.name,
                    'display_name': user_role.role.display_name,
                    'location': user_role.location.name if user_role.location else None,
                    'group': user_role.group.name if user_role.group else None,
                }
                for user_role in user.user_roles.filter(is_active=True).select_related('role', 'location', 'group')
            ]
        })
        
        # Log successful login
        if request:
            session_key = 'api-request'  # Default for API requests
            if hasattr(request, 'session') and request.session.session_key:
                session_key = request.session.session_key
            
            AuditLog.objects.create(
                user=user,
                username=user.username,
                action='login',
                resource_type='Authentication',
                resource_id=str(user.id),
                resource_name=user.username,
                description=f'User {user.username} logged in successfully',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_key=session_key,
                success=True
            )
        
        return data
    
    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model with ISP-specific fields.
    """
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    roles = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'phone', 'department', 'employee_id', 'mfa_enabled',
            'timezone', 'is_active', 'is_staff', 'password', 'password_confirm',
            'roles', 'created_at', 'updated_at', 'last_login'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'last_login']
    
    def get_roles(self, obj):
        """Get user roles with location and group information."""
        return [
            {
                'role': user_role.role.name,
                'display_name': user_role.role.display_name,
                'location': user_role.location.name if user_role.location else None,
                'group': user_role.group.name if user_role.group else None,
                'assigned_at': user_role.assigned_at,
                'is_active': user_role.is_active,
            }
            for user_role in obj.user_roles.filter(is_active=True).select_related('role', 'location', 'group')
        ]
    
    def validate(self, attrs):
        """Validate password confirmation."""
        if 'password' in attrs and 'password_confirm' in attrs:
            if attrs['password'] != attrs['password_confirm']:
                raise serializers.ValidationError("Passwords don't match")
        return attrs
    
    def create(self, validated_data):
        """Create user with proper password hashing."""
        validated_data.pop('password_confirm', None)
        password = validated_data.pop('password')
        user = User.objects.create_user(password=password, **validated_data)
        return user
    
    def update(self, instance, validated_data):
        """Update user with optional password change."""
        validated_data.pop('password_confirm', None)
        password = validated_data.pop('password', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        if password:
            instance.set_password(password)
        
        instance.save()
        return instance


class RoleSerializer(serializers.ModelSerializer):
    """
    Serializer for Role model.
    """
    user_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Role
        fields = [
            'name', 'display_name', 'description', 'permissions',
            'user_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']
    
    def get_user_count(self, obj):
        """Get count of users assigned to this role."""
        return obj.user_assignments.filter(is_active=True).count()


class UserRoleSerializer(serializers.ModelSerializer):
    """
    Serializer for UserRole assignments.
    """
    user_username = serializers.CharField(source='user.username', read_only=True)
    role_display_name = serializers.CharField(source='role.display_name', read_only=True)
    location_name = serializers.CharField(source='location.name', read_only=True)
    group_name = serializers.CharField(source='group.name', read_only=True)
    assigned_by_username = serializers.CharField(source='assigned_by.username', read_only=True)
    
    class Meta:
        model = UserRole
        fields = [
            'id', 'user', 'user_username', 'role', 'role_display_name',
            'location', 'location_name', 'group', 'group_name',
            'assigned_by', 'assigned_by_username', 'assigned_at', 'is_active'
        ]
        read_only_fields = ['id', 'assigned_by', 'assigned_at']


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change functionality.
    """
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(required=True)
    
    def validate(self, attrs):
        """Validate password change request."""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        return attrs
    
    def validate_current_password(self, value):
        """Validate current password."""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect")
        return value


class AuditLogSerializer(serializers.ModelSerializer):
    """
    Serializer for AuditLog model.
    """
    user_username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'user', 'user_username', 'username', 'action', 
            'resource_type', 'resource_id', 'resource_name',
            'description', 'changes', 'metadata', 'ip_address',
            'user_agent', 'session_key', 'timestamp', 'success',
            'error_message'
        ]
        read_only_fields = ['id', 'timestamp']


class ProfileSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'phone', 'department', 'employee_id', 'timezone',
            'mfa_enabled', 'roles', 'last_login'
        ]
        read_only_fields = ['id', 'username', 'last_login', 'roles']
    
    def get_roles(self, obj):
        """Get user roles with location and group information."""
        return [
            {
                'role': user_role.role.name,
                'display_name': user_role.role.display_name,
                'location': user_role.location.name if user_role.location else None,
                'group': user_role.group.name if user_role.group else None,
            }
            for user_role in obj.user_roles.filter(is_active=True).select_related('role', 'location', 'group')
        ]