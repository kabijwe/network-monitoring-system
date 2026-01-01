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
    Custom JWT token serializer that includes user information, MFA support, and audit logging.
    """
    mfa_token = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, attrs):
        # Get the request from context
        request = self.context.get('request')
        
        # First, authenticate with username/password
        username = attrs.get('username')
        password = attrs.get('password')
        mfa_token = attrs.get('mfa_token', '')
        
        if username is None or password is None:
            raise serializers.ValidationError('Must include username and password.')
        
        # Authenticate user
        user = authenticate(request=request, username=username, password=password)
        
        if user is None:
            # Log failed login attempt
            if request:
                session_key = 'api-request'
                if hasattr(request, 'session') and request.session.session_key:
                    session_key = request.session.session_key
                
                AuditLog.objects.create(
                    user=None,
                    username=username,
                    action='login',
                    resource_type='Authentication',
                    resource_id='',
                    resource_name=username,
                    description=f'Failed login attempt for username: {username}',
                    ip_address=self._get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    session_key=session_key,
                    success=False,
                    error_message='Invalid credentials'
                )
            
            raise serializers.ValidationError('Invalid credentials.')
        
        if not user.is_active:
            raise serializers.ValidationError('User account is disabled.')
        
        # Check if MFA is enabled for this user
        from .mfa import MFAService
        if MFAService.is_mfa_enabled(user):
            if not mfa_token:
                # Return special response indicating MFA is required
                raise serializers.ValidationError({
                    'mfa_required': True,
                    'message': 'MFA token is required for this user.'
                })
            
            # Verify MFA token
            from django_otp.plugins.otp_totp.models import TOTPDevice
            device = user.totpdevice_set.filter(confirmed=True).first()
            
            if not device or not device.verify_token(mfa_token):
                # Log failed MFA attempt
                if request:
                    session_key = 'api-request'
                    if hasattr(request, 'session') and request.session.session_key:
                        session_key = request.session.session_key
                    
                    AuditLog.objects.create(
                        user=user,
                        username=user.username,
                        action='login',
                        resource_type='Authentication',
                        resource_id=str(user.id),
                        resource_name=user.username,
                        description=f'Failed MFA verification for user: {user.username}',
                        ip_address=self._get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        session_key=session_key,
                        success=False,
                        error_message='Invalid MFA token'
                    )
                
                raise serializers.ValidationError('Invalid MFA token.')
        
        # Set user for token generation
        self.user = user
        
        # Generate tokens
        refresh = self.get_token(user)
        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
        
        # Add user information to the response
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
                description=f'User {user.username} logged in successfully' + (' with MFA' if MFAService.is_mfa_enabled(user) else ''),
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_key=session_key,
                success=True
            )
            
            # Update last login IP
            user.last_login_ip = self._get_client_ip(request)
            user.save(update_fields=['last_login_ip'])
        
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