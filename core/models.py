"""
Core models for Network Monitoring System.

This module contains the fundamental models for user management,
authentication, authorization, and audit logging.
"""

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import uuid


class User(AbstractUser):
    """
    Extended user model with ISP-specific fields and enhanced functionality.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, blank=True)
    department = models.CharField(max_length=100, blank=True)
    employee_id = models.CharField(max_length=50, blank=True)
    
    # MFA settings
    mfa_enabled = models.BooleanField(default=False)
    
    # Profile information
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    timezone = models.CharField(max_length=50, default='UTC')
    
    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    class Meta:
        db_table = 'core_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return f"{self.username} ({self.get_full_name() or self.email})"

    @property
    def full_name(self):
        return self.get_full_name() or self.username


class Role(models.Model):
    """
    Role model for RBAC implementation.
    """
    ROLE_CHOICES = [
        ('superadmin', 'SuperAdmin'),
        ('admin', 'Admin'),
        ('editor', 'Editor'),
        ('viewer', 'Viewer'),
    ]
    
    name = models.CharField(max_length=50, choices=ROLE_CHOICES, unique=True)
    display_name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    permissions = models.JSONField(default=dict)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'core_role'
        verbose_name = 'Role'
        verbose_name_plural = 'Roles'

    def __str__(self):
        return self.display_name


class UserRole(models.Model):
    """
    User-Role assignment with location and group scoping.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_assignments')
    
    # Scope limitations
    location = models.ForeignKey(
        'monitoring.Location', 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True,
        related_name='user_roles'
    )
    group = models.ForeignKey(
        'monitoring.DeviceGroup', 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True,
        related_name='user_roles'
    )
    
    # Metadata
    assigned_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='role_assignments_made'
    )
    assigned_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'core_user_role'
        verbose_name = 'User Role Assignment'
        verbose_name_plural = 'User Role Assignments'
        unique_together = ['user', 'role', 'location', 'group']

    def __str__(self):
        scope = ""
        if self.location:
            scope += f" @ {self.location.name}"
        if self.group:
            scope += f" / {self.group.name}"
        return f"{self.user.username} - {self.role.display_name}{scope}"


class AuditLog(models.Model):
    """
    Comprehensive audit logging for all user actions.
    """
    ACTION_CHOICES = [
        ('create', 'Create'),
        ('read', 'Read'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('acknowledge', 'Acknowledge'),
        ('maintenance', 'Maintenance'),
        ('export', 'Export'),
        ('import', 'Import'),
        ('config_change', 'Configuration Change'),
    ]
    
    # Who performed the action
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    username = models.CharField(max_length=150)  # Store username in case user is deleted
    
    # What action was performed
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    resource_type = models.CharField(max_length=50)  # Model name or resource type
    resource_id = models.CharField(max_length=100, blank=True)  # Object ID
    resource_name = models.CharField(max_length=255, blank=True)  # Human-readable name
    
    # Action details
    description = models.TextField()
    changes = models.JSONField(default=dict, blank=True)  # Before/after values
    metadata = models.JSONField(default=dict, blank=True)  # Additional context
    
    # Request context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    session_key = models.CharField(max_length=40, blank=True)
    
    # Timing
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Status
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)

    class Meta:
        db_table = 'core_audit_log'
        verbose_name = 'Audit Log Entry'
        verbose_name_plural = 'Audit Log Entries'
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['timestamp']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.username} - {self.action} {self.resource_type} at {self.timestamp}"


class SystemConfiguration(models.Model):
    """
    System-wide configuration settings.
    """
    key = models.CharField(max_length=100, unique=True)
    value = models.JSONField()
    description = models.TextField(blank=True)
    category = models.CharField(max_length=50, default='general')
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        db_table = 'core_system_configuration'
        verbose_name = 'System Configuration'
        verbose_name_plural = 'System Configurations'

    def __str__(self):
        return f"{self.key}: {self.value}"