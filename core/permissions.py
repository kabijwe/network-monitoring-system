"""
Custom permission classes for Role-Based Access Control (RBAC).
"""
from rest_framework import permissions
from .models import UserRole


class IsAuthenticated(permissions.BasePermission):
    """
    Custom authentication permission that also checks for active user roles.
    """
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.is_active
        )


class IsSuperAdmin(permissions.BasePermission):
    """
    Permission class for SuperAdmin role.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        return (
            request.user.is_superuser or
            UserRole.objects.filter(
                user=request.user,
                role__name='superadmin',
                is_active=True
            ).exists()
        )


class IsAdmin(permissions.BasePermission):
    """
    Permission class for Admin role and above.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        return (
            request.user.is_superuser or
            UserRole.objects.filter(
                user=request.user,
                role__name__in=['superadmin', 'admin'],
                is_active=True
            ).exists()
        )


class IsEditor(permissions.BasePermission):
    """
    Permission class for Editor role and above.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        return (
            request.user.is_superuser or
            UserRole.objects.filter(
                user=request.user,
                role__name__in=['superadmin', 'admin', 'editor'],
                is_active=True
            ).exists()
        )


class IsViewer(permissions.BasePermission):
    """
    Permission class for Viewer role and above (all authenticated users).
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        return (
            request.user.is_superuser or
            UserRole.objects.filter(
                user=request.user,
                role__name__in=['superadmin', 'admin', 'editor', 'viewer'],
                is_active=True
            ).exists()
        )


class HasLocationAccess(permissions.BasePermission):
    """
    Permission class that checks location-based access control.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # SuperAdmin has access to all locations
        if request.user.is_superuser:
            return True
        
        # Check if user has any active roles
        return UserRole.objects.filter(
            user=request.user,
            is_active=True
        ).exists()
    
    def has_object_permission(self, request, view, obj):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # SuperAdmin has access to all objects
        if request.user.is_superuser:
            return True
        
        # Get the location from the object (assuming it has a location field)
        obj_location = getattr(obj, 'location', None)
        
        if not obj_location:
            # If object has no location, check for general permissions
            return UserRole.objects.filter(
                user=request.user,
                is_active=True,
                location__isnull=True
            ).exists()
        
        # Check if user has access to this specific location
        return UserRole.objects.filter(
            user=request.user,
            is_active=True,
            location=obj_location
        ).exists()


class HasGroupAccess(permissions.BasePermission):
    """
    Permission class that checks group-based access control.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # SuperAdmin has access to all groups
        if request.user.is_superuser:
            return True
        
        # Check if user has any active roles
        return UserRole.objects.filter(
            user=request.user,
            is_active=True
        ).exists()
    
    def has_object_permission(self, request, view, obj):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # SuperAdmin has access to all objects
        if request.user.is_superuser:
            return True
        
        # Get the group from the object (assuming it has a group field)
        obj_group = getattr(obj, 'group', None)
        
        if not obj_group:
            # If object has no group, check for general permissions
            return UserRole.objects.filter(
                user=request.user,
                is_active=True,
                group__isnull=True
            ).exists()
        
        # Check if user has access to this specific group
        return UserRole.objects.filter(
            user=request.user,
            is_active=True,
            group=obj_group
        ).exists()


class CanManageUsers(permissions.BasePermission):
    """
    Permission class for user management operations.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Only SuperAdmin and Admin can manage users
        return (
            request.user.is_superuser or
            UserRole.objects.filter(
                user=request.user,
                role__name__in=['superadmin', 'admin'],
                is_active=True
            ).exists()
        )


class CanManageRoles(permissions.BasePermission):
    """
    Permission class for role management operations.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Only SuperAdmin can manage roles
        return (
            request.user.is_superuser or
            UserRole.objects.filter(
                user=request.user,
                role__name='superadmin',
                is_active=True
            ).exists()
        )


class CanAcknowledgeAlerts(permissions.BasePermission):
    """
    Permission class for alert acknowledgment operations.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Editor and above can acknowledge alerts
        return (
            request.user.is_superuser or
            UserRole.objects.filter(
                user=request.user,
                role__name__in=['superadmin', 'admin', 'editor'],
                is_active=True
            ).exists()
        )


class CanManageDevices(permissions.BasePermission):
    """
    Permission class for device management operations.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Check permission based on HTTP method
        if request.method in permissions.SAFE_METHODS:
            # Read operations - Viewer and above
            return UserRole.objects.filter(
                user=request.user,
                role__name__in=['superadmin', 'admin', 'editor', 'viewer'],
                is_active=True
            ).exists()
        else:
            # Write operations - Editor and above
            return (
                request.user.is_superuser or
                UserRole.objects.filter(
                    user=request.user,
                    role__name__in=['superadmin', 'admin', 'editor'],
                    is_active=True
                ).exists()
            )


class CanExportData(permissions.BasePermission):
    """
    Permission class for data export operations.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Editor and above can export data
        return (
            request.user.is_superuser or
            UserRole.objects.filter(
                user=request.user,
                role__name__in=['superadmin', 'admin', 'editor'],
                is_active=True
            ).exists()
        )


class RoleBasedPermission(permissions.BasePermission):
    """
    Generic role-based permission class that can be configured with required roles.
    """
    required_roles = []  # Override this in subclasses
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        if request.user.is_superuser:
            return True
        
        # Get required roles from view if available
        required_roles = getattr(view, 'required_roles', self.required_roles)
        
        if not required_roles:
            # If no specific roles required, just check for any active role
            return UserRole.objects.filter(
                user=request.user,
                is_active=True
            ).exists()
        
        return UserRole.objects.filter(
            user=request.user,
            role__name__in=required_roles,
            is_active=True
        ).exists()


def get_user_permissions(user):
    """
    Helper function to get all permissions for a user based on their roles.
    """
    if not user.is_authenticated:
        return set()
    
    if user.is_superuser:
        return {'*'}  # SuperUser has all permissions
    
    permissions = set()
    user_roles = UserRole.objects.filter(
        user=user,
        is_active=True
    ).select_related('role')
    
    for user_role in user_roles:
        role_permissions = user_role.role.permissions
        if isinstance(role_permissions, dict):
            permissions.update(role_permissions.keys())
        elif isinstance(role_permissions, list):
            permissions.update(role_permissions)
    
    return permissions


def has_permission(user, permission_name):
    """
    Helper function to check if a user has a specific permission.
    """
    user_permissions = get_user_permissions(user)
    return '*' in user_permissions or permission_name in user_permissions