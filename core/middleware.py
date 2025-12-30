"""
Custom middleware for the Network Monitoring System.
"""

import json
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser
from .models import AuditLog


class AuditMiddleware(MiddlewareMixin):
    """
    Middleware to automatically log user actions for audit purposes.
    """
    
    def process_request(self, request):
        """Process incoming request."""
        # Store request start time for performance tracking
        import time
        request._audit_start_time = time.time()
        return None
    
    def process_response(self, request, response):
        """Process outgoing response and log audit trail."""
        # Skip audit logging for certain paths
        skip_paths = [
            '/metrics/',
            '/health/',
            '/static/',
            '/media/',
            '/admin/jsi18n/',
        ]
        
        if any(request.path.startswith(path) for path in skip_paths):
            return response
            
        # Skip GET requests to reduce noise (optional)
        if request.method == 'GET' and not request.path.startswith('/admin/'):
            return response
            
        # Only log for authenticated users
        if isinstance(request.user, AnonymousUser):
            return response
            
        try:
            # Determine action type based on method and path
            action = self._determine_action(request.method, request.path)
            
            if action:
                # Extract resource information
                resource_type, resource_id = self._extract_resource_info(request.path)
                
                # Create audit log entry
                AuditLog.objects.create(
                    user=request.user,
                    username=request.user.username,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    description=f"{action.title()} {resource_type}",
                    ip_address=self._get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    session_key=request.session.session_key or '',
                    success=200 <= response.status_code < 400,
                    error_message='' if 200 <= response.status_code < 400 else f"HTTP {response.status_code}"
                )
        except Exception as e:
            # Don't let audit logging break the application
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Audit logging failed: {e}")
            
        return response
    
    def _determine_action(self, method, path):
        """Determine the action type based on HTTP method and path."""
        if method == 'POST':
            return 'create'
        elif method in ['PUT', 'PATCH']:
            return 'update'
        elif method == 'DELETE':
            return 'delete'
        elif method == 'GET' and '/admin/' in path:
            return 'read'
        return None
    
    def _extract_resource_info(self, path):
        """Extract resource type and ID from the request path."""
        # Simple path parsing - can be enhanced based on URL patterns
        parts = [p for p in path.split('/') if p]
        
        if not parts:
            return 'unknown', ''
            
        if 'admin' in parts:
            # Django admin paths
            if len(parts) >= 3:
                return parts[2], parts[3] if len(parts) > 3 else ''
        elif 'api' in parts:
            # API paths
            if len(parts) >= 3:
                return parts[2], parts[3] if len(parts) > 3 else ''
                
        return parts[0] if parts else 'unknown', ''
    
    def _get_client_ip(self, request):
        """Get the client IP address from the request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip