"""
Custom CSRF middleware that exempts API endpoints.
"""
import re
from django.middleware.csrf import CsrfViewMiddleware
from django.conf import settings


class APICSRFExemptMiddleware(CsrfViewMiddleware):
    """
    CSRF middleware that exempts API endpoints from CSRF protection.
    """
    
    def process_view(self, request, callback, callback_args, callback_kwargs):
        """
        Check if the request path should be exempt from CSRF protection.
        """
        # Get exempt URLs from settings
        exempt_urls = getattr(settings, 'CSRF_EXEMPT_URLS', [])
        
        # Check if current path matches any exempt pattern
        for pattern in exempt_urls:
            if re.match(pattern, request.path):
                return None  # Skip CSRF check
        
        # Use default CSRF processing for non-exempt URLs
        return super().process_view(request, callback, callback_args, callback_kwargs)