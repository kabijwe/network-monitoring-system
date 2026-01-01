"""
URL configuration for MFA (Multi-Factor Authentication) endpoints.
"""

from django.urls import path
from . import mfa

app_name = 'mfa'

urlpatterns = [
    # MFA Status and Management
    path('status/', mfa.mfa_status, name='mfa_status'),
    path('setup/', mfa.setup_mfa, name='setup_mfa'),
    path('verify-setup/', mfa.verify_mfa_setup, name='verify_mfa_setup'),
    path('disable/', mfa.disable_mfa, name='disable_mfa'),
    
    # MFA Token Verification
    path('verify-token/', mfa.verify_mfa_token, name='verify_mfa_token'),
    
    # Backup Codes
    path('backup-codes/regenerate/', mfa.regenerate_backup_codes, name='regenerate_backup_codes'),
]