"""
Multi-Factor Authentication (MFA) implementation for Network Monitoring System.

This module provides TOTP (Time-based One-Time Password) authentication
using django-otp for enhanced security.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django_otp.models import Device
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64
import json

User = get_user_model()


class MFAService:
    """Service class for MFA operations."""
    
    @staticmethod
    def is_mfa_enabled(user):
        """Check if MFA is enabled for a user."""
        return user.mfa_enabled and user.totpdevice_set.filter(confirmed=True).exists()
    
    @staticmethod
    def get_or_create_totp_device(user):
        """Get or create a TOTP device for the user."""
        device = TOTPDevice.objects.filter(user=user, confirmed=False).first()
        if not device:
            device = TOTPDevice.objects.create(
                user=user,
                name=f"{user.username}-totp",
                confirmed=False
            )
        return device
    
    @staticmethod
    def generate_qr_code(device):
        """Generate QR code for TOTP device setup."""
        qr_url = device.config_url
        
        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_url)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    @staticmethod
    def verify_token(device, token):
        """Verify TOTP token."""
        return device.verify_token(token)
    
    @staticmethod
    def enable_mfa(user, token):
        """Enable MFA for a user after token verification."""
        device = TOTPDevice.objects.filter(user=user, confirmed=False).first()
        if not device:
            return False, "No pending MFA setup found"
        
        if device.verify_token(token):
            device.confirmed = True
            device.save()
            user.mfa_enabled = True
            user.save()
            return True, "MFA enabled successfully"
        else:
            return False, "Invalid token"
    
    @staticmethod
    def disable_mfa(user):
        """Disable MFA for a user."""
        # Remove all TOTP devices
        TOTPDevice.objects.filter(user=user).delete()
        user.mfa_enabled = False
        user.save()
        return True, "MFA disabled successfully"
    
    @staticmethod
    def generate_backup_codes(user, count=10):
        """Generate backup codes for MFA recovery."""
        # This is a simplified implementation
        # In production, you might want to use a more secure method
        codes = [random_hex(8) for _ in range(count)]
        
        # Store backup codes (you might want to hash these)
        from core.models import SystemConfiguration
        SystemConfiguration.objects.update_or_create(
            key=f'mfa_backup_codes_{user.id}',
            defaults={
                'value': codes,
                'description': f'MFA backup codes for {user.username}',
                'category': 'mfa',
                'updated_by': user
            }
        )
        
        return codes


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mfa_status(request):
    """Get MFA status for the current user."""
    user = request.user
    is_enabled = MFAService.is_mfa_enabled(user)
    
    return Response({
        'mfa_enabled': is_enabled,
        'has_backup_codes': False,  # Implement backup codes check if needed
        'devices': [
            {
                'id': device.id,
                'name': device.name,
                'confirmed': device.confirmed,
                'created_at': device.created_at
            }
            for device in user.totpdevice_set.all()
        ]
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def setup_mfa(request):
    """Setup MFA for the current user."""
    user = request.user
    
    # Check if MFA is already enabled
    if MFAService.is_mfa_enabled(user):
        return Response(
            {'error': 'MFA is already enabled'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Get or create TOTP device
    device = MFAService.get_or_create_totp_device(user)
    
    # Generate QR code
    qr_code = MFAService.generate_qr_code(device)
    
    return Response({
        'qr_code': qr_code,
        'secret_key': device.key,
        'device_id': device.id,
        'manual_entry_key': device.key,
        'issuer': 'Network Monitoring System',
        'account_name': user.username
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_mfa_setup(request):
    """Verify MFA setup with TOTP token."""
    user = request.user
    token = request.data.get('token')
    
    if not token:
        return Response(
            {'error': 'Token is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    success, message = MFAService.enable_mfa(user, token)
    
    if success:
        # Generate backup codes
        backup_codes = MFAService.generate_backup_codes(user)
        
        return Response({
            'success': True,
            'message': message,
            'backup_codes': backup_codes
        })
    else:
        return Response(
            {'error': message},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def disable_mfa(request):
    """Disable MFA for the current user."""
    user = request.user
    password = request.data.get('password')
    
    # Verify password for security
    if not user.check_password(password):
        return Response(
            {'error': 'Invalid password'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    success, message = MFAService.disable_mfa(user)
    
    return Response({
        'success': success,
        'message': message
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_mfa_token(request):
    """Verify MFA token for authentication."""
    user = request.user
    token = request.data.get('token')
    
    if not token:
        return Response(
            {'error': 'Token is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Check if user has MFA enabled
    if not MFAService.is_mfa_enabled(user):
        return Response(
            {'error': 'MFA is not enabled for this user'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Get confirmed TOTP device
    device = user.totpdevice_set.filter(confirmed=True).first()
    if not device:
        return Response(
            {'error': 'No MFA device found'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Verify token
    if MFAService.verify_token(device, token):
        return Response({
            'success': True,
            'message': 'Token verified successfully'
        })
    else:
        return Response(
            {'error': 'Invalid token'},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def regenerate_backup_codes(request):
    """Regenerate backup codes for MFA recovery."""
    user = request.user
    password = request.data.get('password')
    
    # Verify password for security
    if not user.check_password(password):
        return Response(
            {'error': 'Invalid password'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Check if MFA is enabled
    if not MFAService.is_mfa_enabled(user):
        return Response(
            {'error': 'MFA is not enabled'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Generate new backup codes
    backup_codes = MFAService.generate_backup_codes(user)
    
    return Response({
        'success': True,
        'backup_codes': backup_codes,
        'message': 'Backup codes regenerated successfully'
    })