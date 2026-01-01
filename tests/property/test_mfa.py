"""
Property-based tests for MFA (Multi-Factor Authentication) functionality.

These tests validate the MFA system using property-based testing
with Hypothesis to ensure correctness across a wide range of inputs.
"""
import pytest
import django
from django.conf import settings
from django.test import TestCase, override_settings, TransactionTestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from hypothesis import given, strategies as st, settings as hypothesis_settings, assume
from hypothesis.extra.django import TestCase as HypothesisTestCase
from rest_framework.test import APIClient
from rest_framework import status
import uuid
from unittest.mock import patch, MagicMock

# Configure Django settings if not already configured
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nms.settings')

from core.models import Role, UserRole, AuditLog
from core.mfa import MFAService
from django_otp.plugins.otp_totp.models import TOTPDevice

User = get_user_model()


# Custom strategies for generating test data
@st.composite
def username_strategy(draw):
    """Generate valid usernames."""
    return draw(st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd')),
        min_size=3,
        max_size=20
    ).filter(lambda x: x.strip() and x.isalnum()))


@st.composite
def password_strategy(draw):
    """Generate valid passwords."""
    return draw(st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd', 'Po')),
        min_size=8,
        max_size=30
    ).filter(lambda x: len(x.strip()) >= 8))


@st.composite
def totp_token_strategy(draw):
    """Generate TOTP token strings."""
    return draw(st.text(
        alphabet='0123456789',
        min_size=6,
        max_size=6
    ))


class MFAPropertyTests(HypothesisTestCase):
    """Property-based tests for MFA functionality."""
    
    def setUp(self):
        """Set up test data."""
        # Create unique test user for each test
        unique_id = str(uuid.uuid4())[:8]
        self.user = User.objects.create_user(
            username=f'testuser_{unique_id}',
            email=f'test_{unique_id}@example.com',
            password='testpass123'
        )
        
        # Create test client
        self.client = APIClient()
    
    @given(
        usernames=st.lists(username_strategy(), min_size=1, max_size=2, unique=True),
        passwords=st.lists(password_strategy(), min_size=1, max_size=2),
        mfa_enabled_flags=st.lists(st.booleans(), min_size=1, max_size=2)
    )
    @hypothesis_settings(max_examples=2, deadline=4000)
    def test_mfa_enforcement_property(self, usernames, passwords, mfa_enabled_flags):
        """
        Property 3: MFA enforcement
        For any user with MFA enabled, authentication should require 
        additional verification factors beyond username/password.
        
        Feature: network-monitoring-tool, Property 3: MFA enforcement
        Validates: Requirements 1.3
        """
        assume(len(usernames) == len(passwords) == len(mfa_enabled_flags))
        
        # Create test users with different MFA settings
        users = []
        unique_id = str(uuid.uuid4())[:8]
        
        for i, (username, password, mfa_enabled) in enumerate(zip(usernames, passwords, mfa_enabled_flags)):
            user = User.objects.create_user(
                username=f"{username}_{unique_id}_{i}",
                email=f"{username}_{unique_id}_{i}@example.com",
                password=password
            )
            user.mfa_enabled = mfa_enabled
            user.save()
            
            # If MFA is enabled, create and confirm a TOTP device
            if mfa_enabled:
                device = TOTPDevice.objects.create(
                    user=user,
                    name=f"{user.username}-totp",
                    confirmed=True
                )
            
            users.append((user, password, mfa_enabled))
        
        # Test authentication behavior for each user
        for user, password, mfa_enabled in users:
            # Test login without MFA token
            response = self.client.post('/api/auth/token/', {
                'username': user.username,
                'password': password
            })
            
            if mfa_enabled:
                # Should require MFA token
                assert response.status_code == status.HTTP_400_BAD_REQUEST, f"MFA-enabled user should be rejected without token"
                assert 'mfa_required' in str(response.data) or 'MFA token' in str(response.data), "Should indicate MFA is required"
            else:
                # Should succeed without MFA token
                assert response.status_code == status.HTTP_200_OK, f"Non-MFA user should succeed without token"
                assert 'access' in response.data, "Should return access token"
                assert 'refresh' in response.data, "Should return refresh token"
    
    @given(
        usernames=st.lists(username_strategy(), min_size=1, max_size=2, unique=True),
        passwords=st.lists(password_strategy(), min_size=1, max_size=2),
        valid_tokens=st.lists(totp_token_strategy(), min_size=1, max_size=2),
        invalid_tokens=st.lists(totp_token_strategy(), min_size=1, max_size=2)
    )
    @hypothesis_settings(max_examples=2, deadline=4000)
    def test_mfa_token_validation_property(self, usernames, passwords, valid_tokens, invalid_tokens):
        """
        Property: MFA token validation is consistent and secure.
        
        For any MFA-enabled user, valid tokens should grant access while
        invalid tokens should be rejected consistently.
        
        Feature: network-monitoring-tool, Property 3: MFA enforcement
        Validates: Requirements 1.3
        """
        assume(len(usernames) == len(passwords) == len(valid_tokens) == len(invalid_tokens))
        assume(all(vt != it for vt, it in zip(valid_tokens, invalid_tokens)))
        
        # Create MFA-enabled users
        users = []
        unique_id = str(uuid.uuid4())[:8]
        
        for i, (username, password) in enumerate(zip(usernames, passwords)):
            user = User.objects.create_user(
                username=f"{username}_{unique_id}_{i}",
                email=f"{username}_{unique_id}_{i}@example.com",
                password=password
            )
            user.mfa_enabled = True
            user.save()
            
            # Create confirmed TOTP device
            device = TOTPDevice.objects.create(
                user=user,
                name=f"{user.username}-totp",
                confirmed=True
            )
            
            users.append((user, password, device))
        
        # Test token validation
        for i, (user, password, device) in enumerate(users):
            valid_token = valid_tokens[i]
            invalid_token = invalid_tokens[i]
            
            # Mock device verification for valid token
            with patch.object(device, 'verify_token') as mock_verify:
                mock_verify.return_value = True
                
                response = self.client.post('/api/auth/token/', {
                    'username': user.username,
                    'password': password,
                    'mfa_token': valid_token
                })
                
                # Valid token should grant access
                assert response.status_code == status.HTTP_200_OK, f"Valid MFA token should grant access"
                assert 'access' in response.data, "Should return access token"
                assert mock_verify.called, "Should verify the token"
            
            # Test invalid token
            with patch.object(device, 'verify_token') as mock_verify:
                mock_verify.return_value = False
                
                response = self.client.post('/api/auth/token/', {
                    'username': user.username,
                    'password': password,
                    'mfa_token': invalid_token
                })
                
                # Invalid token should be rejected
                assert response.status_code == status.HTTP_400_BAD_REQUEST, f"Invalid MFA token should be rejected"
                assert 'access' not in response.data, "Should not return access token"
                assert mock_verify.called, "Should verify the token"
    
    @given(
        usernames=st.lists(username_strategy(), min_size=1, max_size=2, unique=True),
        passwords=st.lists(password_strategy(), min_size=1, max_size=2)
    )
    @hypothesis_settings(max_examples=2, deadline=3000)
    def test_mfa_setup_workflow_property(self, usernames, passwords):
        """
        Property: MFA setup workflow maintains security and consistency.
        
        For any user, the MFA setup process should follow a secure workflow
        that requires token verification before enabling MFA.
        
        Feature: network-monitoring-tool, Property 3: MFA enforcement
        Validates: Requirements 1.3
        """
        assume(len(usernames) == len(passwords))
        
        # Create test users
        users = []
        unique_id = str(uuid.uuid4())[:8]
        
        for i, (username, password) in enumerate(zip(usernames, passwords)):
            user = User.objects.create_user(
                username=f"{username}_{unique_id}_{i}",
                email=f"{username}_{unique_id}_{i}@example.com",
                password=password
            )
            users.append((user, password))
        
        # Test MFA setup workflow for each user
        for user, password in users:
            # Authenticate user
            self.client.force_authenticate(user=user)
            
            # Initial state: MFA should not be enabled
            assert not MFAService.is_mfa_enabled(user), "MFA should not be enabled initially"
            
            # Step 1: Setup MFA (get QR code)
            response = self.client.post('/api/auth/mfa/setup/')
            assert response.status_code == status.HTTP_200_OK, "MFA setup should succeed"
            assert 'qr_code' in response.data, "Should return QR code"
            assert 'secret_key' in response.data, "Should return secret key"
            
            # MFA should still not be enabled (not verified yet)
            user.refresh_from_db()
            assert not MFAService.is_mfa_enabled(user), "MFA should not be enabled before verification"
            
            # Step 2: Verify setup with mock token
            with patch('core.mfa.MFAService.enable_mfa') as mock_enable:
                mock_enable.return_value = (True, "MFA enabled successfully")
                
                response = self.client.post('/api/auth/mfa/verify-setup/', {
                    'token': '123456'
                })
                
                assert response.status_code == status.HTTP_200_OK, "MFA verification should succeed"
                assert mock_enable.called, "Should call MFA enable service"
                assert 'backup_codes' in response.data, "Should return backup codes"
            
            # Step 3: Disable MFA
            response = self.client.post('/api/auth/mfa/disable/', {
                'password': password
            })
            assert response.status_code == status.HTTP_200_OK, "MFA disable should succeed"
    
    @given(
        usernames=st.lists(username_strategy(), min_size=1, max_size=2, unique=True),
        passwords=st.lists(password_strategy(), min_size=1, max_size=2),
        wrong_passwords=st.lists(password_strategy(), min_size=1, max_size=2)
    )
    @hypothesis_settings(max_examples=2, deadline=3000)
    def test_mfa_security_controls_property(self, usernames, passwords, wrong_passwords):
        """
        Property: MFA security controls prevent unauthorized access.
        
        For any MFA operation, proper authentication and authorization
        should be required to prevent unauthorized MFA changes.
        
        Feature: network-monitoring-tool, Property 3: MFA enforcement
        Validates: Requirements 1.3
        """
        assume(len(usernames) == len(passwords) == len(wrong_passwords))
        assume(all(p != wp for p, wp in zip(passwords, wrong_passwords)))
        
        # Create MFA-enabled users
        users = []
        unique_id = str(uuid.uuid4())[:8]
        
        for i, (username, password) in enumerate(zip(usernames, passwords)):
            user = User.objects.create_user(
                username=f"{username}_{unique_id}_{i}",
                email=f"{username}_{unique_id}_{i}@example.com",
                password=password
            )
            user.mfa_enabled = True
            user.save()
            
            # Create confirmed TOTP device
            TOTPDevice.objects.create(
                user=user,
                name=f"{user.username}-totp",
                confirmed=True
            )
            
            users.append((user, password))
        
        # Test security controls
        for i, (user, password) in enumerate(users):
            wrong_password = wrong_passwords[i]
            
            # Authenticate user
            self.client.force_authenticate(user=user)
            
            # Test: Disable MFA with wrong password should fail
            response = self.client.post('/api/auth/mfa/disable/', {
                'password': wrong_password
            })
            assert response.status_code == status.HTTP_400_BAD_REQUEST, "Wrong password should be rejected"
            assert 'Invalid password' in str(response.data), "Should indicate invalid password"
            
            # Test: Disable MFA with correct password should succeed
            response = self.client.post('/api/auth/mfa/disable/', {
                'password': password
            })
            assert response.status_code == status.HTTP_200_OK, "Correct password should succeed"
            
            # Test: Regenerate backup codes with wrong password should fail
            # First re-enable MFA for this test
            user.mfa_enabled = True
            user.save()
            TOTPDevice.objects.create(
                user=user,
                name=f"{user.username}-totp-2",
                confirmed=True
            )
            
            response = self.client.post('/api/auth/mfa/backup-codes/regenerate/', {
                'password': wrong_password
            })
            assert response.status_code == status.HTTP_400_BAD_REQUEST, "Wrong password should be rejected for backup codes"
    
    @given(
        usernames=st.lists(username_strategy(), min_size=1, max_size=2, unique=True),
        passwords=st.lists(password_strategy(), min_size=1, max_size=2)
    )
    @hypothesis_settings(max_examples=2, deadline=3000)
    def test_mfa_audit_logging_property(self, usernames, passwords):
        """
        Property: MFA operations are properly audited and logged.
        
        For any MFA-related operation, appropriate audit logs should be
        created to maintain security accountability.
        
        Feature: network-monitoring-tool, Property 3: MFA enforcement
        Validates: Requirements 1.3
        """
        assume(len(usernames) == len(passwords))
        
        # Create test users
        users = []
        unique_id = str(uuid.uuid4())[:8]
        
        for i, (username, password) in enumerate(zip(usernames, passwords)):
            user = User.objects.create_user(
                username=f"{username}_{unique_id}_{i}",
                email=f"{username}_{unique_id}_{i}@example.com",
                password=password
            )
            users.append((user, password))
        
        # Test audit logging for each user
        for user, password in users:
            initial_log_count = AuditLog.objects.filter(user=user).count()
            
            # Test: Login attempts should be logged
            response = self.client.post('/api/auth/token/', {
                'username': user.username,
                'password': password
            })
            
            # Should have created a login audit log
            new_log_count = AuditLog.objects.filter(user=user, action='login').count()
            assert new_log_count > 0, "Login should create audit log"
            
            # Test: Failed login should also be logged
            response = self.client.post('/api/auth/token/', {
                'username': user.username,
                'password': 'wrongpassword'
            })
            
            # Should have created a failed login audit log
            failed_logs = AuditLog.objects.filter(
                username=user.username, 
                action='login', 
                success=False
            ).count()
            assert failed_logs > 0, "Failed login should create audit log"
    
    def test_mfa_service_consistency_property(self):
        """
        Property: MFA service operations are consistent and idempotent.
        
        For any MFA service operation, repeated calls should produce
        consistent results without side effects.
        
        Feature: network-monitoring-tool, Property 3: MFA enforcement
        Validates: Requirements 1.3
        """
        # Create test user
        unique_id = str(uuid.uuid4())[:8]
        user = User.objects.create_user(
            username=f'testuser_{unique_id}',
            email=f'test_{unique_id}@example.com',
            password='testpass123'
        )
        
        # Test: is_mfa_enabled should be consistent
        initial_status = MFAService.is_mfa_enabled(user)
        repeated_status = MFAService.is_mfa_enabled(user)
        assert initial_status == repeated_status, "MFA status check should be consistent"
        
        # Test: get_or_create_totp_device should be idempotent
        device1 = MFAService.get_or_create_totp_device(user)
        device2 = MFAService.get_or_create_totp_device(user)
        assert device1.id == device2.id, "Should return same device on repeated calls"
        
        # Test: disable_mfa should be idempotent
        success1, message1 = MFAService.disable_mfa(user)
        success2, message2 = MFAService.disable_mfa(user)
        assert success1 == success2, "Disable MFA should be idempotent"
        
        # Verify user state is consistent
        user.refresh_from_db()
        assert not user.mfa_enabled, "User MFA should be disabled"
        assert not MFAService.is_mfa_enabled(user), "Service should reflect disabled state"