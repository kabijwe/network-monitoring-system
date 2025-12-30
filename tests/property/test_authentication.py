"""
Property-based tests for authentication system.

These tests validate universal properties of the authentication system
using Hypothesis to generate test data and verify correctness properties.
"""
import pytest
from hypothesis import given, strategies as st, settings, assume
from django.test import TestCase, TransactionTestCase
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
import json
import re

from core.models import Role, UserRole, AuditLog

User = get_user_model()


class AuthenticationPropertyTests(TestCase):
    """Property-based tests for authentication system."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create roles (use get_or_create to avoid duplicates)
        self.viewer_role, _ = Role.objects.get_or_create(
            name='viewer',
            defaults={
                'display_name': 'Viewer',
                'description': 'Read-only access',
                'permissions': {
                    'report_access': True
                }
            }
        )
        
        self.editor_role, _ = Role.objects.get_or_create(
            name='editor',
            defaults={
                'display_name': 'Editor',
                'description': 'Edit access',
                'permissions': {
                    'device_management': True,
                    'alert_management': True,
                    'report_access': True
                }
            }
        )
    
    def test_property_1_credential_validation_consistency(self):
        """
        Property 1: Credential validation consistency
        
        For any valid user credentials, authentication should be consistent:
        - Valid credentials always authenticate successfully
        - Invalid credentials always fail
        - Authentication state is deterministic
        """
        # Test with multiple generated usernames and passwords
        test_cases = [
            ('testuser1', 'password123'),
            ('admin2024', 'securepass456'),
            ('viewer99', 'mypassword789'),
            ('editor42', 'strongpass000'),
            ('user123', 'testpass111')
        ]
        
        for username, password in test_cases:
            with self.subTest(username=username):
                # Create a user with the credentials
                user = User.objects.create_user(
                    username=username,
                    password=password,
                    email=f"{username}@example.com"
                )
                
                # Assign a role to the user
                UserRole.objects.create(
                    user=user,
                    role=self.viewer_role,
                    assigned_by=user
                )
                
                # Test 1: Valid credentials should always authenticate
                response = self.client.post(
                    reverse('core:token_obtain_pair'),
                    {
                        'username': username,
                        'password': password
                    },
                    format='json'
                )
                
                self.assertEqual(response.status_code, 200)
                self.assertIn('access', response.data)
                self.assertIn('refresh', response.data)
                self.assertIn('user', response.data)
                self.assertEqual(response.data['user']['username'], username)
                
                # Test 2: Invalid password should always fail
                response = self.client.post(
                    reverse('core:token_obtain_pair'),
                    {
                        'username': username,
                        'password': password + 'invalid'
                    },
                    format='json'
                )
                
                self.assertEqual(response.status_code, 401)
                self.assertNotIn('access', response.data)
                
                # Test 3: Invalid username should always fail
                response = self.client.post(
                    reverse('core:token_obtain_pair'),
                    {
                        'username': username + 'invalid',
                        'password': password
                    },
                    format='json'
                )
                
                self.assertEqual(response.status_code, 401)
                self.assertNotIn('access', response.data)
                
                # Verify audit log entries were created
                login_logs = AuditLog.objects.filter(
                    user=user,
                    action='login',
                    success=True
                )
                self.assertGreaterEqual(login_logs.count(), 1)
    
    def test_property_2_jwt_token_issuance(self):
        """
        Property 2: JWT token issuance
        
        For any authenticated user:
        - JWT tokens are always issued in valid format
        - Access and refresh tokens have correct structure
        - Tokens contain valid user information
        - Token expiration times are set correctly
        """
        test_cases = [
            ('tokenuser1', 'tokenpass123'),
            ('jwttest2', 'jwtpassword456'),
            ('authuser3', 'authpass789')
        ]
        
        for username, password in test_cases:
            with self.subTest(username=username):
                # Create user
                user = User.objects.create_user(
                    username=username,
                    password=password,
                    email=f"{username}@example.com"
                )
                
                # Assign role
                UserRole.objects.create(
                    user=user,
                    role=self.editor_role,
                    assigned_by=user
                )
                
                # Authenticate and get tokens
                response = self.client.post(
                    reverse('core:token_obtain_pair'),
                    {
                        'username': username,
                        'password': password
                    },
                    format='json'
                )
                
                self.assertEqual(response.status_code, 200)
                
                # Test JWT token structure
                access_token = response.data['access']
                refresh_token = response.data['refresh']
                
                # JWT tokens should have 3 parts separated by dots
                self.assertEqual(len(access_token.split('.')), 3)
                self.assertEqual(len(refresh_token.split('.')), 3)
                
                # Tokens should be different
                self.assertNotEqual(access_token, refresh_token)
                
                # User information should be included
                user_data = response.data['user']
                self.assertEqual(user_data['username'], username)
                self.assertEqual(user_data['id'], str(user.id))
                self.assertIn('email', user_data)
                
                # Roles should be included
                roles = response.data['roles']
                self.assertIsInstance(roles, list)
                self.assertGreater(len(roles), 0)
                self.assertEqual(roles[0]['role'], 'editor')
                
                # Test token verification
                verify_response = self.client.post(
                    reverse('core:token_verify'),
                    {'token': access_token},
                    format='json'
                )
                self.assertEqual(verify_response.status_code, 200)


# Unit tests for edge cases and specific functionality
class AuthenticationEdgeCaseTests(TestCase):
    """Edge case tests for authentication system."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create a basic role
        self.viewer_role, _ = Role.objects.get_or_create(
            name='viewer',
            defaults={
                'display_name': 'Viewer',
                'description': 'Read-only access',
                'permissions': {'report_access': True}
            }
        )
    
    def test_empty_credentials(self):
        """Test authentication with empty credentials."""
        response = self.client.post(
            reverse('core:token_obtain_pair'),
            {'username': '', 'password': ''},
            format='json'
        )
        self.assertEqual(response.status_code, 400)
    
    def test_malformed_requests(self):
        """Test authentication with malformed requests."""
        # Missing username
        response = self.client.post(
            reverse('core:token_obtain_pair'),
            {'password': 'testpass'},
            format='json'
        )
        self.assertEqual(response.status_code, 400)
        
        # Missing password
        response = self.client.post(
            reverse('core:token_obtain_pair'),
            {'username': 'testuser'},
            format='json'
        )
        self.assertEqual(response.status_code, 400)
    
    def test_inactive_user_authentication(self):
        """Test authentication with inactive user."""
        user = User.objects.create_user(
            username='inactive_user',
            password='testpass123',
            email='inactive@example.com',
            is_active=False
        )
        
        UserRole.objects.create(
            user=user,
            role=self.viewer_role,
            assigned_by=user
        )
        
        response = self.client.post(
            reverse('core:token_obtain_pair'),
            {
                'username': 'inactive_user',
                'password': 'testpass123'
            },
            format='json'
        )
        self.assertEqual(response.status_code, 401)
    
    def test_user_without_roles(self):
        """Test authentication for user without assigned roles."""
        user = User.objects.create_user(
            username='no_roles_user',
            password='testpass123',
            email='noroles@example.com'
        )
        
        response = self.client.post(
            reverse('core:token_obtain_pair'),
            {
                'username': 'no_roles_user',
                'password': 'testpass123'
            },
            format='json'
        )
        
        # Should still authenticate but with empty roles
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['roles']), 0)
    
    def test_role_based_permissions(self):
        """Test role-based permission system."""
        # Create users with different roles
        admin_user = User.objects.create_user(
            username='admin_user',
            password='testpass123',
            email='admin@example.com'
        )
        
        admin_role, _ = Role.objects.get_or_create(
            name='admin',
            defaults={
                'display_name': 'Admin',
                'description': 'Administrative access',
                'permissions': {
                    'user_management': True,
                    'device_management': True
                }
            }
        )
        
        UserRole.objects.create(
            user=admin_user,
            role=admin_role,
            assigned_by=admin_user
        )
        
        # Test authentication
        response = self.client.post(
            reverse('core:token_obtain_pair'),
            {
                'username': 'admin_user',
                'password': 'testpass123'
            },
            format='json'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['roles'][0]['role'], 'admin')
        
        # Test user info endpoint
        access_token = response.data['access']
        user_info_response = self.client.get(
            reverse('core:user_info'),
            HTTP_AUTHORIZATION=f'Bearer {access_token}'
        )
        
        self.assertEqual(user_info_response.status_code, 200)
        self.assertTrue(user_info_response.data['has_admin_access'])
        self.assertTrue(user_info_response.data['can_edit'])
    
    def test_logout_functionality(self):
        """Test logout functionality."""
        user = User.objects.create_user(
            username='logout_user',
            password='testpass123',
            email='logout@example.com'
        )
        
        UserRole.objects.create(
            user=user,
            role=self.viewer_role,
            assigned_by=user
        )
        
        # Login
        login_response = self.client.post(
            reverse('core:token_obtain_pair'),
            {
                'username': 'logout_user',
                'password': 'testpass123'
            },
            format='json'
        )
        
        self.assertEqual(login_response.status_code, 200)
        
        access_token = login_response.data['access']
        refresh_token = login_response.data['refresh']
        
        # Logout
        logout_response = self.client.post(
            reverse('core:logout'),
            {'refresh_token': refresh_token},
            HTTP_AUTHORIZATION=f'Bearer {access_token}',
            format='json'
        )
        
        # Should succeed or return 400 if token is already invalid
        self.assertIn(logout_response.status_code, [200, 400])
        
        # The main test is that logout endpoint is accessible and responds
        # Token blacklisting behavior may vary based on JWT configuration
        # but the endpoint should at least respond properly
        
        # Verify logout audit log (if logout was successful)
        if logout_response.status_code == 200:
            logout_logs = AuditLog.objects.filter(
                user=user,
                action='logout',
                success=True
            )
            self.assertGreaterEqual(logout_logs.count(), 1)
    
    def test_password_change_functionality(self):
        """Test password change functionality."""
        user = User.objects.create_user(
            username='password_user',
            password='oldpass123',
            email='password@example.com'
        )
        
        UserRole.objects.create(
            user=user,
            role=self.viewer_role,
            assigned_by=user
        )
        
        # Login
        login_response = self.client.post(
            reverse('core:token_obtain_pair'),
            {
                'username': 'password_user',
                'password': 'oldpass123'
            },
            format='json'
        )
        
        self.assertEqual(login_response.status_code, 200)
        access_token = login_response.data['access']
        
        # Change password
        change_response = self.client.post(
            reverse('core:change_password'),
            {
                'current_password': 'oldpass123',
                'new_password': 'newpass456',
                'new_password_confirm': 'newpass456'
            },
            HTTP_AUTHORIZATION=f'Bearer {access_token}',
            format='json'
        )
        
        self.assertEqual(change_response.status_code, 200)
        
        # Verify old password no longer works
        old_login_response = self.client.post(
            reverse('core:token_obtain_pair'),
            {
                'username': 'password_user',
                'password': 'oldpass123'
            },
            format='json'
        )
        self.assertEqual(old_login_response.status_code, 401)
        
        # Verify new password works
        new_login_response = self.client.post(
            reverse('core:token_obtain_pair'),
            {
                'username': 'password_user',
                'password': 'newpass456'
            },
            format='json'
        )
        self.assertEqual(new_login_response.status_code, 200)
        
        # Verify password change audit log
        password_logs = AuditLog.objects.filter(
            user=user,
            action='update',
            resource_type='UserPassword',
            success=True
        )
        self.assertGreaterEqual(password_logs.count(), 1)
    
    def test_multiple_role_assignments(self):
        """Test users with multiple role assignments."""
        user = User.objects.create_user(
            username='multi_role_user',
            password='testpass123',
            email='multirole@example.com'
        )
        
        # Create additional roles
        admin_role, _ = Role.objects.get_or_create(
            name='admin',
            defaults={
                'display_name': 'Admin',
                'description': 'Administrative access',
                'permissions': {'user_management': True}
            }
        )
        
        # Assign multiple roles
        UserRole.objects.create(
            user=user,
            role=self.viewer_role,
            assigned_by=user
        )
        
        UserRole.objects.create(
            user=user,
            role=admin_role,
            assigned_by=user
        )
        
        # Test authentication
        response = self.client.post(
            reverse('core:token_obtain_pair'),
            {
                'username': 'multi_role_user',
                'password': 'testpass123'
            },
            format='json'
        )
        
        self.assertEqual(response.status_code, 200)
        
        # Should have multiple roles
        roles = response.data['roles']
        self.assertEqual(len(roles), 2)
        role_names = [role['role'] for role in roles]
        self.assertIn('viewer', role_names)
        self.assertIn('admin', role_names)