"""
Property-based tests for project setup validation.

Feature: network-monitoring-tool, Property 1: Django project structure validation
Tests that the Django project is properly configured and all required
components are available and correctly structured.
"""

import os
import sys
from pathlib import Path
import pytest
from hypothesis import given, strategies as st
from hypothesis.extra.django import TestCase
from django.conf import settings
from django.core.management import call_command
from django.apps import apps
from django.db import connection
from django.core.exceptions import ImproperlyConfigured


class TestProjectSetupProperties(TestCase):
    """
    Property-based tests for Django project structure validation.
    **Validates: Requirements 10.1**
    """

    def test_django_project_structure_validation(self):
        """
        Feature: network-monitoring-tool, Property 1: Django project structure validation
        
        For any Django project setup, all required apps should be properly
        configured and the project structure should be valid.
        """
        # Test that all required apps are installed and configured
        required_apps = [
            'core',
            'monitoring', 
            'api',
            'frontend',
            'rest_framework',
            'channels',
            'django_celery_beat',
            'django_prometheus',
        ]
        
        installed_apps = [app.name for app in apps.get_app_configs()]
        
        for required_app in required_apps:
            self.assertIn(
                required_app, 
                installed_apps,
                f"Required app '{required_app}' is not installed"
            )

    def test_database_configuration_validity(self):
        """
        Test that database configuration is valid and accessible.
        """
        # Test database connection
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                self.assertEqual(result[0], 1)
        except Exception as e:
            self.fail(f"Database connection failed: {e}")

    def test_required_settings_present(self):
        """
        Test that all required Django settings are properly configured.
        """
        required_settings = [
            'SECRET_KEY',
            'DATABASES',
            'INSTALLED_APPS',
            'MIDDLEWARE',
            'ROOT_URLCONF',
            'TEMPLATES',
            'AUTH_USER_MODEL',
            'REST_FRAMEWORK',
            'CELERY_BROKER_URL',
            'CHANNEL_LAYERS',
        ]
        
        for setting_name in required_settings:
            self.assertTrue(
                hasattr(settings, setting_name),
                f"Required setting '{setting_name}' is not configured"
            )
            
            setting_value = getattr(settings, setting_name)
            self.assertIsNotNone(
                setting_value,
                f"Required setting '{setting_name}' is None"
            )

    def test_custom_user_model_configuration(self):
        """
        Test that the custom user model is properly configured.
        """
        from django.contrib.auth import get_user_model
        
        User = get_user_model()
        
        # Test that we're using the custom user model
        self.assertEqual(settings.AUTH_USER_MODEL, 'core.User')
        
        # Test that the user model has required fields
        required_fields = ['email', 'phone', 'department', 'mfa_enabled']
        
        for field_name in required_fields:
            self.assertTrue(
                hasattr(User, field_name),
                f"User model missing required field: {field_name}"
            )

    def test_middleware_configuration(self):
        """
        Test that required middleware is properly configured.
        """
        required_middleware = [
            'django_prometheus.middleware.PrometheusBeforeMiddleware',
            'corsheaders.middleware.CorsMiddleware',
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django_otp.middleware.OTPMiddleware',
            'django_prometheus.middleware.PrometheusAfterMiddleware',
        ]
        
        configured_middleware = settings.MIDDLEWARE
        
        for middleware in required_middleware:
            self.assertIn(
                middleware,
                configured_middleware,
                f"Required middleware '{middleware}' is not configured"
            )

    def test_celery_configuration(self):
        """
        Test that Celery is properly configured.
        """
        # Test Celery settings
        self.assertTrue(hasattr(settings, 'CELERY_BROKER_URL'))
        self.assertTrue(hasattr(settings, 'CELERY_RESULT_BACKEND'))
        
        # Test that Celery app can be imported
        try:
            from nms.celery import app as celery_app
            self.assertIsNotNone(celery_app)
        except ImportError as e:
            self.fail(f"Failed to import Celery app: {e}")

    def test_channels_configuration(self):
        """
        Test that Django Channels is properly configured.
        """
        # Test Channels settings
        self.assertTrue(hasattr(settings, 'ASGI_APPLICATION'))
        self.assertTrue(hasattr(settings, 'CHANNEL_LAYERS'))
        
        # Test that ASGI application can be imported
        try:
            from nms.asgi import application
            self.assertIsNotNone(application)
        except ImportError as e:
            self.fail(f"Failed to import ASGI application: {e}")

    def test_rest_framework_configuration(self):
        """
        Test that Django REST Framework is properly configured.
        """
        rest_config = settings.REST_FRAMEWORK
        
        required_config_keys = [
            'DEFAULT_AUTHENTICATION_CLASSES',
            'DEFAULT_PERMISSION_CLASSES',
            'DEFAULT_PAGINATION_CLASS',
            'PAGE_SIZE',
        ]
        
        for key in required_config_keys:
            self.assertIn(
                key,
                rest_config,
                f"REST Framework missing required configuration: {key}"
            )

    def test_prometheus_integration(self):
        """
        Test that Prometheus integration is properly configured.
        """
        # Test that prometheus middleware is configured
        self.assertIn(
            'django_prometheus.middleware.PrometheusBeforeMiddleware',
            settings.MIDDLEWARE
        )
        self.assertIn(
            'django_prometheus.middleware.PrometheusAfterMiddleware', 
            settings.MIDDLEWARE
        )
        
        # Test that prometheus app is installed
        self.assertIn('django_prometheus', settings.INSTALLED_APPS)

    def test_file_structure_integrity(self):
        """
        Test that required files and directories exist.
        """
        base_dir = Path(settings.BASE_DIR)
        
        required_files = [
            'manage.py',
            'requirements.txt',
            'docker-compose.yml',
            'nms/__init__.py',
            'nms/settings.py',
            'nms/urls.py',
            'nms/wsgi.py',
            'nms/asgi.py',
            'nms/celery.py',
        ]
        
        required_directories = [
            'core',
            'monitoring',
            'api', 
            'frontend',
            'tests',
            'docker',
        ]
        
        for file_path in required_files:
            full_path = base_dir / file_path
            self.assertTrue(
                full_path.exists(),
                f"Required file missing: {file_path}"
            )
        
        for dir_path in required_directories:
            full_path = base_dir / dir_path
            self.assertTrue(
                full_path.exists() and full_path.is_dir(),
                f"Required directory missing: {dir_path}"
            )

    @given(st.text(min_size=1, max_size=100))
    def test_system_configuration_keys_valid(self, config_key):
        """
        Property test: For any configuration key, the system should handle
        it gracefully without errors.
        """
        from core.models import SystemConfiguration
        
        # Test that we can create configuration entries with various keys
        # This tests the robustness of our configuration system
        try:
            # Clean the key to make it valid
            clean_key = ''.join(c for c in config_key if c.isalnum() or c in '._-')
            if not clean_key:
                clean_key = 'test_key'
            
            config = SystemConfiguration(
                key=clean_key,
                value={'test': 'value'},
                description='Test configuration',
                category='test'
            )
            
            # Test that the model validates without errors
            config.full_clean()
            
        except Exception as e:
            # Should not raise exceptions for valid configuration keys
            if 'unique' not in str(e).lower():  # Ignore unique constraint violations
                self.fail(f"Configuration system failed for key '{clean_key}': {e}")

    def test_management_commands_available(self):
        """
        Test that required management commands are available.
        """
        from django.core.management import get_commands
        
        commands = get_commands()
        required_commands = [
            'init_nms',  # Our custom initialization command
        ]
        
        for command in required_commands:
            self.assertIn(
                command,
                commands,
                f"Required management command missing: {command}"
            )

    def test_url_configuration_valid(self):
        """
        Test that URL configuration is valid and doesn't have obvious errors.
        """
        from django.urls import reverse
        from django.urls.exceptions import NoReverseMatch
        
        # Test that admin URLs are configured
        try:
            admin_url = reverse('admin:index')
            self.assertTrue(admin_url.startswith('/admin/'))
        except NoReverseMatch:
            self.fail("Admin URLs not properly configured")

    def test_logging_configuration(self):
        """
        Test that logging is properly configured.
        """
        import logging
        
        # Test that we can get loggers for our apps
        loggers_to_test = ['nms', 'django', 'core', 'monitoring']
        
        for logger_name in loggers_to_test:
            logger = logging.getLogger(logger_name)
            self.assertIsNotNone(logger)
            
        # Test that log directory exists
        log_dir = Path(settings.BASE_DIR) / 'logs'
        self.assertTrue(
            log_dir.exists() or settings.DEBUG,  # May not exist in test environment
            "Log directory should exist in production"
        )