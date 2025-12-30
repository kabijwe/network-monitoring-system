"""
Management command to initialize the Network Monitoring System.

This command sets up the initial system configuration including:
- Default roles and permissions
- System configuration settings
- Default admin user (if not exists)
- Initial monitoring profiles
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction
from core.models import Role, UserRole, SystemConfiguration

User = get_user_model()


class Command(BaseCommand):
    help = 'Initialize the Network Monitoring System with default configuration'

    def add_arguments(self, parser):
        parser.add_argument(
            '--skip-admin',
            action='store_true',
            help='Skip creating default admin user',
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Initializing Network Monitoring System...')
        )

        with transaction.atomic():
            # Create default roles
            self.create_default_roles()
            
            # Create default admin user if requested
            if not options['skip_admin']:
                self.create_default_admin()
            
            # Set up system configuration
            self.setup_system_configuration()

        self.stdout.write(
            self.style.SUCCESS('Network Monitoring System initialized successfully!')
        )

    def create_default_roles(self):
        """Create the four default roles with their permissions."""
        self.stdout.write('Creating default roles...')

        roles_data = [
            {
                'name': 'superadmin',
                'display_name': 'SuperAdmin',
                'description': 'Full system access including user management and system configuration',
                'permissions': {
                    'can_manage_users': True,
                    'can_manage_system': True,
                    'can_manage_hosts': True,
                    'can_acknowledge_alerts': True,
                    'can_create_maintenance': True,
                    'can_export_data': True,
                    'can_import_data': True,
                    'can_view_audit_logs': True,
                    'can_manage_roles': True,
                }
            },
            {
                'name': 'admin',
                'display_name': 'Admin',
                'description': 'User and host management but restricted system-level configuration',
                'permissions': {
                    'can_manage_users': True,
                    'can_manage_system': False,
                    'can_manage_hosts': True,
                    'can_acknowledge_alerts': True,
                    'can_create_maintenance': True,
                    'can_export_data': True,
                    'can_import_data': True,
                    'can_view_audit_logs': True,
                    'can_manage_roles': False,
                }
            },
            {
                'name': 'editor',
                'display_name': 'Editor',
                'description': 'Host editing, acknowledgments, and maintenance scheduling',
                'permissions': {
                    'can_manage_users': False,
                    'can_manage_system': False,
                    'can_manage_hosts': True,
                    'can_acknowledge_alerts': True,
                    'can_create_maintenance': True,
                    'can_export_data': False,
                    'can_import_data': False,
                    'can_view_audit_logs': False,
                    'can_manage_roles': False,
                }
            },
            {
                'name': 'viewer',
                'display_name': 'Viewer',
                'description': 'Read-only access to all monitoring data',
                'permissions': {
                    'can_manage_users': False,
                    'can_manage_system': False,
                    'can_manage_hosts': False,
                    'can_acknowledge_alerts': False,
                    'can_create_maintenance': False,
                    'can_export_data': False,
                    'can_import_data': False,
                    'can_view_audit_logs': False,
                    'can_manage_roles': False,
                }
            }
        ]

        for role_data in roles_data:
            role, created = Role.objects.get_or_create(
                name=role_data['name'],
                defaults={
                    'display_name': role_data['display_name'],
                    'description': role_data['description'],
                    'permissions': role_data['permissions'],
                }
            )
            if created:
                self.stdout.write(f'  Created role: {role.display_name}')
            else:
                self.stdout.write(f'  Role already exists: {role.display_name}')

    def create_default_admin(self):
        """Create default admin user with SuperAdmin role."""
        self.stdout.write('Creating default admin user...')

        # Check if admin user already exists
        if User.objects.filter(username='admin').exists():
            self.stdout.write('  Admin user already exists')
            return

        # Create admin user
        admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='admin123',
            first_name='System',
            last_name='Administrator',
            is_staff=True,
            is_superuser=True,
        )

        # Assign SuperAdmin role
        superadmin_role = Role.objects.get(name='superadmin')
        UserRole.objects.create(
            user=admin_user,
            role=superadmin_role,
            assigned_by=admin_user,
        )

        self.stdout.write(
            self.style.SUCCESS('  Created admin user: admin / admin123')
        )

    def setup_system_configuration(self):
        """Set up default system configuration."""
        self.stdout.write('Setting up system configuration...')

        config_data = [
            {
                'key': 'system.name',
                'value': 'Network Monitoring System',
                'description': 'System display name',
                'category': 'general',
            },
            {
                'key': 'system.version',
                'value': '1.0.0',
                'description': 'System version',
                'category': 'general',
            },
            {
                'key': 'monitoring.ping_timeout',
                'value': 5,
                'description': 'Default ping timeout in seconds',
                'category': 'monitoring',
            },
            {
                'key': 'monitoring.snmp_timeout',
                'value': 10,
                'description': 'Default SNMP timeout in seconds',
                'category': 'monitoring',
            },
            {
                'key': 'monitoring.check_interval',
                'value': 30,
                'description': 'Default monitoring check interval in seconds',
                'category': 'monitoring',
            },
            {
                'key': 'alerts.default_escalation_time',
                'value': 300,
                'description': 'Default alert escalation time in seconds',
                'category': 'alerts',
            },
            {
                'key': 'alerts.max_alerts_per_minute',
                'value': 10,
                'description': 'Maximum alerts per minute to prevent flooding',
                'category': 'alerts',
            },
            {
                'key': 'ui.default_theme',
                'value': 'light',
                'description': 'Default UI theme (light/dark)',
                'category': 'ui',
            },
            {
                'key': 'ui.items_per_page',
                'value': 50,
                'description': 'Default number of items per page in tables',
                'category': 'ui',
            },
            {
                'key': 'security.session_timeout',
                'value': 3600,
                'description': 'Session timeout in seconds',
                'category': 'security',
            },
            {
                'key': 'security.password_min_length',
                'value': 8,
                'description': 'Minimum password length',
                'category': 'security',
            },
            {
                'key': 'backup.retention_days',
                'value': 30,
                'description': 'Number of days to retain backup files',
                'category': 'backup',
            },
        ]

        for config in config_data:
            obj, created = SystemConfiguration.objects.get_or_create(
                key=config['key'],
                defaults={
                    'value': config['value'],
                    'description': config['description'],
                    'category': config['category'],
                }
            )
            if created:
                self.stdout.write(f'  Created configuration: {config["key"]}')
            else:
                self.stdout.write(f'  Configuration already exists: {config["key"]}')

        self.stdout.write(
            self.style.SUCCESS('System configuration completed!')
        )