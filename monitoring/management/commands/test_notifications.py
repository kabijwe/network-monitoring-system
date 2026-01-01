"""
Management command to test the notification system.

This command creates test alerts and sends notifications through all configured channels
to verify that the notification system is working correctly.
"""
import uuid
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.utils import timezone
from monitoring.models import Location, DeviceGroup, Host, Alert, NotificationProfile
from monitoring.notification_service import notification_service
from monitoring.tasks.notification_tasks import send_alert_notification

User = get_user_model()


class Command(BaseCommand):
    help = 'Test the notification system by sending test alerts'

    def add_arguments(self, parser):
        parser.add_argument(
            '--channels',
            nargs='+',
            default=['email'],
            choices=['email', 'telegram', 'slack', 'teams', 'sms'],
            help='Notification channels to test'
        )
        parser.add_argument(
            '--recipient',
            type=str,
            help='Recipient address (email, phone, chat ID, etc.)'
        )
        parser.add_argument(
            '--severity',
            choices=['info', 'warning', 'critical'],
            default='warning',
            help='Alert severity to test'
        )
        parser.add_argument(
            '--profile',
            type=str,
            help='Notification profile name to use (optional)'
        )
        parser.add_argument(
            '--async',
            action='store_true',
            help='Send notifications asynchronously using Celery'
        )
        parser.add_argument(
            '--test-escalation',
            action='store_true',
            help='Test alert escalation functionality'
        )

    def handle(self, *args, **options):
        channels = options['channels']
        recipient = options['recipient']
        severity = options['severity']
        profile_name = options.get('profile')
        use_async = options['async']
        test_escalation = options['test_escalation']

        if test_escalation:
            self.test_escalation_system()
            return

        self.stdout.write(
            self.style.SUCCESS(f'Testing notification system with channels: {", ".join(channels)}')
        )

        try:
            # Create or get test data
            user = self.get_or_create_test_user()
            location = self.get_or_create_test_location(user)
            group = self.get_or_create_test_group(user)
            host = self.get_or_create_test_host(user, location, group)

            # Create test notification profile if needed
            if profile_name:
                profile = self.get_or_create_test_profile(profile_name, channels, recipient)
                profiles = [profile]
            else:
                profiles = self.create_test_profiles(channels, recipient)

            # Create a test alert
            alert, created = Alert.objects.get_or_create(
                host=host,
                title='Test Alert - Notification System',
                defaults={
                    'description': f'This is a test {severity} alert to verify notification delivery.',
                    'severity': severity,
                    'check_type': 'test',
                    'metric_name': 'test_metric',
                    'current_value': 100.0,
                    'threshold_value': 80.0,
                    'status': 'active'
                }
            )

            if not created:
                alert.severity = severity
                alert.description = f'This is a test {severity} alert to verify notification delivery.'
                alert.last_seen = timezone.now()
                alert.save()

            self.stdout.write(f'Created test alert: {alert.title}')

            # Send notifications
            if use_async:
                # Send asynchronously using Celery
                profile_ids = [str(p.id) for p in profiles]
                task = send_alert_notification.delay(str(alert.id), profile_ids)
                self.stdout.write(f'Queued notification task: {task.id}')
                self.stdout.write('Check Celery logs for delivery results.')
            else:
                # Send synchronously
                results = notification_service.send_alert_notification(alert, profiles)
                self.display_results(results)

            self.stdout.write(
                self.style.SUCCESS('Notification test completed successfully!')
            )

        except Exception as e:
            raise CommandError(f'Error testing notifications: {str(e)}')

    def get_or_create_test_user(self):
        """Get or create a test user."""
        user, created = User.objects.get_or_create(
            username='test_notification_user',
            defaults={
                'email': 'test@example.com',
                'first_name': 'Test',
                'last_name': 'User'
            }
        )
        if created:
            user.set_password('testpass123')
            user.save()
        return user

    def get_or_create_test_location(self, user):
        """Get or create a test location."""
        location, created = Location.objects.get_or_create(
            name='Test Location - Notifications',
            defaults={
                'description': 'Test location for notification testing',
                'created_by': user
            }
        )
        return location

    def get_or_create_test_group(self, user):
        """Get or create a test device group."""
        group, created = DeviceGroup.objects.get_or_create(
            name='Test Group - Notifications',
            defaults={
                'description': 'Test group for notification testing',
                'created_by': user
            }
        )
        return group

    def get_or_create_test_host(self, user, location, group):
        """Get or create a test host."""
        host, created = Host.objects.get_or_create(
            hostname='test-notification-host',
            ip_address='192.168.1.100',
            defaults={
                'device_name': 'Test Notification Host',
                'location': location,
                'group': group,
                'monitoring_enabled': True,
                'ping_enabled': True,
                'created_by': user
            }
        )
        return host

    def get_or_create_test_profile(self, name, channels, recipient):
        """Get or create a specific test notification profile."""
        user = self.get_or_create_test_user()
        profile, created = NotificationProfile.objects.get_or_create(
            name=name,
            defaults={
                'description': f'Test profile for {", ".join(channels)} notifications',
                'enabled': True,
                'min_severity': 'info',
                'created_by': user
            }
        )

        # Configure channels
        if 'email' in channels and recipient:
            profile.email_enabled = True
            profile.email_address = recipient
        if 'telegram' in channels and recipient:
            profile.telegram_enabled = True
            profile.telegram_chat_id = recipient
        if 'slack' in channels and recipient:
            profile.slack_enabled = True
            profile.slack_channel = recipient
        if 'teams' in channels and recipient:
            profile.teams_enabled = True
            profile.teams_webhook = recipient
        if 'sms' in channels and recipient:
            profile.sms_enabled = True
            profile.sms_number = recipient

        profile.save()
        return profile

    def create_test_profiles(self, channels, recipient):
        """Create test notification profiles for each channel."""
        profiles = []
        user = self.get_or_create_test_user()

        for channel in channels:
            profile_name = f'Test {channel.title()} Profile'
            
            profile, created = NotificationProfile.objects.get_or_create(
                name=profile_name,
                defaults={
                    'description': f'Test profile for {channel} notifications',
                    'enabled': True,
                    'min_severity': 'info',
                    'created_by': user
                }
            )

            # Configure the specific channel
            if channel == 'email':
                profile.email_enabled = True
                profile.email_address = recipient or 'test@example.com'
            elif channel == 'telegram':
                profile.telegram_enabled = True
                profile.telegram_chat_id = recipient or '123456789'
            elif channel == 'slack':
                profile.slack_enabled = True
                profile.slack_channel = recipient or '#test'
            elif channel == 'teams':
                profile.teams_enabled = True
                profile.teams_webhook = recipient or 'https://example.com/webhook'
            elif channel == 'sms':
                profile.sms_enabled = True
                profile.sms_number = recipient or '+1234567890'

            profile.save()
            profiles.append(profile)

        return profiles

    def display_results(self, results):
        """Display notification delivery results."""
        self.stdout.write('\n' + '='*50)
        self.stdout.write('NOTIFICATION DELIVERY RESULTS')
        self.stdout.write('='*50)

        for profile_name, profile_results in results.items():
            self.stdout.write(f'\nProfile: {profile_name}')
            self.stdout.write('-' * 30)

            for channel, result in profile_results.items():
                status = result.get('status', 'unknown')
                if status == 'sent':
                    self.stdout.write(
                        self.style.SUCCESS(f'  {channel}: ✓ SENT')
                    )
                elif status == 'failed':
                    self.stdout.write(
                        self.style.ERROR(f'  {channel}: ✗ FAILED')
                    )
                elif status == 'error':
                    error = result.get('error', 'Unknown error')
                    self.stdout.write(
                        self.style.ERROR(f'  {channel}: ✗ ERROR - {error}')
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'  {channel}: ? {status.upper()}')
                    )

                if 'log_id' in result:
                    self.stdout.write(f'    Log ID: {result["log_id"]}')

        self.stdout.write('\n' + '='*50)

    def test_escalation_system(self):
        """Test the alert escalation system."""
        from monitoring.escalation_service import escalation_service
        from monitoring.models import EscalationRule
        
        self.stdout.write(
            self.style.SUCCESS('Testing Alert Escalation System')
        )
        
        try:
            # Create test data
            user = self.get_or_create_test_user()
            location = self.get_or_create_test_location(user)
            group = self.get_or_create_test_group(user)
            host = self.get_or_create_test_host(user, location, group)
            
            # Create test notification profiles
            profiles = self.create_test_profiles(['email'], 'test@example.com')
            
            # Create test escalation rule
            rule_data = {
                'name': 'Test Escalation Rule',
                'condition_type': 'severity_based',
                'condition_config': {'severities': ['critical', 'warning']},
                'escalation_settings': {
                    'interval_minutes': 1,  # Short interval for testing
                    'max_level': 2,
                    'enabled': True,
                    'priority': 1,
                    'level_1_profiles': profiles,
                    'level_2_profiles': profiles
                }
            }
            
            rule = escalation_service.create_escalation_rule(
                name=rule_data['name'],
                condition_type=rule_data['condition_type'],
                condition_config=rule_data['condition_config'],
                escalation_settings=rule_data['escalation_settings'],
                user=user
            )
            
            self.stdout.write(f'Created escalation rule: {rule.name}')
            
            # Create test alert
            alert = Alert.objects.create(
                host=host,
                title='Test Escalation Alert',
                description='This is a test alert for escalation testing.',
                severity='critical',
                check_type='test',
                metric_name='test_metric',
                current_value=100.0,
                threshold_value=80.0,
                status='active'
            )
            
            self.stdout.write(f'Created test alert: {alert.title}')
            
            # Test escalation processing
            self.stdout.write('Testing escalation processing...')
            
            # Process escalation for the alert
            result = escalation_service.process_alert_escalation(alert)
            self.stdout.write(f'Escalation result: {result}')
            
            # Test acknowledgment
            self.stdout.write('Testing alert acknowledgment...')
            ack_result = escalation_service.acknowledge_alert(alert, user, 'Test acknowledgment')
            self.stdout.write(f'Acknowledgment result: {ack_result}')
            
            # Get escalation history
            history = escalation_service.get_escalation_history(alert)
            self.stdout.write(f'Escalation history: {history}')
            
            self.stdout.write(
                self.style.SUCCESS('Escalation system test completed successfully!')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error testing escalation system: {str(e)}')
            )
            raise