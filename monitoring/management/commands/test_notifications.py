"""
Management command to test the notification system.
"""
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from monitoring.models import Host, Alert, NotificationProfile
from monitoring.notification_service import NotificationService, test_notification_channel

User = get_user_model()


class Command(BaseCommand):
    help = 'Test the notification system with various channels'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--channel',
            type=str,
            choices=['email', 'telegram', 'slack', 'teams', 'sms', 'all'],
            default='all',
            help='Notification channel to test'
        )
        
        parser.add_argument(
            '--recipient',
            type=str,
            help='Recipient address for the test notification'
        )
        
        parser.add_argument(
            '--create-alert',
            action='store_true',
            help='Create a test alert and send notification'
        )
        
        parser.add_argument(
            '--list-channels',
            action='store_true',
            help='List all available notification channels and their status'
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        
        if options['list_channels']:
            self.list_channels()
            return
        
        channel = options['channel']
        recipient = options['recipient']
        
        if options['create_alert']:
            self.test_alert_notification()
        elif channel == 'all':
            self.test_all_channels()
        else:
            if not recipient:
                raise CommandError(f"Recipient is required for testing {channel} channel")
            self.test_single_channel(channel, recipient)
    
    def list_channels(self):
        """List all notification channels and their status."""
        self.stdout.write(self.style.SUCCESS("Notification Channel Status:"))
        self.stdout.write("-" * 50)
        
        try:
            from monitoring.notification_service import get_notification_status
            status_info = get_notification_status()
            
            for channel, info in status_info.items():
                status_color = self.style.SUCCESS if info['enabled'] and info['configured'] else self.style.ERROR
                status_text = "✓ Enabled & Configured" if info['enabled'] and info['configured'] else "✗ Disabled or Misconfigured"
                
                self.stdout.write(f"{channel.upper():<12}: {status_color(status_text)}")
                self.stdout.write(f"             Type: {info['type']}")
                self.stdout.write(f"             Enabled: {info['enabled']}")
                self.stdout.write(f"             Configured: {info['configured']}")
                self.stdout.write("")
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error getting channel status: {e}"))
    
    def test_single_channel(self, channel, recipient):
        """Test a single notification channel."""
        self.stdout.write(f"Testing {channel} notification to {recipient}...")
        
        try:
            success = test_notification_channel(channel, recipient)
            
            if success:
                self.stdout.write(
                    self.style.SUCCESS(f"✓ {channel} notification sent successfully!")
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f"✗ Failed to send {channel} notification")
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Error testing {channel}: {e}")
            )
    
    def test_all_channels(self):
        """Test all configured notification channels."""
        self.stdout.write("Testing all configured notification channels...")
        self.stdout.write("-" * 50)
        
        # Default test recipients for each channel using user's contact info
        test_recipients = {
            'email': 'bikram.niroula@worldlink.com.np',
            'telegram': '9842478259',
            'slack': '#test-channel',
            'teams': 'teams_webhook',
            'sms': '+9779842478259'
        }
        
        try:
            from monitoring.notification_service import get_notification_status
            status_info = get_notification_status()
            
            for channel, info in status_info.items():
                if info['enabled'] and info['configured']:
                    recipient = test_recipients.get(channel, 'test_recipient')
                    self.stdout.write(f"Testing {channel}...")
                    
                    try:
                        success = test_notification_channel(channel, recipient)
                        
                        if success:
                            self.stdout.write(
                                self.style.SUCCESS(f"  ✓ {channel} test successful")
                            )
                        else:
                            self.stdout.write(
                                self.style.WARNING(f"  ✗ {channel} test failed")
                            )
                    except Exception as e:
                        self.stdout.write(
                            self.style.ERROR(f"  ✗ {channel} error: {e}")
                        )
                else:
                    self.stdout.write(
                        self.style.WARNING(f"  - {channel} skipped (disabled or not configured)")
                    )
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Error testing channels: {e}")
            )
    
    def test_alert_notification(self):
        """Create a test alert and send notifications."""
        self.stdout.write("Creating test alert and sending notifications...")
        
        try:
            # Get or create a test host
            host, created = Host.objects.get_or_create(
                hostname='test-host',
                ip_address='192.168.1.100',
                defaults={
                    'device_name': 'Test Host for Notifications',
                    'device_type': 'other',
                    'location': self._get_or_create_test_location(),
                    'group': self._get_or_create_test_group(),
                    'status': 'down'
                }
            )
            
            if created:
                self.stdout.write("Created test host: test-host (192.168.1.100)")
            
            # Create a test alert
            alert, created = Alert.objects.get_or_create(
                host=host,
                title='Test Alert - Notification System',
                defaults={
                    'description': 'This is a test alert generated to verify the notification system is working correctly.',
                    'severity': 'critical',
                    'status': 'active',
                    'check_type': 'ping',
                    'metric_name': 'ping_status',
                    'current_value': 100.0,
                    'threshold_value': 50.0
                }
            )
            
            if created:
                self.stdout.write(f"Created test alert: {alert.title}")
            
            # Send notification
            from monitoring.notification_service import send_alert_notification
            results = send_alert_notification(alert, escalation_level=0)
            
            self.stdout.write("Notification Results:")
            for channel, success in results.items():
                status_color = self.style.SUCCESS if success else self.style.ERROR
                status_text = "✓ Sent" if success else "✗ Failed"
                self.stdout.write(f"  {channel:<12}: {status_color(status_text)}")
            
            # Clean up test data
            if created:
                alert.delete()
                self.stdout.write("Cleaned up test alert")
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Error creating test alert: {e}")
            )
    
    def _get_or_create_test_location(self):
        """Get or create a test location."""
        from monitoring.models import Location
        
        location, created = Location.objects.get_or_create(
            name='Test Location',
            defaults={
                'description': 'Test location for notification testing',
                'address': 'Test Address'
            }
        )
        return location
    
    def _get_or_create_test_group(self):
        """Get or create a test device group."""
        from monitoring.models import DeviceGroup
        
        group, created = DeviceGroup.objects.get_or_create(
            name='Test Group',
            defaults={
                'description': 'Test device group for notification testing'
            }
        )
        return group