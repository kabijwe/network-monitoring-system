"""
Management command to test the monitoring system components.

This command tests ping monitoring, SNMP collection, service checks,
and notification systems to ensure everything is working correctly.
"""

import asyncio
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import models
from monitoring.models import Host, Location, DeviceGroup
from monitoring.ping_monitor import ping_host_sync, PingResult as PingResultData, PingThresholds
from monitoring.snmp_monitor import collect_snmp_metrics, is_snmp_available
from monitoring.service_monitor import check_host_services
from monitoring.notification_service import test_notification_channel
from monitoring.tasks import (
    ping_monitoring_task, 
    snmp_monitoring_task, 
    service_monitoring_task,
    health_check_task
)


class Command(BaseCommand):
    help = 'Test network monitoring system components'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--ping',
            action='store_true',
            help='Test ping monitoring'
        )
        
        parser.add_argument(
            '--snmp',
            action='store_true',
            help='Test SNMP monitoring'
        )
        
        parser.add_argument(
            '--services',
            action='store_true',
            help='Test service monitoring'
        )
        
        parser.add_argument(
            '--notifications',
            action='store_true',
            help='Test notification channels'
        )
        
        parser.add_argument(
            '--tasks',
            action='store_true',
            help='Test Celery tasks'
        )
        
        parser.add_argument(
            '--all',
            action='store_true',
            help='Run all tests'
        )
        
        parser.add_argument(
            '--host',
            type=str,
            help='Test specific host by hostname or IP'
        )
        
        parser.add_argument(
            '--create-test-host',
            action='store_true',
            help='Create a test host for testing'
        )
    
    def handle(self, *args, **options):
        """Main command handler."""
        self.stdout.write(
            self.style.SUCCESS('🧪 Testing Network Monitoring System Components...')
        )
        
        # Create test host if requested
        if options['create_test_host']:
            test_host = self._create_test_host()
            self.stdout.write(
                self.style.SUCCESS(f'✅ Created test host: {test_host.hostname}')
            )
        
        # Get test host
        test_host = self._get_test_host(options.get('host'))
        if not test_host:
            self.stdout.write(
                self.style.ERROR('❌ No test host available. Use --create-test-host or specify --host')
            )
            return
        
        self.stdout.write(f'🎯 Using test host: {test_host.hostname} ({test_host.ip_address})')
        
        # Run tests based on options
        if options['all'] or options['ping']:
            self._test_ping_monitoring(test_host)
        
        if options['all'] or options['snmp']:
            self._test_snmp_monitoring(test_host)
        
        if options['all'] or options['services']:
            self._test_service_monitoring(test_host)
        
        if options['all'] or options['notifications']:
            self._test_notifications()
        
        if options['all'] or options['tasks']:
            self._test_celery_tasks(test_host)
        
        self.stdout.write(
            self.style.SUCCESS('\n✅ Testing completed!')
        )
    
    def _create_test_host(self):
        """Create a test host for monitoring."""
        # Create or get test location
        location, created = Location.objects.get_or_create(
            name='Test Location',
            defaults={
                'description': 'Test location for monitoring system testing',
                'address': 'Test Address'
            }
        )
        
        # Create or get test group
        group, created = DeviceGroup.objects.get_or_create(
            name='Test Group',
            defaults={
                'description': 'Test group for monitoring system testing',
                'color': '#28a745'
            }
        )
        
        # Create test host (using Google DNS as a reliable test target)
        host, created = Host.objects.get_or_create(
            hostname='google-dns-test',
            ip_address='8.8.8.8',
            defaults={
                'device_name': 'Google DNS Test Host',
                'device_type': 'server',
                'location': location,
                'group': group,
                'monitoring_enabled': True,
                'ping_enabled': True,
                'snmp_enabled': False,  # Google DNS doesn't support SNMP
                'service_checks_enabled': True,
                'tcp_ports': '53',  # DNS port
                'udp_ports': '53',  # DNS port
                'http_urls': 'https://dns.google',  # Google DNS over HTTPS
                'ping_timeout': 5,
                'ping_packet_count': 4
            }
        )
        
        return host
    
    def _get_test_host(self, hostname_or_ip=None):
        """Get a test host for monitoring."""
        if hostname_or_ip:
            try:
                return Host.objects.get(
                    models.Q(hostname=hostname_or_ip) | 
                    models.Q(ip_address=hostname_or_ip)
                )
            except Host.DoesNotExist:
                return None
        
        # Try to get the test host we created
        try:
            return Host.objects.get(hostname='google-dns-test')
        except Host.DoesNotExist:
            pass
        
        # Get any enabled host
        return Host.objects.filter(monitoring_enabled=True).first()
    
    def _test_ping_monitoring(self, host):
        """Test ping monitoring functionality."""
        self.stdout.write('\n🏓 Testing Ping Monitoring...')
        
        try:
            # Test direct ping function
            self.stdout.write(f'  Testing ping to {host.ip_address}...')
            
            result = ping_host_sync(
                host.hostname,
                host.ip_address,
                PingThresholds(
                    packet_count=host.ping_packet_count,
                    timeout=host.ping_timeout
                )
            )
            
            if result.success:
                self.stdout.write(
                    self.style.SUCCESS(
                        f'  ✅ Ping successful: {result.latency:.2f}ms, '
                        f'{result.packet_loss:.1f}% loss'
                    )
                )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f'  ⚠️  Ping failed: {result.error_message}'
                    )
                )
            
            # Show detailed results
            self.stdout.write(f'    Packets: {result.packets_sent} sent, {result.packets_received} received')
            if result.latency:
                self.stdout.write(f'    Latency: {result.latency:.2f}ms')
            self.stdout.write(f'    Packet Loss: {result.packet_loss:.1f}%')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Ping test failed: {e}')
            )
    
    def _test_snmp_monitoring(self, host):
        """Test SNMP monitoring functionality."""
        self.stdout.write('\n📊 Testing SNMP Monitoring...')
        
        if not is_snmp_available():
            self.stdout.write(
                self.style.WARNING('  ⚠️  SNMP not available (pysnmp not installed)')
            )
            return
        
        if not host.snmp_enabled:
            self.stdout.write(
                self.style.WARNING(f'  ⚠️  SNMP not enabled for host {host.hostname}')
            )
            return
        
        try:
            # Test SNMP collection
            self.stdout.write(f'  Testing SNMP collection from {host.ip_address}...')
            
            # Run async SNMP collection
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                results = loop.run_until_complete(
                    collect_snmp_metrics(host, ['system'])
                )
            finally:
                loop.close()
            
            # Display results
            for collector_name, result in results.items():
                if result.success:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'  ✅ {collector_name}: {len(result.metrics)} metrics collected'
                        )
                    )
                    
                    # Show some sample metrics
                    for metric_name, value in list(result.metrics.items())[:3]:
                        self.stdout.write(f'    {metric_name}: {value}')
                    
                    if len(result.metrics) > 3:
                        self.stdout.write(f'    ... and {len(result.metrics) - 3} more metrics')
                else:
                    self.stdout.write(
                        self.style.WARNING(
                            f'  ⚠️  {collector_name}: {result.error_message}'
                        )
                    )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ SNMP test failed: {e}')
            )
    
    def _test_service_monitoring(self, host):
        """Test service monitoring functionality."""
        self.stdout.write('\n🔧 Testing Service Monitoring...')
        
        if not host.service_checks_enabled:
            self.stdout.write(
                self.style.WARNING(f'  ⚠️  Service checks not enabled for host {host.hostname}')
            )
            return
        
        try:
            # Test service checks
            self.stdout.write(f'  Testing service checks for {host.ip_address}...')
            
            # Run async service checks
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                results = loop.run_until_complete(
                    check_host_services(host)
                )
            finally:
                loop.close()
            
            # Display results
            for service_type, service_results in results.items():
                self.stdout.write(f'  {service_type.upper()} Services:')
                
                for result in service_results:
                    status_icon = '✅' if result.success else '❌'
                    self.stdout.write(
                        f'    {status_icon} Response time: {result.response_time:.2f}ms'
                    )
                    
                    if not result.success:
                        self.stdout.write(f'      Error: {result.error_message}')
                    
                    if result.additional_data:
                        for key, value in result.additional_data.items():
                            if key not in ['service_type', 'service_name']:
                                self.stdout.write(f'      {key}: {value}')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Service monitoring test failed: {e}')
            )
    
    def _test_notifications(self):
        """Test notification channels."""
        self.stdout.write('\n📧 Testing Notification Channels...')
        
        # Test email notifications
        try:
            success = test_notification_channel('email', 'bikram.niroula@worldlink.com.np')
            status_icon = '✅' if success else '❌'
            self.stdout.write(f'  {status_icon} Email: {"Success" if success else "Failed"}')
        except Exception as e:
            self.stdout.write(f'  ❌ Email: Error - {e}')
        
        # Test Telegram notifications
        try:
            success = test_notification_channel('telegram', '7238208371')
            status_icon = '✅' if success else '❌'
            self.stdout.write(f'  {status_icon} Telegram: {"Success" if success else "Failed"}')
        except Exception as e:
            self.stdout.write(f'  ❌ Telegram: Error - {e}')
        
        # Test other channels (will likely fail without configuration)
        for channel in ['slack', 'teams', 'sms']:
            try:
                success = test_notification_channel(channel, 'test_recipient')
                status_icon = '✅' if success else '❌'
                self.stdout.write(f'  {status_icon} {channel.title()}: {"Success" if success else "Not configured"}')
            except Exception as e:
                self.stdout.write(f'  ❌ {channel.title()}: Not configured')
    
    def _test_celery_tasks(self, host):
        """Test Celery task execution."""
        self.stdout.write('\n⚙️  Testing Celery Tasks...')
        
        try:
            # Test health check task
            self.stdout.write('  Testing health check task...')
            result = health_check_task.delay()
            
            # Wait for result with timeout
            try:
                health_data = result.get(timeout=30)
                self.stdout.write(
                    self.style.SUCCESS(f'  ✅ Health check: {health_data.get("overall_health", "Unknown")}')
                )
                
                # Show health details
                for key, value in health_data.items():
                    if key not in ['overall_health', 'timestamp']:
                        self.stdout.write(f'    {key}: {value}')
                        
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Health check task failed: {e}')
                )
            
            # Test ping monitoring task
            self.stdout.write('  Testing ping monitoring task...')
            result = ping_monitoring_task.delay(str(host.id))
            
            try:
                ping_data = result.get(timeout=30)
                status_icon = '✅' if ping_data.get('status') == 'success' else '❌'
                self.stdout.write(
                    f'  {status_icon} Ping task: {ping_data.get("status", "Unknown")}'
                )
                
                if 'result' in ping_data:
                    ping_result = ping_data['result']
                    self.stdout.write(
                        f'    Latency: {ping_result.get("latency", "N/A")}ms, '
                        f'Loss: {ping_result.get("packet_loss", "N/A")}%'
                    )
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Ping task failed: {e}')
                )
            
            # Test service monitoring task if enabled
            if host.service_checks_enabled:
                self.stdout.write('  Testing service monitoring task...')
                result = service_monitoring_task.delay(str(host.id))
                
                try:
                    service_data = result.get(timeout=30)
                    status_icon = '✅' if service_data.get('status') == 'success' else '❌'
                    self.stdout.write(
                        f'  {status_icon} Service task: {service_data.get("status", "Unknown")}'
                    )
                    
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f'  ❌ Service task failed: {e}')
                    )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Celery task testing failed: {e}')
            )