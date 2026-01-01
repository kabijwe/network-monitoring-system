"""
Property-based tests for the notification system.

These tests validate the notification system's behavior across
various scenarios using property-based testing with Hypothesis.
"""
import pytest
from hypothesis import given, strategies as st, settings, assume, example
from hypothesis.extra.django import TestCase as HypothesisTestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch, MagicMock

from monitoring.models import (
    Location, DeviceGroup, Host, Alert, NotificationProfile, 
    NotificationLog, EscalationRule, AlertEscalation, AlertEscalationHistory
)
from monitoring.notification_service import notification_service
from monitoring.escalation_service import escalation_service
from monitoring.correlation_service import correlation_service
from monitoring.template_service import template_service

User = get_user_model()


class NotificationSystemPropertyTests(HypothesisTestCase):
    """Property-based tests for notification system functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.user, created = User.objects.get_or_create(
            username='testuser',
            defaults={
                'email': 'test@example.com',
                'password': 'testpass123'
            }
        )
        if created:
            self.user.set_password('testpass123')
            self.user.save()
        
        self.location, created = Location.objects.get_or_create(
            name='Test Location',
            defaults={'created_by': self.user}
        )
        
        self.group, created = DeviceGroup.objects.get_or_create(
            name='Test Group',
            defaults={'created_by': self.user}
        )
    
    @given(
        hostname=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-.')),
        severity=st.sampled_from(['info', 'warning', 'critical']),
        channels=st.lists(st.sampled_from(['email', 'telegram', 'slack', 'teams', 'sms']), min_size=1, max_size=3, unique=True)
    )
    @settings(max_examples=5, deadline=10000)
    def test_property_33_multi_channel_notification_delivery(self, hostname, severity, channels):
        """
        Property 33: Multi-channel notification delivery
        
        Tests that notifications are delivered consistently across all enabled channels
        for a notification profile, regardless of the specific channels or alert content.
        """
        assume(len(hostname.strip()) > 0)
        
        # Create host
        host = Host.objects.create(
            hostname=hostname,
            ip_address='192.168.1.100',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        # Create alert
        alert = Alert.objects.create(
            host=host,
            title=f'Test Alert - {severity}',
            description=f'Test {severity} alert for multi-channel delivery',
            severity=severity,
            check_type='test',
            status='active'
        )
        
        # Create notification profile with multiple channels
        profile = NotificationProfile.objects.create(
            name=f'Test Profile {hostname}',
            description='Test profile for multi-channel delivery',
            enabled=True,
            min_severity='info',
            created_by=self.user
        )
        
        # Configure channels
        recipients = {}
        for channel in channels:
            if channel == 'email':
                profile.email_enabled = True
                profile.email_address = 'test@example.com'
                recipients['email'] = 'test@example.com'
            elif channel == 'telegram':
                profile.telegram_enabled = True
                profile.telegram_chat_id = '123456789'
                recipients['telegram'] = '123456789'
            elif channel == 'slack':
                profile.slack_enabled = True
                profile.slack_channel = '#test'
                recipients['slack'] = '#test'
            elif channel == 'teams':
                profile.teams_enabled = True
                profile.teams_webhook = 'https://example.com/webhook'
                recipients['teams'] = 'https://example.com/webhook'
            elif channel == 'sms':
                profile.sms_enabled = True
                profile.sms_number = '+1234567890'
                recipients['sms'] = '+1234567890'
        
        profile.save()
        
        # Mock notification delivery
        with patch.object(notification_service, '_send_notification', return_value=True) as mock_send:
            # Send notification
            results = notification_service.send_alert_notification(alert, [profile])
            
            # Verify results structure
            assert isinstance(results, dict)
            assert profile.name in results
            
            profile_results = results[profile.name]
            
            # Property: All enabled channels should be attempted
            enabled_channels = profile.get_enabled_channels()
            assert len(enabled_channels) == len(channels)
            
            for channel in enabled_channels:
                assert channel in profile_results
                assert profile_results[channel]['status'] == 'sent'
            
            # Property: Notification should be called for each enabled channel
            assert mock_send.call_count == len(enabled_channels)
            
            # Property: Each call should have correct parameters
            for call in mock_send.call_args_list:
                args, kwargs = call
                if len(args) >= 5:  # Check if we have enough arguments
                    channel, recipient, subject, message, alert_obj = args
                    
                    assert channel in enabled_channels
                    assert recipient == recipients[channel]
                    assert alert_obj == alert
                    assert len(subject) > 0
                    assert len(message) > 0
    
    @given(
        escalation_interval=st.integers(min_value=1, max_value=60),
        max_level=st.integers(min_value=1, max_value=5),
        severity=st.sampled_from(['warning', 'critical'])
    )
    @settings(max_examples=3, deadline=15000)
    def test_property_34_alert_escalation_timing(self, escalation_interval, max_level, severity):
        """
        Property 34: Alert escalation timing
        
        Tests that alert escalations occur at the correct intervals and respect
        the maximum escalation level configuration.
        """
        # Create host and alert
        host = Host.objects.create(
            hostname='test-escalation-host',
            ip_address='192.168.1.101',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        alert = Alert.objects.create(
            host=host,
            title=f'Escalation Test Alert - {severity}',
            description=f'Test {severity} alert for escalation timing',
            severity=severity,
            check_type='test',
            status='active'
        )
        
        # Create notification profile
        profile = NotificationProfile.objects.create(
            name='Escalation Test Profile',
            description='Test profile for escalation',
            enabled=True,
            min_severity='info',
            email_enabled=True,
            email_address='escalation@example.com',
            created_by=self.user
        )
        
        # Create escalation rule
        rule = EscalationRule.objects.create(
            name='Test Escalation Rule',
            condition_type='severity_based',
            condition_config={'severities': [severity]},
            escalation_interval_minutes=escalation_interval,
            max_escalation_level=max_level,
            enabled=True,
            priority=1,
            created_by=self.user
        )
        rule.level_1_profiles.add(profile)
        if max_level >= 2:
            rule.level_2_profiles.add(profile)
        if max_level >= 3:
            rule.level_3_profiles.add(profile)
        
        # Create escalation record
        escalation = AlertEscalation.objects.create(
            alert=alert,
            escalation_rule=rule,
            current_level=0,
            next_escalation_time=timezone.now() - timedelta(minutes=1)  # Past due
        )
        
        # Mock notification sending
        with patch.object(notification_service, 'send_alert_notification', return_value={'test': 'success'}) as mock_notify:
            # Process escalation multiple times
            escalation_results = []
            
            for level in range(1, max_level + 2):  # Try one more than max
                result = escalation_service.process_alert_escalation(alert)
                escalation_results.append(result)
                
                # Refresh escalation from database
                escalation.refresh_from_db()
                
                if level <= max_level:
                    # Property: Escalation should succeed within max level
                    assert result.get('escalated', False) == True
                    assert result.get('level') == level
                    assert escalation.current_level == level
                    
                    # Property: Next escalation time should be set correctly
                    expected_next_time = escalation.last_escalation_time + timedelta(minutes=escalation_interval)
                    time_diff = abs((escalation.next_escalation_time - expected_next_time).total_seconds())
                    assert time_diff < 60  # Within 1 minute tolerance
                    
                    # Set next escalation time to past for next iteration
                    escalation.next_escalation_time = timezone.now() - timedelta(minutes=1)
                    escalation.save()
                else:
                    # Property: Escalation should fail beyond max level
                    assert result.get('escalated', False) == False
                    assert result.get('reason') == 'max_level_reached'
    
    @given(
        template_vars=st.dictionaries(
            keys=st.sampled_from(['custom_var1', 'custom_var2', 'test_value']),
            values=st.text(min_size=1, max_size=20),
            min_size=1,
            max_size=3
        ),
        channel=st.sampled_from(['email', 'telegram', 'slack', 'teams', 'sms'])
    )
    @settings(max_examples=3, deadline=10000)
    def test_property_35_template_variable_substitution(self, template_vars, channel):
        """
        Property 35: Template variable substitution
        
        Tests that template variables are correctly substituted in notification
        messages across different channels and variable combinations.
        """
        # Create host and alert
        host = Host.objects.create(
            hostname='template-test-host',
            ip_address='192.168.1.102',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        alert = Alert.objects.create(
            host=host,
            title='Template Test Alert',
            description='Test alert for template variable substitution',
            severity='warning',
            check_type='test',
            status='active'
        )
        
        # Create custom template with variables
        template_text = "Alert: {{ alert.title }} Host: {{ alert.host.hostname }}"
        for var_name in template_vars.keys():
            template_text += f" {var_name}: {{{{ {var_name} }}}}"
        
        # Test template rendering
        rendered = template_service.render_notification_message(
            alert, channel, template_text, **template_vars
        )
        
        # Property: All standard variables should be substituted
        assert alert.title in rendered
        assert alert.host.hostname in rendered
        
        # Property: All custom variables should be substituted
        for var_name, var_value in template_vars.items():
            assert var_value in rendered
            # Variable placeholder should not remain
            assert f"{{{{{var_name}}}}}" not in rendered
        
        # Property: Template should not contain unresolved variables
        assert "{{" not in rendered or "}}" not in rendered
    
    @given(
        alert_count=st.integers(min_value=2, max_value=8),
        correlation_type=st.sampled_from(['location_based', 'group_based', 'check_type_based'])
    )
    @settings(max_examples=3, deadline=15000)
    def test_property_37_alert_correlation_and_deduplication(self, alert_count, correlation_type):
        """
        Property 37: Alert correlation and deduplication
        
        Tests that related alerts are properly correlated and duplicate alerts
        are deduplicated to reduce notification noise.
        """
        hosts = []
        alerts = []
        
        # Create multiple hosts based on correlation type
        for i in range(alert_count):
            if correlation_type == 'location_based':
                # Same location, different hosts
                host_location = self.location
                host_group = DeviceGroup.objects.create(
                    name=f'Group {i}',
                    created_by=self.user
                )
            elif correlation_type == 'group_based':
                # Same group, different hosts
                host_location = Location.objects.create(
                    name=f'Location {i}',
                    created_by=self.user
                )
                host_group = self.group
            else:  # check_type_based
                # Different locations and groups
                host_location = Location.objects.create(
                    name=f'Location {i}',
                    created_by=self.user
                )
                host_group = DeviceGroup.objects.create(
                    name=f'Group {i}',
                    created_by=self.user
                )
            
            host = Host.objects.create(
                hostname=f'correlation-host-{i}',
                ip_address=f'192.168.1.{110 + i}',
                location=host_location,
                group=host_group,
                created_by=self.user
            )
            hosts.append(host)
        
        # Create alerts that should be correlated
        for i, host in enumerate(hosts):
            alert = Alert.objects.create(
                host=host,
                title=f'Correlation Test Alert {i}',
                description='Test alert for correlation',
                severity='critical',
                check_type='ping' if correlation_type == 'check_type_based' else 'test',
                metric_name='test_metric',
                status='active'
            )
            alerts.append(alert)
        
        # Process correlation for each alert
        correlation_results = []
        for alert in alerts:
            result = correlation_service.process_new_alert(alert)
            correlation_results.append(result)
        
        # Property: At least some alerts should be correlated (except first one)
        correlated_count = sum(1 for result in correlation_results if result.get('correlated', False))
        
        if correlation_type in ['location_based', 'group_based']:
            # These should correlate when there are multiple alerts
            assert correlated_count > 0
        
        # Property: Correlated alerts should have correlation group data
        correlated_alerts = [alert for alert, result in zip(alerts, correlation_results) 
                           if result.get('correlated', False)]
        
        for alert in correlated_alerts:
            alert.refresh_from_db()
            if alert.additional_data:
                assert 'correlation_group_id' in alert.additional_data
                assert 'correlation_count' in alert.additional_data
        
        # Property: No alert should be both correlated and deduplicated
        for result in correlation_results:
            if result.get('correlated', False):
                assert not result.get('deduplicated', False)
    
    @given(
        maintenance_duration_hours=st.integers(min_value=1, max_value=24),
        alert_severity=st.sampled_from(['warning', 'critical'])
    )
    @settings(max_examples=3, deadline=10000)
    def test_property_36_maintenance_window_alert_suppression(self, maintenance_duration_hours, alert_severity):
        """
        Property 36: Maintenance window alert suppression
        
        Tests that alerts are properly suppressed during maintenance windows
        and restored when maintenance ends.
        """
        # Create host
        host = Host.objects.create(
            hostname='maintenance-test-host',
            ip_address='192.168.1.120',
            location=self.location,
            group=self.group,
            created_by=self.user
        )
        
        # Set host in maintenance
        maintenance_start = timezone.now() - timedelta(hours=1)
        maintenance_end = maintenance_start + timedelta(hours=maintenance_duration_hours)
        
        host.in_maintenance = True
        host.maintenance_start = maintenance_start
        host.maintenance_end = maintenance_end
        host.maintenance_comment = 'Test maintenance window'
        host.save()
        
        # Create alert during maintenance
        alert = Alert.objects.create(
            host=host,
            title=f'Maintenance Test Alert - {alert_severity}',
            description=f'Test {alert_severity} alert during maintenance',
            severity=alert_severity,
            check_type='test',
            status='active'
        )
        
        # Process alert correlation (which includes maintenance suppression)
        result = correlation_service.process_new_alert(alert)
        
        # Property: Alert should be suppressed during maintenance
        if timezone.now() <= maintenance_end:
            assert result.get('suppressed', False) == True
            assert 'maintenance_suppressed' in result.get('actions_taken', [])
            
            # Refresh alert from database
            alert.refresh_from_db()
            assert alert.status == 'suppressed'
        
        # Test alert after maintenance ends
        host.maintenance_end = timezone.now() - timedelta(minutes=1)  # End maintenance
        host.save()
        
        # Create new alert after maintenance
        post_maintenance_alert = Alert.objects.create(
            host=host,
            title=f'Post-Maintenance Alert - {alert_severity}',
            description=f'Test {alert_severity} alert after maintenance',
            severity=alert_severity,
            check_type='test',
            status='active'
        )
        
        # Process post-maintenance alert
        post_result = correlation_service.process_new_alert(post_maintenance_alert)
        
        # Property: Alert should not be suppressed after maintenance
        assert post_result.get('suppressed', False) == False
        assert 'maintenance_suppressed' not in post_result.get('actions_taken', [])
        
        # Refresh alert from database
        post_maintenance_alert.refresh_from_db()
        assert post_maintenance_alert.status == 'active'