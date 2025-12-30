"""
Multi-channel notification service for the network monitoring system.

This service handles sending notifications through various channels including
Email, Telegram, Slack, Teams, and SMS for alert notifications and escalations.
"""
import logging
import smtplib
import json
import requests
from typing import List, Dict, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from django.conf import settings
from django.template import Template, Context
from django.utils import timezone
from django.db import transaction
from .models import Alert, Host
from core.models import User

logger = logging.getLogger(__name__)


class NotificationChannel:
    """Base class for notification channels."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the notification channel with configuration."""
        self.config = config
        self.enabled = config.get('enabled', False)
    
    def send(self, recipient: str, subject: str, message: str, 
             alert: Alert = None, **kwargs) -> bool:
        """Send notification through this channel."""
        raise NotImplementedError("Subclasses must implement send method")
    
    def validate_config(self) -> bool:
        """Validate the channel configuration."""
        return True
    
    def format_message(self, template: str, context: Dict[str, Any]) -> str:
        """Format message using Django template system."""
        try:
            django_template = Template(template)
            return django_template.render(Context(context))
        except Exception as e:
            logger.error(f"Error formatting message template: {e}")
            return template


class EmailNotificationChannel(NotificationChannel):
    """Email notification channel using SMTP."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.smtp_host = config.get('smtp_host', 'localhost')
        self.smtp_port = config.get('smtp_port', 587)
        self.smtp_username = config.get('smtp_username', '')
        self.smtp_password = config.get('smtp_password', '')
        self.smtp_use_tls = config.get('smtp_use_tls', True)
        self.from_email = config.get('from_email', 'nms@example.com')
        self.from_name = config.get('from_name', 'Network Monitoring System')
    
    def validate_config(self) -> bool:
        """Validate SMTP configuration."""
        required_fields = ['smtp_host', 'from_email']
        return all(self.config.get(field) for field in required_fields)
    
    def send(self, recipient: str, subject: str, message: str, 
             alert: Alert = None, **kwargs) -> bool:
        """Send email notification."""
        if not self.enabled or not self.validate_config():
            logger.warning("Email notifications disabled or misconfigured")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = recipient
            
            # Create HTML and text versions
            text_part = MIMEText(message, 'plain', 'utf-8')
            html_message = self._create_html_message(message, alert)
            html_part = MIMEText(html_message, 'html', 'utf-8')
            
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()
                
                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)
                
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {recipient}: {e}")
            return False
    
    def _create_html_message(self, message: str, alert: Alert = None) -> str:
        """Create HTML version of the email message."""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Network Monitoring Alert</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .alert-critical { border-left: 5px solid #dc3545; padding-left: 15px; }
                .alert-warning { border-left: 5px solid #ffc107; padding-left: 15px; }
                .alert-info { border-left: 5px solid #17a2b8; padding-left: 15px; }
                .alert-details { background-color: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; }
                .timestamp { color: #6c757d; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <div class="alert-{{ severity }}">
                <h2>{{ title }}</h2>
                <p>{{ message }}</p>
                
                {% if alert %}
                <div class="alert-details">
                    <h3>Alert Details</h3>
                    <p><strong>Host:</strong> {{ alert.host.hostname }} ({{ alert.host.ip_address }})</p>
                    <p><strong>Location:</strong> {{ alert.host.location.name }}</p>
                    <p><strong>Group:</strong> {{ alert.host.group.name }}</p>
                    <p><strong>Check Type:</strong> {{ alert.check_type }}</p>
                    <p><strong>Severity:</strong> {{ alert.severity|upper }}</p>
                    <p><strong>First Seen:</strong> {{ alert.first_seen }}</p>
                    {% if alert.current_value %}
                    <p><strong>Current Value:</strong> {{ alert.current_value }}</p>
                    {% endif %}
                    {% if alert.threshold_value %}
                    <p><strong>Threshold:</strong> {{ alert.threshold_value }}</p>
                    {% endif %}
                </div>
                {% endif %}
                
                <p class="timestamp">Sent at {{ timestamp }}</p>
            </div>
        </body>
        </html>
        """
        
        context = {
            'message': message,
            'alert': alert,
            'severity': alert.severity if alert else 'info',
            'title': alert.title if alert else 'Network Monitoring Notification',
            'timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        }
        
        return self.format_message(html_template, context)


class TelegramNotificationChannel(NotificationChannel):
    """Telegram notification channel using Bot API."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.bot_token = config.get('bot_token', '')
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}"
    
    def validate_config(self) -> bool:
        """Validate Telegram configuration."""
        return bool(self.bot_token)
    
    def send(self, recipient: str, subject: str, message: str, 
             alert: Alert = None, **kwargs) -> bool:
        """Send Telegram notification."""
        if not self.enabled or not self.validate_config():
            logger.warning("Telegram notifications disabled or misconfigured")
            return False
        
        try:
            # Format message for Telegram
            telegram_message = self._format_telegram_message(subject, message, alert)
            
            # Send message
            url = f"{self.api_url}/sendMessage"
            payload = {
                'chat_id': recipient,
                'text': telegram_message,
                'parse_mode': 'Markdown',
                'disable_web_page_preview': True
            }
            
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Telegram message sent successfully to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Telegram message to {recipient}: {e}")
            return False
    
    def _format_telegram_message(self, subject: str, message: str, alert: Alert = None) -> str:
        """Format message for Telegram with Markdown."""
        lines = [f"🚨 *{subject}*", "", message]
        
        if alert:
            lines.extend([
                "",
                "*Alert Details:*",
                f"• Host: `{alert.host.hostname}` ({alert.host.ip_address})",
                f"• Location: {alert.host.location.name}",
                f"• Severity: {alert.severity.upper()}",
                f"• Check: {alert.check_type}",
                f"• Time: {alert.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            ])
            
            if alert.current_value:
                lines.append(f"• Current Value: {alert.current_value}")
            
            if alert.threshold_value:
                lines.append(f"• Threshold: {alert.threshold_value}")
        
        return "\n".join(lines)


class SlackNotificationChannel(NotificationChannel):
    """Slack notification channel using webhooks."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get('webhook_url', '')
        self.channel = config.get('channel', '#alerts')
        self.username = config.get('username', 'NMS Bot')
        self.icon_emoji = config.get('icon_emoji', ':warning:')
    
    def validate_config(self) -> bool:
        """Validate Slack configuration."""
        return bool(self.webhook_url)
    
    def send(self, recipient: str, subject: str, message: str, 
             alert: Alert = None, **kwargs) -> bool:
        """Send Slack notification."""
        if not self.enabled or not self.validate_config():
            logger.warning("Slack notifications disabled or misconfigured")
            return False
        
        try:
            # Create Slack message payload
            payload = self._create_slack_payload(subject, message, alert, recipient)
            
            # Send webhook
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Slack message sent successfully to {recipient or self.channel}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack message: {e}")
            return False
    
    def _create_slack_payload(self, subject: str, message: str, alert: Alert = None, channel: str = None) -> Dict[str, Any]:
        """Create Slack message payload with rich formatting."""
        # Determine color based on alert severity
        color_map = {
            'critical': 'danger',
            'warning': 'warning',
            'info': 'good'
        }
        
        severity = alert.severity if alert else 'info'
        color = color_map.get(severity, 'warning')
        
        # Create attachment
        attachment = {
            'color': color,
            'title': subject,
            'text': message,
            'ts': int(timezone.now().timestamp())
        }
        
        # Add alert details as fields
        if alert:
            attachment['fields'] = [
                {'title': 'Host', 'value': f"{alert.host.hostname} ({alert.host.ip_address})", 'short': True},
                {'title': 'Location', 'value': alert.host.location.name, 'short': True},
                {'title': 'Severity', 'value': alert.severity.upper(), 'short': True},
                {'title': 'Check Type', 'value': alert.check_type, 'short': True}
            ]
            
            if alert.current_value:
                attachment['fields'].append({
                    'title': 'Current Value', 
                    'value': str(alert.current_value), 
                    'short': True
                })
            
            if alert.threshold_value:
                attachment['fields'].append({
                    'title': 'Threshold', 
                    'value': str(alert.threshold_value), 
                    'short': True
                })
        
        return {
            'channel': channel or self.channel,
            'username': self.username,
            'icon_emoji': self.icon_emoji,
            'attachments': [attachment]
        }


class TeamsNotificationChannel(NotificationChannel):
    """Microsoft Teams notification channel using webhooks."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get('webhook_url', '')
    
    def validate_config(self) -> bool:
        """Validate Teams configuration."""
        return bool(self.webhook_url)
    
    def send(self, recipient: str, subject: str, message: str, 
             alert: Alert = None, **kwargs) -> bool:
        """Send Teams notification."""
        if not self.enabled or not self.validate_config():
            logger.warning("Teams notifications disabled or misconfigured")
            return False
        
        try:
            # Create Teams message payload
            payload = self._create_teams_payload(subject, message, alert)
            
            # Send webhook
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info("Teams message sent successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Teams message: {e}")
            return False
    
    def _create_teams_payload(self, subject: str, message: str, alert: Alert = None) -> Dict[str, Any]:
        """Create Teams message payload with adaptive cards."""
        # Determine theme color based on severity
        color_map = {
            'critical': 'attention',
            'warning': 'warning',
            'info': 'good'
        }
        
        severity = alert.severity if alert else 'info'
        theme_color = color_map.get(severity, 'warning')
        
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": subject,
            "sections": [
                {
                    "activityTitle": subject,
                    "activitySubtitle": message,
                    "markdown": True
                }
            ]
        }
        
        # Add alert details as facts
        if alert:
            facts = [
                {"name": "Host", "value": f"{alert.host.hostname} ({alert.host.ip_address})"},
                {"name": "Location", "value": alert.host.location.name},
                {"name": "Severity", "value": alert.severity.upper()},
                {"name": "Check Type", "value": alert.check_type},
                {"name": "Time", "value": alert.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}
            ]
            
            if alert.current_value:
                facts.append({"name": "Current Value", "value": str(alert.current_value)})
            
            if alert.threshold_value:
                facts.append({"name": "Threshold", "value": str(alert.threshold_value)})
            
            payload["sections"][0]["facts"] = facts
        
        return payload


class SMSNotificationChannel(NotificationChannel):
    """SMS notification channel using Twilio."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.account_sid = config.get('account_sid', '')
        self.auth_token = config.get('auth_token', '')
        self.from_number = config.get('from_number', '')
    
    def validate_config(self) -> bool:
        """Validate Twilio configuration."""
        required_fields = ['account_sid', 'auth_token', 'from_number']
        return all(self.config.get(field) for field in required_fields)
    
    def send(self, recipient: str, subject: str, message: str, 
             alert: Alert = None, **kwargs) -> bool:
        """Send SMS notification."""
        if not self.enabled or not self.validate_config():
            logger.warning("SMS notifications disabled or misconfigured")
            return False
        
        try:
            # Import Twilio client (optional dependency)
            from twilio.rest import Client
            
            # Create SMS message (keep it short)
            sms_message = self._format_sms_message(subject, message, alert)
            
            # Send SMS
            client = Client(self.account_sid, self.auth_token)
            message = client.messages.create(
                body=sms_message,
                from_=self.from_number,
                to=recipient
            )
            
            logger.info(f"SMS sent successfully to {recipient}, SID: {message.sid}")
            return True
            
        except ImportError:
            logger.error("Twilio library not installed. Install with: pip install twilio")
            return False
        except Exception as e:
            logger.error(f"Failed to send SMS to {recipient}: {e}")
            return False
    
    def _format_sms_message(self, subject: str, message: str, alert: Alert = None) -> str:
        """Format message for SMS (keep it short)."""
        lines = [subject]
        
        if alert:
            lines.append(f"Host: {alert.host.hostname}")
            lines.append(f"Status: {alert.severity.upper()}")
            lines.append(f"Time: {alert.first_seen.strftime('%H:%M')}")
        
        # Keep SMS under 160 characters if possible
        sms_text = "\n".join(lines)
        if len(sms_text) > 160:
            # Truncate message
            sms_text = sms_text[:157] + "..."
        
        return sms_text


class NotificationService:
    """Main notification service that manages all notification channels."""
    
    def __init__(self):
        """Initialize the notification service with configured channels."""
        self.channels = {}
        self._initialize_channels()
    
    def _initialize_channels(self):
        """Initialize all notification channels from Django settings."""
        notification_settings = getattr(settings, 'NOTIFICATION_SETTINGS', {})
        
        # Initialize Email channel
        email_config = notification_settings.get('email', {})
        self.channels['email'] = EmailNotificationChannel(email_config)
        
        # Initialize Telegram channel
        telegram_config = notification_settings.get('telegram', {})
        self.channels['telegram'] = TelegramNotificationChannel(telegram_config)
        
        # Initialize Slack channel
        slack_config = notification_settings.get('slack', {})
        self.channels['slack'] = SlackNotificationChannel(slack_config)
        
        # Initialize Teams channel
        teams_config = notification_settings.get('teams', {})
        self.channels['teams'] = TeamsNotificationChannel(teams_config)
        
        # Initialize SMS channel
        sms_config = notification_settings.get('sms', {})
        self.channels['sms'] = SMSNotificationChannel(sms_config)
        
        logger.info(f"Initialized {len(self.channels)} notification channels")
    
    def send_notification(self, channels: List[str], recipients: Dict[str, str], 
                         subject: str, message: str, alert: Alert = None,
                         template_context: Dict[str, Any] = None) -> Dict[str, bool]:
        """
        Send notification through specified channels.
        
        Args:
            channels: List of channel names to use
            recipients: Dict mapping channel names to recipient addresses
            subject: Notification subject
            message: Notification message
            alert: Optional Alert instance for additional context
            template_context: Optional context for message templating
            
        Returns:
            Dict mapping channel names to success status
        """
        results = {}
        
        # Apply template context if provided
        if template_context:
            subject = self._apply_template_context(subject, template_context)
            message = self._apply_template_context(message, template_context)
        
        for channel_name in channels:
            if channel_name not in self.channels:
                logger.warning(f"Unknown notification channel: {channel_name}")
                results[channel_name] = False
                continue
            
            channel = self.channels[channel_name]
            recipient = recipients.get(channel_name)
            
            if not recipient:
                logger.warning(f"No recipient specified for channel: {channel_name}")
                results[channel_name] = False
                continue
            
            try:
                success = channel.send(recipient, subject, message, alert)
                results[channel_name] = success
                
                if success:
                    logger.info(f"Notification sent successfully via {channel_name} to {recipient}")
                else:
                    logger.warning(f"Failed to send notification via {channel_name} to {recipient}")
                    
            except Exception as e:
                logger.error(f"Error sending notification via {channel_name}: {e}")
                results[channel_name] = False
        
        return results
    
    def send_alert_notification(self, alert: Alert, escalation_level: int = 0) -> Dict[str, bool]:
        """
        Send notification for an alert with appropriate recipients and channels.
        
        Args:
            alert: Alert instance to notify about
            escalation_level: Escalation level (0 = initial, 1+ = escalated)
            
        Returns:
            Dict mapping channel names to success status
        """
        # Get notification preferences for the alert
        notification_config = self._get_alert_notification_config(alert, escalation_level)
        
        # Create notification content
        subject = self._create_alert_subject(alert, escalation_level)
        message = self._create_alert_message(alert, escalation_level)
        
        # Send notifications
        return self.send_notification(
            channels=notification_config['channels'],
            recipients=notification_config['recipients'],
            subject=subject,
            message=message,
            alert=alert
        )
    
    def _get_alert_notification_config(self, alert: Alert, escalation_level: int) -> Dict[str, Any]:
        """Get notification configuration for an alert based on escalation level."""
        # This would typically be configured per user/group/location
        # For now, using default configuration with user's contact info
        
        base_channels = ['email']
        recipients = {'email': 'bikram.niroula@worldlink.com.np'}
        
        # Add more channels for higher escalation levels
        if escalation_level >= 1:
            base_channels.extend(['telegram'])
            recipients.update({
                'telegram': '7238208371'  # User's correct chat ID
            })
        
        if escalation_level >= 2:
            base_channels.extend(['slack', 'teams'])
            recipients.update({
                'slack': '#critical-alerts',
                'teams': 'teams_webhook'
            })
        
        if escalation_level >= 3:
            base_channels.extend(['sms'])
            recipients.update({
                'sms': '+9779842478259'  # Full international format for SMS
            })
        
        return {
            'channels': base_channels,
            'recipients': recipients
        }
    
    def _create_alert_subject(self, alert: Alert, escalation_level: int) -> str:
        """Create alert notification subject."""
        escalation_prefix = f"[ESCALATED L{escalation_level}] " if escalation_level > 0 else ""
        severity_prefix = f"[{alert.severity.upper()}] "
        
        return f"{escalation_prefix}{severity_prefix}{alert.title}"
    
    def _create_alert_message(self, alert: Alert, escalation_level: int) -> str:
        """Create alert notification message."""
        lines = [
            alert.description,
            "",
            f"Host: {alert.host.hostname} ({alert.host.ip_address})",
            f"Location: {alert.host.location.name}",
            f"Group: {alert.host.group.name}",
            f"Check Type: {alert.check_type}",
            f"Severity: {alert.severity.upper()}",
            f"First Seen: {alert.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Last Seen: {alert.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        ]
        
        if alert.current_value is not None:
            lines.append(f"Current Value: {alert.current_value}")
        
        if alert.threshold_value is not None:
            lines.append(f"Threshold: {alert.threshold_value}")
        
        if escalation_level > 0:
            lines.extend([
                "",
                f"This alert has been escalated to level {escalation_level}.",
                f"Last escalated: {alert.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            ])
        
        return "\n".join(lines)
    
    def _apply_template_context(self, text: str, context: Dict[str, Any]) -> str:
        """Apply template context to text using Django template system."""
        try:
            template = Template(text)
            return template.render(Context(context))
        except Exception as e:
            logger.error(f"Error applying template context: {e}")
            return text
    
    def test_channel(self, channel_name: str, recipient: str) -> bool:
        """Test a notification channel with a test message."""
        if channel_name not in self.channels:
            logger.error(f"Unknown notification channel: {channel_name}")
            return False
        
        channel = self.channels[channel_name]
        
        test_subject = "NMS Notification Test"
        test_message = f"This is a test notification from the Network Monitoring System.\nChannel: {channel_name}\nTime: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
        
        return channel.send(recipient, test_subject, test_message)
    
    def get_channel_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all notification channels."""
        status = {}
        
        for name, channel in self.channels.items():
            status[name] = {
                'enabled': channel.enabled,
                'configured': channel.validate_config(),
                'type': channel.__class__.__name__
            }
        
        return status


# Convenience functions for easy access
def send_alert_notification(alert: Alert, escalation_level: int = 0) -> Dict[str, bool]:
    """Send notification for an alert."""
    service = NotificationService()
    return service.send_alert_notification(alert, escalation_level)


def test_notification_channel(channel_name: str, recipient: str) -> bool:
    """Test a notification channel."""
    service = NotificationService()
    return service.test_channel(channel_name, recipient)


def get_notification_status() -> Dict[str, Dict[str, Any]]:
    """Get status of all notification channels."""
    service = NotificationService()
    return service.get_channel_status()