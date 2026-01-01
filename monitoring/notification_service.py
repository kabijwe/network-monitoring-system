"""
Multi-channel notification service for alert delivery.

This module provides notification delivery across multiple channels:
- Email (SMTP)
- Telegram Bot API
- Slack Webhooks
- Microsoft Teams Webhooks
- SMS (Twilio)
"""
import logging
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
from django.conf import settings
from django.template import Template, Context
from django.utils import timezone
from .models import NotificationProfile, NotificationLog, Alert

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for delivering notifications across multiple channels."""
    
    def __init__(self):
        self.smtp_config = getattr(settings, 'SMTP_CONFIG', {})
        self.telegram_config = getattr(settings, 'TELEGRAM_CONFIG', {})
        self.slack_config = getattr(settings, 'SLACK_CONFIG', {})
        self.teams_config = getattr(settings, 'TEAMS_CONFIG', {})
        self.twilio_config = getattr(settings, 'TWILIO_CONFIG', {})
    
    def send_alert_notification(self, alert: Alert, profiles: List[NotificationProfile]) -> Dict[str, Any]:
        """
        Send alert notification to all specified profiles.
        
        Args:
            alert: Alert instance to send
            profiles: List of notification profiles to send to
            
        Returns:
            Dictionary with delivery results per profile
        """
        results = {}
        
        for profile in profiles:
            if not profile.should_notify(alert):
                logger.debug(f"Skipping notification for profile {profile.name} - conditions not met")
                continue
            
            profile_results = {}
            channels = profile.get_enabled_channels()
            recipients = profile.get_recipients()
            
            for channel in channels:
                if channel not in recipients:
                    continue
                
                try:
                    # Create notification log entry
                    notification_log = NotificationLog.objects.create(
                        alert=alert,
                        profile=profile,
                        channel=channel,
                        recipient=recipients[channel],
                        subject=self._generate_subject(alert),
                        message=self._generate_message(alert, channel),
                        status='pending'
                    )
                    
                    # Send notification
                    success = self._send_notification(
                        channel=channel,
                        recipient=recipients[channel],
                        subject=notification_log.subject,
                        message=notification_log.message,
                        alert=alert
                    )
                    
                    if success:
                        notification_log.mark_sent()
                        profile_results[channel] = {'status': 'sent', 'log_id': str(notification_log.id)}
                    else:
                        notification_log.mark_failed('Delivery failed')
                        profile_results[channel] = {'status': 'failed', 'log_id': str(notification_log.id)}
                        
                except Exception as e:
                    logger.error(f"Error sending {channel} notification: {e}")
                    if 'notification_log' in locals():
                        notification_log.mark_failed(str(e))
                    profile_results[channel] = {'status': 'error', 'error': str(e)}
            
            results[profile.name] = profile_results
        
        return results
    
    def _send_notification(self, channel: str, recipient: str, subject: str, 
                          message: str, alert: Alert) -> bool:
        """Send notification via specified channel."""
        try:
            if channel == 'email':
                return self._send_email(recipient, subject, message)
            elif channel == 'telegram':
                return self._send_telegram(recipient, message)
            elif channel == 'slack':
                return self._send_slack(recipient, subject, message)
            elif channel == 'teams':
                return self._send_teams(recipient, subject, message)
            elif channel == 'sms':
                return self._send_sms(recipient, message)
            else:
                logger.error(f"Unknown notification channel: {channel}")
                return False
        except Exception as e:
            logger.error(f"Error sending {channel} notification: {e}")
            return False
    
    def _send_email(self, recipient: str, subject: str, message: str) -> bool:
        """Send email notification via SMTP."""
        try:
            smtp_host = self.smtp_config.get('host', 'localhost')
            smtp_port = self.smtp_config.get('port', 587)
            smtp_user = self.smtp_config.get('username', '')
            smtp_pass = self.smtp_config.get('password', '')
            smtp_tls = self.smtp_config.get('use_tls', True)
            from_email = self.smtp_config.get('from_email', 'nms@example.com')
            
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = recipient
            msg['Subject'] = subject
            
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(smtp_host, smtp_port)
            if smtp_tls:
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email sent successfully to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {recipient}: {e}")
            return False
    
    def _send_telegram(self, chat_id: str, message: str) -> bool:
        """Send Telegram notification via Bot API."""
        try:
            bot_token = self.telegram_config.get('bot_token')
            if not bot_token:
                logger.error("Telegram bot token not configured")
                return False
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Telegram message sent successfully to {chat_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Telegram message to {chat_id}: {e}")
            return False
    
    def _send_slack(self, webhook_url: str, subject: str, message: str) -> bool:
        """Send Slack notification via webhook."""
        try:
            payload = {
                'text': subject,
                'attachments': [
                    {
                        'color': 'danger',
                        'text': message,
                        'ts': int(timezone.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Slack message sent successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack message: {e}")
            return False
    
    def _send_teams(self, webhook_url: str, subject: str, message: str) -> bool:
        """Send Microsoft Teams notification via webhook."""
        try:
            payload = {
                '@type': 'MessageCard',
                '@context': 'http://schema.org/extensions',
                'themeColor': 'FF0000',
                'summary': subject,
                'sections': [
                    {
                        'activityTitle': subject,
                        'activitySubtitle': 'Network Monitoring Alert',
                        'text': message,
                        'markdown': True
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Teams message sent successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Teams message: {e}")
            return False
    
    def _send_sms(self, phone_number: str, message: str) -> bool:
        """Send SMS notification via Twilio."""
        try:
            account_sid = self.twilio_config.get('account_sid')
            auth_token = self.twilio_config.get('auth_token')
            from_number = self.twilio_config.get('from_number')
            
            if not all([account_sid, auth_token, from_number]):
                logger.error("Twilio configuration incomplete")
                return False
            
            from twilio.rest import Client
            client = Client(account_sid, auth_token)
            
            # Truncate message to SMS limits
            if len(message) > 160:
                message = message[:157] + "..."
            
            message_obj = client.messages.create(
                body=message,
                from_=from_number,
                to=phone_number
            )
            
            logger.info(f"SMS sent successfully to {phone_number}, SID: {message_obj.sid}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send SMS to {phone_number}: {e}")
            return False
    
    def _generate_subject(self, alert: Alert) -> str:
        """Generate notification subject line."""
        from .template_service import template_service
        return template_service.render_notification_subject(alert, 'email')
    
    def _generate_message(self, alert: Alert, channel: str) -> str:
        """Generate notification message content."""
        from .template_service import template_service
        return template_service.render_notification_message(alert, channel)
    
# Global notification service instance
notification_service = NotificationService()