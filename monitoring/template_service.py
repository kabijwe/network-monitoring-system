"""
Template service for customizable notification messages.

This module provides template management and variable substitution
for notification messages across different channels.
"""
import logging
from typing import Dict, Any, Optional
from django.template import Template, Context, TemplateSyntaxError
from django.utils import timezone
from django.conf import settings

from .models import Alert, Host, NotificationProfile

logger = logging.getLogger(__name__)


class NotificationTemplateService:
    """Service for managing notification templates and variable substitution."""
    
    # Default templates for different channels and alert types
    DEFAULT_TEMPLATES = {
        'email': {
            'subject': '{{ severity_emoji }} {{ severity|upper }}: {{ alert.title }}',
            'body': '''
Alert: {{ alert.title }}
Host: {{ alert.host.hostname }} ({{ alert.host.ip_address }})
Location: {{ alert.host.location.name }}
Group: {{ alert.host.group.name }}
Severity: {{ alert.severity|upper }}
Status: {{ alert.status }}

Description: {{ alert.description }}

Check Details:
- Check Type: {{ alert.check_type }}
- Current Value: {{ alert.current_value }}
- Threshold: {{ alert.threshold_value }}

Timing:
- First Seen: {{ alert.first_seen|date:"Y-m-d H:i:s" }}
- Last Seen: {{ alert.last_seen|date:"Y-m-d H:i:s" }}

{% if escalation_level %}
ESCALATION INFORMATION:
- Escalation Level: {{ escalation_level }}
- Escalation Rule: {{ escalation_rule }}
- Original Alert Time: {{ original_alert_time|date:"Y-m-d H:i:s" }}
{% endif %}

Please investigate and acknowledge this alert.
            '''.strip()
        },
        
        'telegram': {
            'message': '''
<b>{{ severity_emoji }} {{ alert.severity|upper }}: {{ alert.title }}</b>

<b>Host:</b> {{ alert.host.hostname }} ({{ alert.host.ip_address }})
<b>Location:</b> {{ alert.host.location.name }}
<b>Group:</b> {{ alert.host.group.name }}

<b>Description:</b> {{ alert.description }}
<b>Check Type:</b> {{ alert.check_type }}
<b>Current Value:</b> {{ alert.current_value }}
<b>Threshold:</b> {{ alert.threshold_value }}

<b>First Seen:</b> {{ alert.first_seen|date:"Y-m-d H:i:s" }}

{% if escalation_level %}<b>🚨 ESCALATION LEVEL {{ escalation_level }}</b>{% endif %}
            '''.strip()
        },
        
        'slack': {
            'message': '''
*{{ severity_emoji }} {{ alert.severity|upper }}: {{ alert.title }}*

*Host:* {{ alert.host.hostname }} ({{ alert.host.ip_address }})
*Location:* {{ alert.host.location.name }}
*Group:* {{ alert.host.group.name }}

*Description:* {{ alert.description }}
*Check Type:* {{ alert.check_type }}
*Current Value:* {{ alert.current_value }}
*Threshold:* {{ alert.threshold_value }}

*First Seen:* {{ alert.first_seen|date:"Y-m-d H:i:s" }}

{% if escalation_level %}🚨 *ESCALATION LEVEL {{ escalation_level }}*{% endif %}
            '''.strip()
        },
        
        'teams': {
            'message': '''
**{{ severity_emoji }} {{ alert.severity|upper }}: {{ alert.title }}**

**Host:** {{ alert.host.hostname }} ({{ alert.host.ip_address }})
**Location:** {{ alert.host.location.name }}
**Group:** {{ alert.host.group.name }}

**Description:** {{ alert.description }}
**Check Type:** {{ alert.check_type }}
**Current Value:** {{ alert.current_value }}
**Threshold:** {{ alert.threshold_value }}

**First Seen:** {{ alert.first_seen|date:"Y-m-d H:i:s" }}

{% if escalation_level %}🚨 **ESCALATION LEVEL {{ escalation_level }}**{% endif %}
            '''.strip()
        },
        
        'sms': {
            'message': '''
{{ severity_emoji }} {{ alert.severity|upper }}: {{ alert.host.hostname }} - {{ alert.title }}
Location: {{ alert.host.location.name }}
{% if escalation_level %}ESCALATION L{{ escalation_level }}{% endif %}
            '''.strip()
        }
    }
    
    # Severity emoji mapping
    SEVERITY_EMOJIS = {
        'info': 'ℹ️',
        'warning': '⚠️',
        'critical': '🚨'
    }
    
    def render_template(self, template_text: str, context: Dict[str, Any]) -> str:
        """
        Render a template with the given context.
        
        Args:
            template_text: Template string
            context: Context variables
            
        Returns:
            Rendered template string
        """
        try:
            template = Template(template_text)
            django_context = Context(context)
            return template.render(django_context)
            
        except TemplateSyntaxError as e:
            logger.error(f"Template syntax error: {e}")
            return f"Template Error: {str(e)}"
        
        except Exception as e:
            logger.error(f"Template rendering error: {e}")
            return f"Rendering Error: {str(e)}"
    
    def get_alert_context(self, alert: Alert, **extra_context) -> Dict[str, Any]:
        """
        Build template context for an alert.
        
        Args:
            alert: Alert instance
            **extra_context: Additional context variables
            
        Returns:
            Dictionary with template context
        """
        context = {
            'alert': alert,
            'host': alert.host,
            'location': alert.host.location,
            'group': alert.host.group,
            'severity_emoji': self.SEVERITY_EMOJIS.get(alert.severity, '📢'),
            'current_time': timezone.now(),
            'system_name': getattr(settings, 'SYSTEM_NAME', 'Network Monitoring System'),
            'system_url': getattr(settings, 'SYSTEM_URL', 'http://localhost:8000'),
        }
        
        # Add extra context
        context.update(extra_context)
        
        return context
    
    def render_notification_subject(self, alert: Alert, channel: str = 'email', 
                                  template_override: Optional[str] = None,
                                  **extra_context) -> str:
        """
        Render notification subject line.
        
        Args:
            alert: Alert instance
            channel: Notification channel
            template_override: Custom template to use
            **extra_context: Additional context variables
            
        Returns:
            Rendered subject line
        """
        if template_override:
            template_text = template_override
        else:
            template_text = self.DEFAULT_TEMPLATES.get(channel, {}).get('subject', 
                self.DEFAULT_TEMPLATES['email']['subject'])
        
        context = self.get_alert_context(alert, **extra_context)
        return self.render_template(template_text, context)
    
    def render_notification_message(self, alert: Alert, channel: str,
                                  template_override: Optional[str] = None,
                                  **extra_context) -> str:
        """
        Render notification message content.
        
        Args:
            alert: Alert instance
            channel: Notification channel
            template_override: Custom template to use
            **extra_context: Additional context variables
            
        Returns:
            Rendered message content
        """
        if template_override:
            template_text = template_override
        else:
            # Get template based on channel
            channel_templates = self.DEFAULT_TEMPLATES.get(channel, {})
            template_text = channel_templates.get('message', 
                channel_templates.get('body', 
                    self.DEFAULT_TEMPLATES['email']['body']))
        
        context = self.get_alert_context(alert, **extra_context)
        return self.render_template(template_text, context)
    
    def render_escalation_message(self, alert: Alert, escalation_level: int,
                                escalation_rule: str, channel: str,
                                template_override: Optional[str] = None) -> str:
        """
        Render escalation-specific message.
        
        Args:
            alert: Alert instance
            escalation_level: Current escalation level
            escalation_rule: Name of escalation rule
            channel: Notification channel
            template_override: Custom template to use
            
        Returns:
            Rendered escalation message
        """
        extra_context = {
            'escalation_level': escalation_level,
            'escalation_rule': escalation_rule,
            'original_alert_time': alert.first_seen,
            'escalation_time': timezone.now()
        }
        
        return self.render_notification_message(
            alert, channel, template_override, **extra_context
        )
    
    def validate_template(self, template_text: str) -> Dict[str, Any]:
        """
        Validate a template for syntax errors.
        
        Args:
            template_text: Template string to validate
            
        Returns:
            Dictionary with validation results
        """
        try:
            # Try to create template
            template = Template(template_text)
            
            # Try to render with sample context
            sample_context = self.get_sample_context()
            django_context = Context(sample_context)
            rendered = template.render(django_context)
            
            return {
                'valid': True,
                'rendered_sample': rendered[:200] + '...' if len(rendered) > 200 else rendered
            }
            
        except TemplateSyntaxError as e:
            return {
                'valid': False,
                'error': f'Syntax Error: {str(e)}',
                'error_type': 'syntax'
            }
        
        except Exception as e:
            return {
                'valid': False,
                'error': f'Rendering Error: {str(e)}',
                'error_type': 'rendering'
            }
    
    def get_sample_context(self) -> Dict[str, Any]:
        """
        Get sample context for template validation.
        
        Returns:
            Dictionary with sample context variables
        """
        from datetime import datetime
        
        # Create mock objects for template validation
        class MockObject:
            def __init__(self, **kwargs):
                for key, value in kwargs.items():
                    setattr(self, key, value)
        
        mock_location = MockObject(name='Sample Location')
        mock_group = MockObject(name='Sample Group')
        mock_host = MockObject(
            hostname='sample-host',
            ip_address='192.168.1.100',
            location=mock_location,
            group=mock_group
        )
        mock_alert = MockObject(
            title='Sample Alert',
            description='This is a sample alert for template validation',
            severity='warning',
            status='active',
            check_type='ping',
            current_value=150.5,
            threshold_value=100.0,
            first_seen=timezone.now(),
            last_seen=timezone.now(),
            host=mock_host
        )
        
        return {
            'alert': mock_alert,
            'host': mock_host,
            'location': mock_location,
            'group': mock_group,
            'severity_emoji': '⚠️',
            'current_time': timezone.now(),
            'system_name': 'Network Monitoring System',
            'system_url': 'http://localhost:8000',
            'escalation_level': 2,
            'escalation_rule': 'Sample Escalation Rule',
            'original_alert_time': timezone.now(),
            'escalation_time': timezone.now()
        }
    
    def get_available_variables(self) -> Dict[str, str]:
        """
        Get list of available template variables with descriptions.
        
        Returns:
            Dictionary mapping variable names to descriptions
        """
        return {
            # Alert variables
            'alert.title': 'Alert title',
            'alert.description': 'Alert description',
            'alert.severity': 'Alert severity (info, warning, critical)',
            'alert.status': 'Alert status (active, acknowledged, resolved)',
            'alert.check_type': 'Type of check that generated the alert',
            'alert.current_value': 'Current metric value',
            'alert.threshold_value': 'Threshold value that was exceeded',
            'alert.first_seen': 'When the alert was first seen',
            'alert.last_seen': 'When the alert was last updated',
            
            # Host variables
            'host.hostname': 'Host hostname',
            'host.ip_address': 'Host IP address',
            'host.device_name': 'Host device name',
            'host.device_type': 'Host device type',
            
            # Location variables
            'location.name': 'Location name',
            'location.description': 'Location description',
            
            # Group variables
            'group.name': 'Device group name',
            'group.description': 'Device group description',
            
            # System variables
            'severity_emoji': 'Emoji representing alert severity',
            'current_time': 'Current timestamp',
            'system_name': 'System name',
            'system_url': 'System URL',
            
            # Escalation variables (available in escalation messages)
            'escalation_level': 'Current escalation level',
            'escalation_rule': 'Name of escalation rule',
            'original_alert_time': 'When the original alert was created',
            'escalation_time': 'When the escalation occurred'
        }


# Global template service instance
template_service = NotificationTemplateService()