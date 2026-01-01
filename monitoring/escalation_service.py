"""
Alert escalation service for managing alert escalation chains and timing.

This module handles:
- Escalation rule evaluation
- Escalation timing and scheduling
- Template variable substitution
- Escalation history tracking
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import timedelta
from django.utils import timezone
from django.template import Template, Context
from django.db.models import Q

from .models import (
    Alert, EscalationRule, NotificationProfile, NotificationLog,
    AlertEscalation, AlertEscalationHistory
)

logger = logging.getLogger(__name__)


class EscalationService:
    """Service for managing alert escalation chains."""
    
    def process_alert_escalations(self) -> Dict[str, Any]:
        """
        Process all pending alert escalations.
        
        Returns:
            Dictionary with processing results
        """
        results = {
            'processed_alerts': 0,
            'escalations_triggered': 0,
            'errors': []
        }
        
        try:
            # Get all active alerts that need escalation processing
            active_alerts = Alert.objects.filter(
                status='active',
                acknowledged=False
            ).select_related('host', 'host__location', 'host__group')
            
            for alert in active_alerts:
                try:
                    escalation_result = self.process_alert_escalation(alert)
                    results['processed_alerts'] += 1
                    
                    if escalation_result.get('escalated'):
                        results['escalations_triggered'] += 1
                        
                except Exception as e:
                    logger.error(f"Error processing escalation for alert {alert.id}: {e}")
                    results['errors'].append({
                        'alert_id': str(alert.id),
                        'error': str(e)
                    })
            
            logger.info(f"Escalation processing completed: {results}")
            return results
            
        except Exception as e:
            logger.error(f"Error in escalation processing: {e}")
            results['errors'].append({'general_error': str(e)})
            return results
    
    def process_alert_escalation(self, alert: Alert) -> Dict[str, Any]:
        """
        Process escalation for a specific alert.
        
        Args:
            alert: Alert instance to process
            
        Returns:
            Dictionary with escalation results
        """
        # Get applicable escalation rules
        rules = self.get_applicable_escalation_rules(alert)
        
        if not rules:
            return {'escalated': False, 'reason': 'no_applicable_rules'}
        
        # Get or create escalation tracking record
        escalation, created = AlertEscalation.objects.get_or_create(
            alert=alert,
            defaults={
                'current_level': 0,
                'next_escalation_time': timezone.now() + timedelta(minutes=30),
                'escalation_rule': rules[0] if rules else None
            }
        )
        
        # Check if it's time to escalate
        if timezone.now() < escalation.next_escalation_time:
            return {'escalated': False, 'reason': 'not_time_yet'}
        
        # Determine next escalation level
        rule = escalation.escalation_rule or rules[0]
        next_level = escalation.current_level + 1
        
        if next_level > rule.max_escalation_level:
            return {'escalated': False, 'reason': 'max_level_reached'}
        
        # Get notification profiles for this escalation level
        profiles = rule.get_profiles_for_level(next_level)
        
        if not profiles:
            return {'escalated': False, 'reason': 'no_profiles_for_level'}
        
        # Send escalation notifications
        notification_results = self.send_escalation_notifications(
            alert, profiles, next_level, rule
        )
        
        # Update escalation record
        escalation.current_level = next_level
        escalation.last_escalation_time = timezone.now()
        escalation.next_escalation_time = timezone.now() + timedelta(
            minutes=rule.escalation_interval_minutes
        )
        escalation.save()
        
        # Create escalation history record
        AlertEscalationHistory.objects.create(
            alert=alert,
            escalation_level=next_level,
            escalation_rule=rule,
            notification_profiles=profiles,
            escalation_time=timezone.now(),
            notification_results=notification_results
        )
        
        logger.info(f"Alert {alert.id} escalated to level {next_level}")
        
        return {
            'escalated': True,
            'level': next_level,
            'rule': rule.name,
            'profiles_count': len(profiles),
            'notification_results': notification_results
        }
    
    def get_applicable_escalation_rules(self, alert: Alert) -> List[EscalationRule]:
        """
        Get escalation rules that apply to the given alert.
        
        Args:
            alert: Alert instance
            
        Returns:
            List of applicable EscalationRule instances, ordered by priority
        """
        rules = EscalationRule.objects.filter(
            enabled=True
        ).order_by('-priority', 'name')
        
        applicable_rules = []
        
        for rule in rules:
            if rule.matches_alert(alert):
                applicable_rules.append(rule)
        
        return applicable_rules
    
    def send_escalation_notifications(self, alert: Alert, profiles: List[NotificationProfile], 
                                    level: int, rule: EscalationRule) -> Dict[str, Any]:
        """
        Send escalation notifications to specified profiles.
        
        Args:
            alert: Alert instance
            profiles: List of notification profiles
            level: Escalation level
            rule: Escalation rule being applied
            
        Returns:
            Dictionary with notification results
        """
        from .notification_service import notification_service
        
        # Create escalation-specific alert context
        escalation_context = {
            'escalation_level': level,
            'escalation_rule': rule.name,
            'escalation_time': timezone.now(),
            'original_alert_time': alert.first_seen
        }
        
        # Temporarily modify alert title to indicate escalation
        original_title = alert.title
        alert.title = f"[ESCALATION L{level}] {original_title}"
        
        try:
            # Send notifications
            results = notification_service.send_alert_notification(alert, profiles)
            
            # Log escalation notifications separately
            for profile in profiles:
                for channel in profile.get_enabled_channels():
                    NotificationLog.objects.create(
                        alert=alert,
                        profile=profile,
                        channel=channel,
                        recipient=profile.get_recipients().get(channel, ''),
                        subject=f"ESCALATION L{level}: {original_title}",
                        message=self.generate_escalation_message(alert, escalation_context),
                        status='sent',
                        escalation_level=level
                    )
            
            return results
            
        finally:
            # Restore original alert title
            alert.title = original_title
    
    def generate_escalation_message(self, alert: Alert, context: Dict[str, Any]) -> str:
        """
        Generate escalation-specific message content.
        
        Args:
            alert: Alert instance
            context: Escalation context data
            
        Returns:
            Formatted escalation message
        """
        template_text = """
🚨 ALERT ESCALATION - Level {{ escalation_level }}

This alert has been escalated due to lack of acknowledgment.

Alert Details:
- Title: {{ alert.title }}
- Host: {{ alert.host.hostname }} ({{ alert.host.ip_address }})
- Location: {{ alert.host.location.name }}
- Group: {{ alert.host.group.name }}
- Severity: {{ alert.severity|upper }}
- Description: {{ alert.description }}

Escalation Information:
- Escalation Level: {{ escalation_level }}
- Escalation Rule: {{ escalation_rule }}
- Original Alert Time: {{ original_alert_time|date:"Y-m-d H:i:s" }}
- Escalation Time: {{ escalation_time|date:"Y-m-d H:i:s" }}

Check Details:
- Check Type: {{ alert.check_type }}
- Current Value: {{ alert.current_value }}
- Threshold: {{ alert.threshold_value }}

⚠️ This alert requires immediate attention!
        """.strip()
        
        template = Template(template_text)
        template_context = Context({
            'alert': alert,
            'escalation_level': context['escalation_level'],
            'escalation_rule': context['escalation_rule'],
            'escalation_time': context['escalation_time'],
            'original_alert_time': context['original_alert_time']
        })
        
        return template.render(template_context)
    
    def acknowledge_alert(self, alert: Alert, user, comment: str = '') -> Dict[str, Any]:
        """
        Acknowledge an alert and stop its escalation.
        
        Args:
            alert: Alert instance to acknowledge
            user: User acknowledging the alert
            comment: Acknowledgment comment
            
        Returns:
            Dictionary with acknowledgment results
        """
        try:
            # Acknowledge the alert
            alert.acknowledge(user, comment)
            
            # Stop escalation
            try:
                escalation = AlertEscalation.objects.get(alert=alert)
                escalation.acknowledged = True
                escalation.acknowledged_by = user
                escalation.acknowledged_at = timezone.now()
                escalation.acknowledgment_comment = comment
                escalation.save()
                
                logger.info(f"Alert {alert.id} acknowledged by {user.username}, escalation stopped")
                
            except AlertEscalation.DoesNotExist:
                # No escalation record exists, which is fine
                pass
            
            return {
                'acknowledged': True,
                'alert_id': str(alert.id),
                'acknowledged_by': user.username,
                'comment': comment
            }
            
        except Exception as e:
            logger.error(f"Error acknowledging alert {alert.id}: {e}")
            return {
                'acknowledged': False,
                'error': str(e)
            }
    
    def create_escalation_rule(self, name: str, condition_type: str, 
                             condition_config: Dict[str, Any], 
                             escalation_settings: Dict[str, Any],
                             user) -> EscalationRule:
        """
        Create a new escalation rule.
        
        Args:
            name: Rule name
            condition_type: Type of condition (severity_based, location_based, etc.)
            condition_config: Configuration for the condition
            escalation_settings: Escalation timing and profile settings
            user: User creating the rule
            
        Returns:
            Created EscalationRule instance
        """
        rule = EscalationRule.objects.create(
            name=name,
            condition_type=condition_type,
            condition_config=condition_config,
            escalation_interval_minutes=escalation_settings.get('interval_minutes', 30),
            max_escalation_level=escalation_settings.get('max_level', 3),
            enabled=escalation_settings.get('enabled', True),
            priority=escalation_settings.get('priority', 0),
            created_by=user
        )
        
        # Set up escalation level profiles
        if 'level_1_profiles' in escalation_settings:
            rule.level_1_profiles.set(escalation_settings['level_1_profiles'])
        if 'level_2_profiles' in escalation_settings:
            rule.level_2_profiles.set(escalation_settings['level_2_profiles'])
        if 'level_3_profiles' in escalation_settings:
            rule.level_3_profiles.set(escalation_settings['level_3_profiles'])
        
        logger.info(f"Created escalation rule: {rule.name}")
        return rule
    
    def get_escalation_history(self, alert: Alert) -> List[Dict[str, Any]]:
        """
        Get escalation history for an alert.
        
        Args:
            alert: Alert instance
            
        Returns:
            List of escalation history records
        """
        history = AlertEscalationHistory.objects.filter(
            alert=alert
        ).order_by('escalation_time')
        
        return [
            {
                'level': record.escalation_level,
                'rule': record.escalation_rule.name if record.escalation_rule else None,
                'time': record.escalation_time,
                'profiles_count': len(record.notification_profiles.all()),
                'notification_results': record.notification_results
            }
            for record in history
        ]


# Global escalation service instance
escalation_service = EscalationService()