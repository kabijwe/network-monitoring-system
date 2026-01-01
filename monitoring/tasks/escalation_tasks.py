"""
Celery tasks for alert escalation processing.

This module contains Celery tasks for processing alert escalations,
managing escalation timing, and handling acknowledgments.
"""
import logging
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from typing import Dict, Any, List

from ..models import Alert, AlertEscalation, EscalationRule
from ..escalation_service import escalation_service

logger = logging.getLogger(__name__)


@shared_task
def process_alert_escalations() -> Dict[str, Any]:
    """
    Process all pending alert escalations.
    
    Returns:
        Dictionary with processing results
    """
    try:
        results = escalation_service.process_alert_escalations()
        logger.info(f"Alert escalation processing completed: {results}")
        return results
        
    except Exception as e:
        logger.error(f"Error in alert escalation processing: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@shared_task
def process_single_alert_escalation(alert_id: str) -> Dict[str, Any]:
    """
    Process escalation for a specific alert.
    
    Args:
        alert_id: UUID of the alert to process
        
    Returns:
        Dictionary with escalation results
    """
    try:
        alert = Alert.objects.get(id=alert_id)
        results = escalation_service.process_alert_escalation(alert)
        
        logger.info(f"Escalation processing for alert {alert_id}: {results}")
        return results
        
    except Alert.DoesNotExist:
        logger.error(f"Alert {alert_id} not found")
        return {
            'success': False,
            'error': f'Alert {alert_id} not found'
        }
    
    except Exception as e:
        logger.error(f"Error processing escalation for alert {alert_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@shared_task
def acknowledge_alert_task(alert_id: str, user_id: int, comment: str = '') -> Dict[str, Any]:
    """
    Acknowledge an alert and stop its escalation.
    
    Args:
        alert_id: UUID of the alert to acknowledge
        user_id: ID of the user acknowledging the alert
        comment: Acknowledgment comment
        
    Returns:
        Dictionary with acknowledgment results
    """
    try:
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        alert = Alert.objects.get(id=alert_id)
        user = User.objects.get(id=user_id)
        
        results = escalation_service.acknowledge_alert(alert, user, comment)
        
        logger.info(f"Alert {alert_id} acknowledged by user {user_id}: {results}")
        return results
        
    except Alert.DoesNotExist:
        logger.error(f"Alert {alert_id} not found")
        return {
            'success': False,
            'error': f'Alert {alert_id} not found'
        }
    
    except Exception as e:
        logger.error(f"Error acknowledging alert {alert_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@shared_task
def schedule_escalation_check(alert_id: str, delay_minutes: int = 30) -> Dict[str, Any]:
    """
    Schedule an escalation check for an alert after a delay.
    
    Args:
        alert_id: UUID of the alert
        delay_minutes: Minutes to wait before checking escalation
        
    Returns:
        Dictionary with scheduling results
    """
    try:
        # Schedule the escalation check task
        from .escalation_tasks import process_single_alert_escalation
        
        eta = timezone.now() + timedelta(minutes=delay_minutes)
        
        process_single_alert_escalation.apply_async(
            args=[alert_id],
            eta=eta
        )
        
        logger.info(f"Scheduled escalation check for alert {alert_id} at {eta}")
        
        return {
            'success': True,
            'alert_id': alert_id,
            'scheduled_for': eta.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error scheduling escalation check for alert {alert_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@shared_task
def cleanup_old_escalations(days: int = 90) -> Dict[str, Any]:
    """
    Clean up old escalation records for resolved alerts.
    
    Args:
        days: Number of days to keep escalation records
        
    Returns:
        Dictionary with cleanup results
    """
    try:
        cutoff_date = timezone.now() - timedelta(days=days)
        
        # Get escalations for resolved alerts older than cutoff
        old_escalations = AlertEscalation.objects.filter(
            alert__status='resolved',
            alert__resolved_at__lt=cutoff_date
        )
        
        deleted_count = old_escalations.count()
        old_escalations.delete()
        
        logger.info(f"Cleaned up {deleted_count} old escalation records")
        
        return {
            'success': True,
            'deleted_count': deleted_count,
            'cutoff_date': cutoff_date.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up old escalations: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@shared_task
def update_escalation_schedules() -> Dict[str, Any]:
    """
    Update escalation schedules based on rule changes.
    
    Returns:
        Dictionary with update results
    """
    try:
        # Get all active escalations
        active_escalations = AlertEscalation.objects.filter(
            alert__status='active',
            acknowledged=False
        ).select_related('alert', 'escalation_rule')
        
        updated_count = 0
        
        for escalation in active_escalations:
            if escalation.escalation_rule:
                # Recalculate next escalation time based on current rule
                if escalation.last_escalation_time:
                    next_time = escalation.last_escalation_time + timedelta(
                        minutes=escalation.escalation_rule.escalation_interval_minutes
                    )
                else:
                    next_time = timezone.now() + timedelta(
                        minutes=escalation.escalation_rule.escalation_interval_minutes
                    )
                
                if escalation.next_escalation_time != next_time:
                    escalation.next_escalation_time = next_time
                    escalation.save(update_fields=['next_escalation_time'])
                    updated_count += 1
        
        logger.info(f"Updated {updated_count} escalation schedules")
        
        return {
            'success': True,
            'updated_count': updated_count
        }
        
    except Exception as e:
        logger.error(f"Error updating escalation schedules: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@shared_task
def create_escalation_rule_task(rule_data: Dict[str, Any], user_id: int) -> Dict[str, Any]:
    """
    Create a new escalation rule.
    
    Args:
        rule_data: Dictionary with rule configuration
        user_id: ID of the user creating the rule
        
    Returns:
        Dictionary with creation results
    """
    try:
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        user = User.objects.get(id=user_id)
        
        rule = escalation_service.create_escalation_rule(
            name=rule_data['name'],
            condition_type=rule_data['condition_type'],
            condition_config=rule_data['condition_config'],
            escalation_settings=rule_data['escalation_settings'],
            user=user
        )
        
        logger.info(f"Created escalation rule: {rule.name}")
        
        return {
            'success': True,
            'rule_id': str(rule.id),
            'rule_name': rule.name
        }
        
    except Exception as e:
        logger.error(f"Error creating escalation rule: {e}")
        return {
            'success': False,
            'error': str(e)
        }