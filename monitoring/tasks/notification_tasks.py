"""
Celery tasks for notification delivery.

This module contains Celery tasks for sending notifications
across different channels with retry logic and error handling.
"""
import logging
from celery import shared_task
from django.utils import timezone
from typing import List, Dict, Any

from ..models import Alert, NotificationProfile, NotificationLog
from ..notification_service import notification_service

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_alert_notification(self, alert_id: str, profile_ids: List[str]) -> Dict[str, Any]:
    """
    Send alert notification to specified profiles.
    
    Args:
        alert_id: UUID of the alert
        profile_ids: List of notification profile UUIDs
        
    Returns:
        Dictionary with delivery results
    """
    try:
        # Get alert and profiles
        alert = Alert.objects.get(id=alert_id)
        profiles = NotificationProfile.objects.filter(id__in=profile_ids)
        
        # Send notifications
        results = notification_service.send_alert_notification(alert, list(profiles))
        
        logger.info(f"Notification task completed for alert {alert_id}: {results}")
        return {
            'success': True,
            'alert_id': alert_id,
            'results': results
        }
        
    except Alert.DoesNotExist:
        logger.error(f"Alert {alert_id} not found")
        return {
            'success': False,
            'error': f'Alert {alert_id} not found'
        }
    
    except Exception as e:
        logger.error(f"Error in notification task for alert {alert_id}: {e}")
        
        # Retry on failure
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying notification task for alert {alert_id} (attempt {self.request.retries + 1})")
            raise self.retry(exc=e)
        
        return {
            'success': False,
            'error': str(e),
            'retries_exhausted': True
        }


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_escalation_notification(self, alert_id: str, escalation_level: int, 
                               profile_ids: List[str], rule_name: str) -> Dict[str, Any]:
    """
    Send escalation notification for an alert.
    
    Args:
        alert_id: UUID of the alert
        escalation_level: Current escalation level
        profile_ids: List of notification profile UUIDs
        rule_name: Name of the escalation rule
        
    Returns:
        Dictionary with delivery results
    """
    try:
        from ..escalation_service import escalation_service
        
        # Get alert and profiles
        alert = Alert.objects.get(id=alert_id)
        profiles = NotificationProfile.objects.filter(id__in=profile_ids)
        
        # Send escalation notifications
        results = {}
        for profile in profiles:
            for channel in profile.get_enabled_channels():
                try:
                    # Generate escalation message
                    from ..template_service import template_service
                    message = template_service.render_escalation_message(
                        alert, escalation_level, rule_name, channel
                    )
                    subject = f"[ESCALATION L{escalation_level}] {alert.title}"
                    
                    # Send notification
                    success = notification_service._send_notification(
                        channel=channel,
                        recipient=profile.get_recipients().get(channel, ''),
                        subject=subject,
                        message=message,
                        alert=alert
                    )
                    
                    # Log the notification
                    NotificationLog.objects.create(
                        alert=alert,
                        profile=profile,
                        channel=channel,
                        recipient=profile.get_recipients().get(channel, ''),
                        subject=subject,
                        message=message,
                        status='sent' if success else 'failed',
                        escalation_level=escalation_level
                    )
                    
                    results[f"{profile.name}_{channel}"] = {
                        'status': 'sent' if success else 'failed'
                    }
                    
                except Exception as e:
                    logger.error(f"Error sending escalation to {profile.name} via {channel}: {e}")
                    results[f"{profile.name}_{channel}"] = {
                        'status': 'error',
                        'error': str(e)
                    }
        
        logger.info(f"Escalation notification task completed for alert {alert_id}: {results}")
        return {
            'success': True,
            'alert_id': alert_id,
            'escalation_level': escalation_level,
            'results': results
        }
        
    except Alert.DoesNotExist:
        logger.error(f"Alert {alert_id} not found")
        return {
            'success': False,
            'error': f'Alert {alert_id} not found'
        }
    
    except Exception as e:
        logger.error(f"Error in escalation notification task for alert {alert_id}: {e}")
        
        # Retry on failure
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying escalation notification task for alert {alert_id} (attempt {self.request.retries + 1})")
            raise self.retry(exc=e)
        
        return {
            'success': False,
            'error': str(e),
            'retries_exhausted': True
        }


@shared_task
def process_notification_queue() -> Dict[str, Any]:
    """
    Process pending notifications in the queue.
    
    Returns:
        Dictionary with processing results
    """
    try:
        # Get pending notifications
        pending_notifications = NotificationLog.objects.filter(
            status__in=['pending', 'retrying']
        ).select_related('alert', 'profile')
        
        results = {
            'processed': 0,
            'sent': 0,
            'failed': 0,
            'errors': []
        }
        
        for notification in pending_notifications:
            try:
                # Check if we should retry
                if notification.status == 'retrying' and notification.retry_count >= notification.max_retries:
                    notification.mark_failed("Max retries exceeded")
                    results['failed'] += 1
                    continue
                
                # Send notification
                success = notification_service._send_notification(
                    channel=notification.channel,
                    recipient=notification.recipient,
                    subject=notification.subject,
                    message=notification.message,
                    alert=notification.alert
                )
                
                if success:
                    notification.mark_sent()
                    results['sent'] += 1
                else:
                    notification.increment_retry()
                    results['failed'] += 1
                
                results['processed'] += 1
                
            except Exception as e:
                logger.error(f"Error processing notification {notification.id}: {e}")
                notification.mark_failed(str(e))
                results['errors'].append({
                    'notification_id': str(notification.id),
                    'error': str(e)
                })
                results['failed'] += 1
        
        logger.info(f"Notification queue processing completed: {results}")
        return results
        
    except Exception as e:
        logger.error(f"Error processing notification queue: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@shared_task
def cleanup_old_notifications(days: int = 30) -> Dict[str, Any]:
    """
    Clean up old notification logs.
    
    Args:
        days: Number of days to keep notifications
        
    Returns:
        Dictionary with cleanup results
    """
    try:
        from datetime import timedelta
        
        cutoff_date = timezone.now() - timedelta(days=days)
        
        # Delete old notification logs
        deleted_count, _ = NotificationLog.objects.filter(
            created_at__lt=cutoff_date
        ).delete()
        
        logger.info(f"Cleaned up {deleted_count} old notification logs")
        
        return {
            'success': True,
            'deleted_count': deleted_count,
            'cutoff_date': cutoff_date.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up old notifications: {e}")
        return {
            'success': False,
            'error': str(e)
        }