"""
Celery tasks for network monitoring system.

This module contains all Celery tasks for periodic monitoring including
ping checks, SNMP collection, service monitoring, and alert processing.
"""

import logging
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from celery import shared_task
from celery.exceptions import Retry
from asgiref.sync import sync_to_async

from .models import Host, PingResult, Alert, MonitoringMetric
from .ping_monitor import ping_host_sync, PingResult as PingResultData, PingMonitor
from .snmp_monitor import collect_snmp_metrics, is_snmp_available
from .service_monitor import check_host_services
from .notification_service import NotificationService
from .notification_service import NotificationService

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def ping_monitoring_task(self, host_id: str):
    """
    Perform ping monitoring for a single host.
    
    Args:
        host_id: UUID of the host to monitor
    """
    try:
        # Get host from database
        host = Host.objects.get(id=host_id)
        
        if not host.monitoring_enabled or not host.ping_enabled:
            logger.debug(f"Ping monitoring disabled for host {host.hostname}")
            return {'status': 'disabled', 'host': host.hostname}
        
        logger.info(f"Starting ping monitoring for {host.hostname}")
        
        # Perform ping check
        result = ping_host_sync(
            host.hostname,
            host.ip_address,
            host.get_ping_thresholds()
        )
        
        # Store result in database
        db_result = PingResult.objects.create(
            host=host,
            success=result.success,
            latency=result.latency,
            packet_loss=result.packet_loss,
            packets_sent=result.packets_sent,
            packets_received=result.packets_received,
            status='up' if result.success else 'down',
            status_reason=result.error_message or '',
            error_message=result.error_message or '',
            check_duration=1.0  # Placeholder
        )
        
        # Update host status and last check time
        monitor = PingMonitor()
        status = monitor.evaluate_status(result)
        host.status = status
        host.last_check = timezone.now()
        if result.success:
            host.last_seen = timezone.now()
        host.save(update_fields=['status', 'last_check', 'last_seen'])
        
        # Process alerts if needed (placeholder)
        # TODO: Implement alert processing
        # alert_service = AlertService()
        # alert_service.process_ping_result(host, result)
        
        logger.info(f"Ping monitoring completed for {host.hostname}: {status}")
        
        return {
            'status': 'success',
            'host': host.hostname,
            'result': {
                'success': result.success,
                'latency': result.latency,
                'packet_loss': result.packet_loss,
                'status': status
            }
        }
        
    except Host.DoesNotExist:
        logger.error(f"Host with ID {host_id} not found")
        return {'status': 'error', 'message': 'Host not found'}
    
    except Exception as e:
        logger.error(f"Error in ping monitoring task for host {host_id}: {e}")
        
        # Retry the task
        try:
            raise self.retry(countdown=60, exc=e)
        except self.MaxRetriesExceededError:
            logger.error(f"Max retries exceeded for ping monitoring task: {host_id}")
            return {'status': 'failed', 'message': str(e)}


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def snmp_monitoring_task(self, host_id: str, collectors: List[str] = None):
    """
    Perform SNMP monitoring for a single host.
    
    Args:
        host_id: UUID of the host to monitor
        collectors: List of SNMP collectors to use (default: all)
    """
    try:
        # Check if SNMP is available
        if not is_snmp_available():
            logger.warning("SNMP monitoring disabled - pysnmp not available")
            return {'status': 'disabled', 'message': 'SNMP not available'}
        
        # Get host from database
        host = Host.objects.get(id=host_id)
        
        if not host.monitoring_enabled or not host.snmp_enabled:
            logger.debug(f"SNMP monitoring disabled for host {host.hostname}")
            return {'status': 'disabled', 'host': host.hostname}
        
        logger.info(f"Starting SNMP monitoring for {host.hostname}")
        
        # Run SNMP collection in async context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                collect_snmp_metrics(host, collectors)
            )
        finally:
            loop.close()
        
        # Process results and update host status if needed
        success_count = sum(1 for result in results.values() if result.success)
        total_count = len(results)
        
        if total_count > 0:
            success_rate = success_count / total_count
            
            # Update host last check time
            host.last_check = timezone.now()
            if success_rate > 0.5:  # Consider successful if more than half succeed
                host.last_seen = timezone.now()
            host.save(update_fields=['last_check', 'last_seen'])
        
        logger.info(f"SNMP monitoring completed for {host.hostname}: {success_count}/{total_count} collectors succeeded")
        
        return {
            'status': 'success',
            'host': host.hostname,
            'results': {
                name: {
                    'success': result.success,
                    'error_message': result.error_message,
                    'metrics_count': len(result.metrics) if result.metrics else 0
                }
                for name, result in results.items()
            }
        }
        
    except Host.DoesNotExist:
        logger.error(f"Host with ID {host_id} not found")
        return {'status': 'error', 'message': 'Host not found'}
    
    except Exception as e:
        logger.error(f"Error in SNMP monitoring task for host {host_id}: {e}")
        
        # Retry the task
        try:
            raise self.retry(countdown=60, exc=e)
        except self.MaxRetriesExceededError:
            logger.error(f"Max retries exceeded for SNMP monitoring task: {host_id}")
            return {'status': 'failed', 'message': str(e)}


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def service_monitoring_task(self, host_id: str):
    """
    Perform service monitoring for a single host.
    
    Args:
        host_id: UUID of the host to monitor
    """
    try:
        # Get host from database
        host = Host.objects.get(id=host_id)
        
        if not host.monitoring_enabled or not host.service_checks_enabled:
            logger.debug(f"Service monitoring disabled for host {host.hostname}")
            return {'status': 'disabled', 'host': host.hostname}
        
        logger.info(f"Starting service monitoring for {host.hostname}")
        
        # Run service checks in async context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                check_host_services(host)
            )
        finally:
            loop.close()
        
        # Process results
        total_checks = 0
        successful_checks = 0
        
        for service_type, service_results in results.items():
            for result in service_results:
                total_checks += 1
                if result.success:
                    successful_checks += 1
        
        # Update host status if needed
        if total_checks > 0:
            host.last_check = timezone.now()
            success_rate = successful_checks / total_checks
            
            if success_rate > 0.8:  # Consider successful if 80%+ services are up
                host.last_seen = timezone.now()
            
            host.save(update_fields=['last_check', 'last_seen'])
        
        logger.info(f"Service monitoring completed for {host.hostname}: {successful_checks}/{total_checks} checks succeeded")
        
        return {
            'status': 'success',
            'host': host.hostname,
            'results': {
                service_type: [
                    {
                        'success': result.success,
                        'response_time': result.response_time,
                        'error_message': result.error_message
                    }
                    for result in service_results
                ]
                for service_type, service_results in results.items()
            }
        }
        
    except Host.DoesNotExist:
        logger.error(f"Host with ID {host_id} not found")
        return {'status': 'error', 'message': 'Host not found'}
    
    except Exception as e:
        logger.error(f"Error in service monitoring task for host {host_id}: {e}")
        
        # Retry the task
        try:
            raise self.retry(countdown=60, exc=e)
        except self.MaxRetriesExceededError:
            logger.error(f"Max retries exceeded for service monitoring task: {host_id}")
            return {'status': 'failed', 'message': str(e)}


@shared_task
def schedule_monitoring_tasks():
    """
    Schedule monitoring tasks for all enabled hosts.
    This task is called periodically by Celery Beat.
    """
    try:
        # Get all hosts that need monitoring
        hosts = Host.objects.filter(monitoring_enabled=True).select_related('location', 'group')
        
        scheduled_tasks = {
            'ping': 0,
            'snmp': 0,
            'service': 0
        }
        
        for host in hosts:
            host_id = str(host.id)
            
            # Schedule ping monitoring
            if host.ping_enabled:
                ping_monitoring_task.delay(host_id)
                scheduled_tasks['ping'] += 1
            
            # Schedule SNMP monitoring
            if host.snmp_enabled and is_snmp_available():
                snmp_monitoring_task.delay(host_id)
                scheduled_tasks['snmp'] += 1
            
            # Schedule service monitoring
            if host.service_checks_enabled:
                service_monitoring_task.delay(host_id)
                scheduled_tasks['service'] += 1
        
        logger.info(f"Scheduled monitoring tasks: {scheduled_tasks}")
        
        return {
            'status': 'success',
            'scheduled_tasks': scheduled_tasks,
            'total_hosts': hosts.count()
        }
        
    except Exception as e:
        logger.error(f"Error scheduling monitoring tasks: {e}")
        return {'status': 'error', 'message': str(e)}


@shared_task
def process_alert_escalations():
    """
    Process alert escalations for unacknowledged alerts.
    This task is called periodically to handle alert escalation.
    """
    try:
        alert_service = AlertService()
        
        # Get active alerts that need escalation
        escalation_interval = getattr(settings, 'ALERT_ESCALATION_INTERVAL', 30)  # minutes
        cutoff_time = timezone.now() - timedelta(minutes=escalation_interval)
        
        alerts_to_escalate = Alert.objects.filter(
            status='active',
            last_notification__lt=cutoff_time
        ).select_related('host', 'host__location', 'host__group')
        
        escalated_count = 0
        
        for alert in alerts_to_escalate:
            try:
                # Process escalation
                escalated = alert_service.escalate_alert(alert)
                if escalated:
                    escalated_count += 1
                    
            except Exception as e:
                logger.error(f"Error escalating alert {alert.id}: {e}")
                continue
        
        logger.info(f"Processed {escalated_count} alert escalations")
        
        return {
            'status': 'success',
            'escalated_count': escalated_count,
            'total_checked': alerts_to_escalate.count()
        }
        
    except Exception as e:
        logger.error(f"Error processing alert escalations: {e}")
        return {'status': 'error', 'message': str(e)}


@shared_task
def cleanup_old_data():
    """
    Clean up old monitoring data to prevent database bloat.
    This task is called periodically to remove old records.
    """
    try:
        # Get retention settings
        monitoring_settings = getattr(settings, 'MONITORING_SETTINGS', {})
        ping_retention_days = monitoring_settings.get('PING_RETENTION_DAYS', 30)
        metric_retention_days = monitoring_settings.get('METRIC_RETENTION_DAYS', 90)
        alert_retention_days = monitoring_settings.get('ALERT_RETENTION_DAYS', 365)
        
        cleanup_stats = {}
        
        # Clean up old ping results
        ping_cutoff = timezone.now() - timedelta(days=ping_retention_days)
        deleted_ping = PingResult.objects.filter(timestamp__lt=ping_cutoff).delete()
        cleanup_stats['ping_results'] = deleted_ping[0] if deleted_ping[0] else 0
        
        # Clean up old metrics
        metric_cutoff = timezone.now() - timedelta(days=metric_retention_days)
        deleted_metrics = MonitoringMetric.objects.filter(timestamp__lt=metric_cutoff).delete()
        cleanup_stats['metrics'] = deleted_metrics[0] if deleted_metrics[0] else 0
        
        # Clean up old resolved alerts
        alert_cutoff = timezone.now() - timedelta(days=alert_retention_days)
        deleted_alerts = Alert.objects.filter(
            status='resolved',
            resolved_at__lt=alert_cutoff
        ).delete()
        cleanup_stats['alerts'] = deleted_alerts[0] if deleted_alerts[0] else 0
        
        logger.info(f"Data cleanup completed: {cleanup_stats}")
        
        return {
            'status': 'success',
            'cleanup_stats': cleanup_stats
        }
        
    except Exception as e:
        logger.error(f"Error during data cleanup: {e}")
        return {'status': 'error', 'message': str(e)}


@shared_task
def health_check_task():
    """
    Perform system health check to ensure monitoring is working correctly.
    """
    try:
        health_status = {
            'database': False,
            'redis': False,
            'snmp': False,
            'hosts_monitored': 0,
            'active_alerts': 0,
            'last_ping_results': 0
        }
        
        # Check database connectivity
        try:
            host_count = Host.objects.count()
            health_status['database'] = True
            health_status['hosts_monitored'] = host_count
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
        
        # Check Redis connectivity
        try:
            from django.core.cache import cache
            cache.set('health_check', 'ok', 30)
            if cache.get('health_check') == 'ok':
                health_status['redis'] = True
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
        
        # Check SNMP availability
        health_status['snmp'] = is_snmp_available()
        
        # Check recent monitoring activity
        try:
            one_hour_ago = timezone.now() - timedelta(hours=1)
            
            health_status['active_alerts'] = Alert.objects.filter(status='active').count()
            health_status['last_ping_results'] = PingResult.objects.filter(
                timestamp__gte=one_hour_ago
            ).count()
            
        except Exception as e:
            logger.error(f"Activity health check failed: {e}")
        
        # Determine overall health
        critical_checks = ['database', 'redis']
        overall_health = all(health_status[check] for check in critical_checks)
        
        health_status['overall_health'] = overall_health
        health_status['timestamp'] = timezone.now().isoformat()
        
        if overall_health:
            logger.info("System health check passed")
        else:
            logger.warning(f"System health check failed: {health_status}")
        
        return health_status
        
    except Exception as e:
        logger.error(f"Error during health check: {e}")
        return {
            'status': 'error',
            'message': str(e),
            'timestamp': timezone.now().isoformat()
        }


# Utility functions for task management
def get_task_status(task_id: str) -> Dict[str, Any]:
    """Get status of a Celery task."""
    from celery.result import AsyncResult
    
    result = AsyncResult(task_id)
    
    return {
        'task_id': task_id,
        'status': result.status,
        'result': result.result,
        'traceback': result.traceback,
        'successful': result.successful(),
        'failed': result.failed()
    }


def schedule_host_monitoring(host: Host) -> Dict[str, str]:
    """Schedule monitoring tasks for a specific host."""
    task_ids = {}
    
    if host.monitoring_enabled:
        if host.ping_enabled:
            task = ping_monitoring_task.delay(str(host.id))
            task_ids['ping'] = task.id
        
        if host.snmp_enabled and is_snmp_available():
            task = snmp_monitoring_task.delay(str(host.id))
            task_ids['snmp'] = task.id
        
        if host.service_checks_enabled:
            task = service_monitoring_task.delay(str(host.id))
            task_ids['service'] = task.id
    
    return task_ids


def get_monitoring_statistics() -> Dict[str, Any]:
    """Get monitoring system statistics."""
    try:
        stats = {
            'hosts': {
                'total': Host.objects.count(),
                'monitoring_enabled': Host.objects.filter(monitoring_enabled=True).count(),
                'ping_enabled': Host.objects.filter(ping_enabled=True).count(),
                'snmp_enabled': Host.objects.filter(snmp_enabled=True).count(),
                'service_checks_enabled': Host.objects.filter(service_checks_enabled=True).count(),
            },
            'alerts': {
                'active': Alert.objects.filter(status='active').count(),
                'acknowledged': Alert.objects.filter(status='acknowledged').count(),
                'resolved_today': Alert.objects.filter(
                    status='resolved',
                    resolved_at__gte=timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
                ).count(),
            },
            'monitoring_data': {
                'ping_results_today': PingResult.objects.filter(
                    timestamp__gte=timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
                ).count(),
                'metrics_today': MonitoringMetric.objects.filter(
                    timestamp__gte=timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
                ).count(),
            },
            'system': {
                'snmp_available': is_snmp_available(),
                'timestamp': timezone.now().isoformat()
            }
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting monitoring statistics: {e}")
        return {'error': str(e)}


@shared_task(bind=True, max_retries=2, default_retry_delay=300)
def network_discovery_task(self, subnets=None):
    """
    Perform network discovery on specified subnets.
    
    Args:
        subnets: List of subnets to scan (uses default if None)
    """
    try:
        from .discovery import DiscoveryService
        
        logger.info(f"Starting network discovery task for subnets: {subnets}")
        
        # Initialize discovery service
        discovery_service = DiscoveryService()
        
        # Run discovery in async context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                discovery_service.run_discovery(subnets)
            )
        finally:
            loop.close()
        
        logger.info(f"Network discovery completed: {result}")
        
        return {
            'status': 'success',
            'result': result
        }
        
    except Exception as e:
        logger.error(f"Error in network discovery task: {e}")
        
        # Retry the task
        try:
            raise self.retry(countdown=300, exc=e)
        except self.MaxRetriesExceededError:
            logger.error(f"Max retries exceeded for network discovery task")
            return {'status': 'failed', 'message': str(e)}


@shared_task
def approve_discovered_device_task(device_id, location_id, group_id, user_id):
    """
    Approve a discovered device and add it to monitoring.
    
    Args:
        device_id: ID of discovered device
        location_id: Location to assign device to
        group_id: Group to assign device to
        user_id: ID of user approving the device
    """
    try:
        from .discovery import DiscoveryService
        
        discovery_service = DiscoveryService()
        
        # Run approval in async context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            success = loop.run_until_complete(
                discovery_service.approve_discovered_device(
                    device_id, location_id, group_id, user_id
                )
            )
        finally:
            loop.close()
        
        if success:
            logger.info(f"Successfully approved discovered device {device_id}")
            return {'status': 'success', 'device_id': device_id}
        else:
            logger.error(f"Failed to approve discovered device {device_id}")
            return {'status': 'failed', 'device_id': device_id}
            
    except Exception as e:
        logger.error(f"Error approving discovered device {device_id}: {e}")
        return {'status': 'error', 'message': str(e), 'device_id': device_id}


@shared_task
def reject_discovered_device_task(device_id, user_id, reason=''):
    """
    Reject a discovered device.
    
    Args:
        device_id: ID of discovered device
        user_id: ID of user rejecting the device
        reason: Reason for rejection
    """
    try:
        from .discovery import DiscoveryService
        
        discovery_service = DiscoveryService()
        
        # Run rejection in async context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            success = loop.run_until_complete(
                discovery_service.reject_discovered_device(
                    device_id, user_id, reason
                )
            )
        finally:
            loop.close()
        
        if success:
            logger.info(f"Successfully rejected discovered device {device_id}")
            return {'status': 'success', 'device_id': device_id}
        else:
            logger.error(f"Failed to reject discovered device {device_id}")
            return {'status': 'failed', 'device_id': device_id}
            
    except Exception as e:
        logger.error(f"Error rejecting discovered device {device_id}: {e}")
        return {'status': 'error', 'message': str(e), 'device_id': device_id}


@shared_task
def cleanup_old_discoveries():
    """
    Clean up old discovery records to prevent database bloat.
    """
    try:
        from .models import DiscoveredDevice
        
        # Get retention settings
        discovery_settings = getattr(settings, 'DISCOVERY_SETTINGS', {})
        retention_days = discovery_settings.get('DISCOVERY_RETENTION_DAYS', 90)
        
        # Clean up old rejected discoveries
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        
        deleted_count = DiscoveredDevice.objects.filter(
            status='rejected',
            rejected_at__lt=cutoff_date
        ).delete()[0]
        
        # Clean up old ignored discoveries
        ignored_deleted = DiscoveredDevice.objects.filter(
            status='ignored',
            discovered_at__lt=cutoff_date
        ).delete()[0]
        
        total_deleted = deleted_count + ignored_deleted
        
        logger.info(f"Cleaned up {total_deleted} old discovery records")
        
        return {
            'status': 'success',
            'deleted_rejected': deleted_count,
            'deleted_ignored': ignored_deleted,
            'total_deleted': total_deleted
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up old discoveries: {e}")
        return {'status': 'error', 'message': str(e)}


def schedule_network_discovery(subnets=None):
    """Schedule a network discovery task."""
    task = network_discovery_task.delay(subnets)
    return task.id


def get_discovery_task_status(task_id):
    """Get status of a discovery task."""
    return get_task_status(task_id)