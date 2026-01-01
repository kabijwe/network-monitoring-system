"""
Celery configuration for Network Monitoring System.

This module configures Celery for background task processing including
periodic monitoring tasks, alert processing, and data cleanup.
"""

import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nms.settings')

app = Celery('nms')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Celery Beat Schedule for periodic tasks
app.conf.beat_schedule = {
    # Main monitoring task - runs every 30 seconds
    'schedule-monitoring-tasks': {
        'task': 'monitoring.tasks.schedule_monitoring_tasks',
        'schedule': 30.0,  # Every 30 seconds
        'options': {
            'expires': 25,  # Task expires after 25 seconds to prevent overlap
        }
    },
    
    # Alert escalation processing - runs every 5 minutes
    'process-alert-escalations': {
        'task': 'monitoring.tasks.process_alert_escalations',
        'schedule': 300.0,  # Every 5 minutes
        'options': {
            'expires': 240,  # Task expires after 4 minutes
        }
    },
    
    # System health check - runs every 10 minutes
    'health-check': {
        'task': 'monitoring.tasks.health_check_task',
        'schedule': 600.0,  # Every 10 minutes
        'options': {
            'expires': 540,  # Task expires after 9 minutes
        }
    },
    
    # Data cleanup - runs daily at 2 AM
    'cleanup-old-data': {
        'task': 'monitoring.tasks.cleanup_old_data',
        'schedule': {
            'hour': 2,
            'minute': 0,
        },
        'options': {
            'expires': 3600,  # Task expires after 1 hour
        }
    },
    
    # Network discovery - runs daily at 3 AM
    'network-discovery': {
        'task': 'monitoring.tasks.network_discovery_task',
        'schedule': {
            'hour': 3,
            'minute': 0,
        },
        'options': {
            'expires': 7200,  # Task expires after 2 hours
        }
    },
    
    # Discovery cleanup - runs weekly on Sunday at 4 AM
    'cleanup-old-discoveries': {
        'task': 'monitoring.tasks.cleanup_old_discoveries',
        'schedule': {
            'hour': 4,
            'minute': 0,
            'day_of_week': 0,  # Sunday
        },
        'options': {
            'expires': 3600,  # Task expires after 1 hour
        }
    },
    
    # Notification retry processing - runs every 15 minutes
    'process-notification-retries': {
        'task': 'monitoring.tasks.notification_tasks.process_notification_retries',
        'schedule': 900.0,  # Every 15 minutes
        'options': {
            'expires': 840,  # Task expires after 14 minutes
        }
    },
    
    # Notification log cleanup - runs daily at 1 AM
    'cleanup-old-notification-logs': {
        'task': 'monitoring.tasks.notification_tasks.cleanup_old_notification_logs',
        'schedule': {
            'hour': 1,
            'minute': 0,
        },
        'options': {
            'expires': 3600,  # Task expires after 1 hour
        }
    },
}

# Celery configuration
app.conf.update(
    # Task routing
    task_routes={
        'monitoring.tasks.ping_monitoring_task': {'queue': 'monitoring'},
        'monitoring.tasks.snmp_monitoring_task': {'queue': 'monitoring'},
        'monitoring.tasks.service_monitoring_task': {'queue': 'monitoring'},
        'monitoring.tasks.schedule_monitoring_tasks': {'queue': 'scheduler'},
        'monitoring.tasks.process_alert_escalations': {'queue': 'alerts'},
        'monitoring.tasks.notification_tasks.send_alert_notification': {'queue': 'notifications'},
        'monitoring.tasks.notification_tasks.process_notification_retries': {'queue': 'notifications'},
        'monitoring.tasks.notification_tasks.cleanup_old_notification_logs': {'queue': 'maintenance'},
        'monitoring.tasks.cleanup_old_data': {'queue': 'maintenance'},
        'monitoring.tasks.health_check_task': {'queue': 'maintenance'},
        'monitoring.tasks.network_discovery_task': {'queue': 'discovery'},
        'monitoring.tasks.approve_discovered_device_task': {'queue': 'discovery'},
        'monitoring.tasks.reject_discovered_device_task': {'queue': 'discovery'},
        'monitoring.tasks.cleanup_old_discoveries': {'queue': 'maintenance'},
    },
    
    # Task execution settings
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    
    # Worker settings
    worker_prefetch_multiplier=1,  # Disable prefetching for better load distribution
    task_acks_late=True,  # Acknowledge tasks after completion
    worker_disable_rate_limits=False,
    
    # Result backend settings
    result_expires=3600,  # Results expire after 1 hour
    result_persistent=True,
    
    # Task execution limits
    task_time_limit=300,  # 5 minutes hard limit
    task_soft_time_limit=240,  # 4 minutes soft limit
    
    # Error handling
    task_reject_on_worker_lost=True,
    task_ignore_result=False,
    
    # Monitoring and logging
    worker_send_task_events=True,
    task_send_sent_event=True,
    
    # Queue configuration
    task_default_queue='default',
    task_default_exchange='default',
    task_default_exchange_type='direct',
    task_default_routing_key='default',
    
    # Beat scheduler settings
    beat_scheduler='django_celery_beat.schedulers:DatabaseScheduler',
)

# Queue definitions
app.conf.task_routes = {
    # Monitoring tasks - high priority, dedicated workers
    'monitoring.tasks.ping_monitoring_task': {
        'queue': 'monitoring',
        'routing_key': 'monitoring.ping',
    },
    'monitoring.tasks.snmp_monitoring_task': {
        'queue': 'monitoring',
        'routing_key': 'monitoring.snmp',
    },
    'monitoring.tasks.service_monitoring_task': {
        'queue': 'monitoring',
        'routing_key': 'monitoring.service',
    },
    
    # Scheduler tasks - medium priority
    'monitoring.tasks.schedule_monitoring_tasks': {
        'queue': 'scheduler',
        'routing_key': 'scheduler.main',
    },
    
    # Alert processing - high priority
    'monitoring.tasks.process_alert_escalations': {
        'queue': 'alerts',
        'routing_key': 'alerts.escalation',
    },
    
    # Notification processing - high priority
    'monitoring.tasks.notification_tasks.send_alert_notification': {
        'queue': 'notifications',
        'routing_key': 'notifications.send',
    },
    'monitoring.tasks.notification_tasks.process_notification_retries': {
        'queue': 'notifications',
        'routing_key': 'notifications.retry',
    },
    'monitoring.tasks.notification_tasks.cleanup_old_notification_logs': {
        'queue': 'maintenance',
        'routing_key': 'maintenance.notification_cleanup',
    },
    
    # Maintenance tasks - low priority
    'monitoring.tasks.cleanup_old_data': {
        'queue': 'maintenance',
        'routing_key': 'maintenance.cleanup',
    },
    'monitoring.tasks.health_check_task': {
        'queue': 'maintenance',
        'routing_key': 'maintenance.health',
    },
    'monitoring.tasks.cleanup_old_discoveries': {
        'queue': 'maintenance',
        'routing_key': 'maintenance.discovery_cleanup',
    },
    
    # Discovery tasks - medium priority
    'monitoring.tasks.network_discovery_task': {
        'queue': 'discovery',
        'routing_key': 'discovery.scan',
    },
    'monitoring.tasks.approve_discovered_device_task': {
        'queue': 'discovery',
        'routing_key': 'discovery.approve',
    },
    'monitoring.tasks.reject_discovered_device_task': {
        'queue': 'discovery',
        'routing_key': 'discovery.reject',
    },
}


@app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery configuration."""
    print(f'Request: {self.request!r}')
    return {'status': 'debug_task_completed', 'worker': self.request.hostname}


# Celery signal handlers for monitoring and logging
from celery.signals import task_prerun, task_postrun, task_failure, worker_ready

@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **kwds):
    """Log task start."""
    import logging
    logger = logging.getLogger('celery.task')
    logger.info(f'Task {task.name}[{task_id}] started')


@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, retval=None, state=None, **kwds):
    """Log task completion."""
    import logging
    logger = logging.getLogger('celery.task')
    logger.info(f'Task {task.name}[{task_id}] completed with state: {state}')


@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, traceback=None, einfo=None, **kwds):
    """Log task failures."""
    import logging
    logger = logging.getLogger('celery.task')
    logger.error(f'Task {sender.name}[{task_id}] failed: {exception}')


@worker_ready.connect
def worker_ready_handler(sender=None, **kwargs):
    """Log when worker is ready."""
    import logging
    logger = logging.getLogger('celery.worker')
    logger.info(f'Celery worker {sender.hostname} is ready')


# Health check function for monitoring Celery workers
def get_celery_worker_status():
    """Get status of Celery workers."""
    try:
        from celery import current_app
        
        # Get active workers
        inspect = current_app.control.inspect()
        
        stats = inspect.stats()
        active_tasks = inspect.active()
        scheduled_tasks = inspect.scheduled()
        reserved_tasks = inspect.reserved()
        
        return {
            'workers': list(stats.keys()) if stats else [],
            'worker_stats': stats,
            'active_tasks': active_tasks,
            'scheduled_tasks': scheduled_tasks,
            'reserved_tasks': reserved_tasks,
            'total_workers': len(stats) if stats else 0,
            'status': 'healthy' if stats else 'no_workers'
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'workers': [],
            'total_workers': 0
        }


# Task monitoring utilities
def get_task_queue_lengths():
    """Get length of task queues."""
    try:
        from celery import current_app
        
        inspect = current_app.control.inspect()
        active_queues = inspect.active_queues()
        
        queue_info = {}
        
        if active_queues:
            for worker, queues in active_queues.items():
                for queue in queues:
                    queue_name = queue['name']
                    if queue_name not in queue_info:
                        queue_info[queue_name] = {
                            'workers': [],
                            'routing_key': queue.get('routing_key', ''),
                            'exchange': queue.get('exchange', {}).get('name', '')
                        }
                    queue_info[queue_name]['workers'].append(worker)
        
        return queue_info
        
    except Exception as e:
        return {'error': str(e)}


def purge_all_queues():
    """Purge all Celery queues (use with caution)."""
    try:
        from celery import current_app
        
        # Purge all known queues
        queues_to_purge = ['monitoring', 'scheduler', 'alerts', 'maintenance', 'default']
        purged = {}
        
        for queue_name in queues_to_purge:
            try:
                count = current_app.control.purge()
                purged[queue_name] = count
            except Exception as e:
                purged[queue_name] = f'Error: {str(e)}'
        
        return purged
        
    except Exception as e:
        return {'error': str(e)}