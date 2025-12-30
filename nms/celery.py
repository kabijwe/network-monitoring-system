"""
Celery configuration for Network Monitoring System (NMS).

This module configures Celery for background task processing including
monitoring tasks, alert processing, and scheduled operations.
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
    'monitor-hosts': {
        'task': 'monitoring.tasks.monitor_all_hosts',
        'schedule': 30.0,  # Run every 30 seconds
    },
    'process-alerts': {
        'task': 'monitoring.tasks.process_pending_alerts',
        'schedule': 60.0,  # Run every minute
    },
    'cleanup-old-metrics': {
        'task': 'monitoring.tasks.cleanup_old_metrics',
        'schedule': 3600.0,  # Run every hour
    },
    'auto-discovery': {
        'task': 'monitoring.tasks.auto_discovery_scan',
        'schedule': 300.0,  # Run every 5 minutes
    },
}

app.conf.timezone = 'UTC'

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')