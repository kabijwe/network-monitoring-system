# Network Monitoring System
# Enterprise-grade NMS for ISP environments

__version__ = '1.0.0'
__author__ = 'NMS Development Team'

# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
from .celery import app as celery_app

__all__ = ('celery_app',)