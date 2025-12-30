"""
Signal handlers for monitoring app.
"""
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from core.models import AuditLog


# Monitoring signal handlers will be added here as models are created
# Example:
# @receiver(post_save, sender=Host)
# def log_host_changes(sender, instance, created, **kwargs):
#     """Log host creation and updates."""
#     action = 'CREATE' if created else 'UPDATE'
#     AuditLog.objects.create(
#         action=action,
#         model_name='Host',
#         object_id=str(instance.id),
#         changes={'message': f'Host {instance.hostname} {action.lower()}d'}
#     )