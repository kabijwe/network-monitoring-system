"""
Signal handlers for core app.
"""
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import AuditLog

User = get_user_model()


@receiver(post_save, sender=User)
def log_user_creation(sender, instance, created, **kwargs):
    """Log user creation and updates."""
    if created:
        AuditLog.objects.create(
            user=instance,
            username=instance.username,
            action='CREATE',
            resource_type='User',
            resource_id=str(instance.id),
            resource_name=instance.username,
            description=f'User {instance.username} created',
            changes={'message': f'User {instance.username} created'}
        )
    else:
        AuditLog.objects.create(
            user=instance,
            username=instance.username,
            action='UPDATE',
            resource_type='User',
            resource_id=str(instance.id),
            resource_name=instance.username,
            description=f'User {instance.username} updated',
            changes={'message': f'User {instance.username} updated'}
        )


@receiver(post_delete, sender=User)
def log_user_deletion(sender, instance, **kwargs):
    """Log user deletion."""
    AuditLog.objects.create(
        username=instance.username,
        action='DELETE',
        resource_type='User',
        resource_id=str(instance.id),
        resource_name=instance.username,
        description=f'User {instance.username} deleted',
        changes={'message': f'User {instance.username} deleted'}
    )