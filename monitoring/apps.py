from django.apps import AppConfig


class MonitoringConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'monitoring'
    verbose_name = 'Network Monitoring'

    def ready(self):
        """Initialize the monitoring app when Django starts."""
        import monitoring.signals  # noqa