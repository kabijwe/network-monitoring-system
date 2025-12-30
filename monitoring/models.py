"""
Monitoring models for Network Monitoring System.

This module contains models for network devices, monitoring data,
alerts, and related functionality.
"""

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
import uuid

User = get_user_model()


class Location(models.Model):
    """
    Physical or logical location for network devices.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    
    # Geographic information
    address = models.TextField(blank=True)
    latitude = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    longitude = models.DecimalField(max_digits=11, decimal_places=8, null=True, blank=True)
    
    # Hierarchy
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        db_table = 'monitoring_location'
        verbose_name = 'Location'
        verbose_name_plural = 'Locations'
        ordering = ['name']

    def __str__(self):
        return self.name


class DeviceGroup(models.Model):
    """
    Logical grouping of network devices.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    
    # Group properties
    color = models.CharField(max_length=7, default='#007bff')  # Hex color for UI
    icon = models.CharField(max_length=50, default='device')
    
    # Hierarchy
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        db_table = 'monitoring_device_group'
        verbose_name = 'Device Group'
        verbose_name_plural = 'Device Groups'
        ordering = ['name']

    def __str__(self):
        return self.name


class Host(models.Model):
    """
    Network host/device to be monitored.
    """
    STATUS_CHOICES = [
        ('up', 'Up'),
        ('down', 'Down'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
        ('maintenance', 'Maintenance'),
        ('unknown', 'Unknown'),
    ]
    
    DEVICE_TYPE_CHOICES = [
        ('ap', 'Access Point'),
        ('sm', 'Subscriber Module'),
        ('switch', 'Switch'),
        ('router', 'Router'),
        ('firewall', 'Firewall'),
        ('server', 'Server'),
        ('other', 'Other'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Basic device information
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    device_name = models.CharField(max_length=255, blank=True)
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPE_CHOICES, default='other')
    
    # ISP-specific fields
    ap_name = models.CharField(max_length=255, blank=True, verbose_name='AP Name')
    cid = models.CharField(max_length=100, blank=True, verbose_name='CID')
    ap_ip = models.GenericIPAddressField(null=True, blank=True, verbose_name='AP IP')
    sm_ip = models.GenericIPAddressField(null=True, blank=True, verbose_name='SM IP')
    
    # Organization
    location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name='hosts')
    group = models.ForeignKey(DeviceGroup, on_delete=models.CASCADE, related_name='hosts')
    
    # Monitoring configuration
    monitoring_enabled = models.BooleanField(default=True)
    ping_enabled = models.BooleanField(default=True)
    snmp_enabled = models.BooleanField(default=False)
    snmp_community = models.CharField(max_length=100, blank=True, default='public')
    snmp_version = models.CharField(max_length=10, default='2c', choices=[('1', 'v1'), ('2c', 'v2c'), ('3', 'v3')])
    
    # Current status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='unknown')
    last_seen = models.DateTimeField(null=True, blank=True)
    last_check = models.DateTimeField(null=True, blank=True)
    
    # Ping monitoring thresholds
    ping_warning_latency = models.FloatField(default=100.0, help_text='Warning threshold for ping latency (ms)')
    ping_critical_latency = models.FloatField(default=500.0, help_text='Critical threshold for ping latency (ms)')
    ping_warning_packet_loss = models.FloatField(default=5.0, help_text='Warning threshold for packet loss (%)')
    ping_critical_packet_loss = models.FloatField(default=20.0, help_text='Critical threshold for packet loss (%)')
    ping_timeout = models.IntegerField(default=5, help_text='Ping timeout in seconds')
    ping_packet_count = models.IntegerField(default=4, help_text='Number of ping packets to send')
    
    # Acknowledgment
    acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='acknowledged_hosts')
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledgment_comment = models.TextField(blank=True)
    
    # Maintenance
    in_maintenance = models.BooleanField(default=False)
    maintenance_start = models.DateTimeField(null=True, blank=True)
    maintenance_end = models.DateTimeField(null=True, blank=True)
    maintenance_comment = models.TextField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        db_table = 'monitoring_host'
        verbose_name = 'Host'
        verbose_name_plural = 'Hosts'
        unique_together = ['hostname', 'ip_address']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['status']),
            models.Index(fields=['location']),
            models.Index(fields=['group']),
            models.Index(fields=['last_check']),
        ]
        ordering = ['hostname']

    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"

    @property
    def display_name(self):
        """Return the most appropriate display name for the host."""
        return self.device_name or self.hostname

    def is_up(self):
        """Check if the host is currently up."""
        return self.status == 'up'

    def is_down(self):
        """Check if the host is currently down."""
        return self.status == 'down'

    def needs_acknowledgment(self):
        """Check if the host needs acknowledgment."""
        return self.status in ['down', 'warning', 'critical'] and not self.acknowledged and not self.in_maintenance

    def get_ping_thresholds(self):
        """Get ping monitoring thresholds for this host."""
        from .ping_monitor import PingThresholds
        return PingThresholds(
            warning_latency=self.ping_warning_latency,
            critical_latency=self.ping_critical_latency,
            warning_packet_loss=self.ping_warning_packet_loss,
            critical_packet_loss=self.ping_critical_packet_loss,
            timeout=self.ping_timeout,
            packet_count=self.ping_packet_count
        )


class PingResult(models.Model):
    """
    Store ping monitoring results for hosts.
    """
    STATUS_CHOICES = [
        ('up', 'Up'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
        ('down', 'Down'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='ping_results')
    
    # Ping results
    success = models.BooleanField()
    latency = models.FloatField(null=True, blank=True, help_text='Average latency in milliseconds')
    packet_loss = models.FloatField(default=0.0, help_text='Packet loss percentage')
    packets_sent = models.IntegerField(default=0)
    packets_received = models.IntegerField(default=0)
    
    # Status evaluation
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    status_reason = models.TextField(blank=True)
    
    # Error information
    error_message = models.TextField(blank=True)
    
    # Timing
    timestamp = models.DateTimeField(auto_now_add=True)
    check_duration = models.FloatField(null=True, blank=True, help_text='Time taken for ping check in seconds')

    class Meta:
        db_table = 'monitoring_ping_result'
        verbose_name = 'Ping Result'
        verbose_name_plural = 'Ping Results'
        indexes = [
            models.Index(fields=['host', 'timestamp']),
            models.Index(fields=['status', 'timestamp']),
            models.Index(fields=['timestamp']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.host.hostname} - {self.status} at {self.timestamp}"


class MonitoringMetric(models.Model):
    """
    Time-series monitoring data for hosts.
    """
    METRIC_TYPE_CHOICES = [
        ('ping_latency', 'Ping Latency'),
        ('ping_loss', 'Ping Loss'),
        ('snmp_cpu', 'CPU Usage'),
        ('snmp_memory', 'Memory Usage'),
        ('snmp_interface_in', 'Interface In'),
        ('snmp_interface_out', 'Interface Out'),
        ('snmp_temperature', 'Temperature'),
        ('custom', 'Custom Metric'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='metrics')
    metric_type = models.CharField(max_length=50, choices=METRIC_TYPE_CHOICES)
    metric_name = models.CharField(max_length=100)
    
    # Metric data
    value = models.FloatField()
    unit = models.CharField(max_length=20, blank=True)
    
    # Context
    interface = models.CharField(max_length=100, blank=True)  # For interface metrics
    additional_data = models.JSONField(default=dict, blank=True)
    
    # Timing
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'monitoring_metric'
        verbose_name = 'Monitoring Metric'
        verbose_name_plural = 'Monitoring Metrics'
        indexes = [
            models.Index(fields=['host', 'metric_type', 'timestamp']),
            models.Index(fields=['timestamp']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.host.hostname} - {self.metric_name}: {self.value} {self.unit}"


class Alert(models.Model):
    """
    Alert generated from monitoring checks.
    """
    SEVERITY_CHOICES = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('acknowledged', 'Acknowledged'),
        ('resolved', 'Resolved'),
        ('suppressed', 'Suppressed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='alerts')
    
    # Alert details
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    # Alert source
    check_type = models.CharField(max_length=50)  # ping, snmp, custom, etc.
    metric_name = models.CharField(max_length=100, blank=True)
    threshold_value = models.FloatField(null=True, blank=True)
    current_value = models.FloatField(null=True, blank=True)
    
    # Timing
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Acknowledgment
    acknowledged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledgment_comment = models.TextField(blank=True)
    
    # Notification tracking
    notifications_sent = models.JSONField(default=list, blank=True)
    last_notification = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'monitoring_alert'
        verbose_name = 'Alert'
        verbose_name_plural = 'Alerts'
        indexes = [
            models.Index(fields=['host', 'status']),
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['first_seen']),
            models.Index(fields=['status']),
        ]
        ordering = ['-first_seen']

    def __str__(self):
        return f"{self.host.hostname} - {self.title} ({self.severity})"

    def is_active(self):
        """Check if the alert is currently active."""
        return self.status == 'active'

    def acknowledge(self, user, comment=''):
        """Acknowledge the alert."""
        self.status = 'acknowledged'
        self.acknowledged_by = user
        self.acknowledged_at = timezone.now()
        self.acknowledgment_comment = comment
        self.save()

    def resolve(self):
        """Mark the alert as resolved."""
        self.status = 'resolved'
        self.resolved_at = timezone.now()
        self.save()


class NotificationProfile(models.Model):
    """
    Notification profile defining how and when to send notifications.
    """
    CHANNEL_CHOICES = [
        ('email', 'Email'),
        ('telegram', 'Telegram'),
        ('slack', 'Slack'),
        ('teams', 'Microsoft Teams'),
        ('sms', 'SMS'),
    ]
    
    SEVERITY_CHOICES = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Profile identification
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    
    # Scope (can be applied to users, locations, groups, or globally)
    users = models.ManyToManyField(User, blank=True, related_name='notification_profiles')
    locations = models.ManyToManyField(Location, blank=True, related_name='notification_profiles')
    groups = models.ManyToManyField(DeviceGroup, blank=True, related_name='notification_profiles')
    is_default = models.BooleanField(default=False)
    
    # Notification settings
    enabled = models.BooleanField(default=True)
    min_severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='warning')
    
    # Channel configuration
    email_enabled = models.BooleanField(default=True)
    email_address = models.EmailField(blank=True)
    
    telegram_enabled = models.BooleanField(default=False)
    telegram_chat_id = models.CharField(max_length=100, blank=True)
    
    slack_enabled = models.BooleanField(default=False)
    slack_channel = models.CharField(max_length=100, blank=True)
    
    teams_enabled = models.BooleanField(default=False)
    teams_webhook = models.URLField(blank=True)
    
    sms_enabled = models.BooleanField(default=False)
    sms_number = models.CharField(max_length=20, blank=True)
    
    # Timing settings
    quiet_hours_start = models.TimeField(null=True, blank=True, help_text="Start of quiet hours (no notifications)")
    quiet_hours_end = models.TimeField(null=True, blank=True, help_text="End of quiet hours")
    quiet_hours_timezone = models.CharField(max_length=50, default='UTC')
    
    # Escalation settings
    escalation_enabled = models.BooleanField(default=True)
    escalation_interval_minutes = models.IntegerField(default=30)
    max_escalation_level = models.IntegerField(default=3)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_notification_profiles')

    class Meta:
        db_table = 'monitoring_notification_profile'
        verbose_name = 'Notification Profile'
        verbose_name_plural = 'Notification Profiles'
        ordering = ['name']

    def __str__(self):
        return self.name
    
    def get_enabled_channels(self):
        """Get list of enabled notification channels."""
        channels = []
        
        if self.email_enabled and self.email_address:
            channels.append('email')
        
        if self.telegram_enabled and self.telegram_chat_id:
            channels.append('telegram')
        
        if self.slack_enabled and self.slack_channel:
            channels.append('slack')
        
        if self.teams_enabled and self.teams_webhook:
            channels.append('teams')
        
        if self.sms_enabled and self.sms_number:
            channels.append('sms')
        
        return channels
    
    def get_recipients(self):
        """Get recipient addresses for each enabled channel."""
        recipients = {}
        
        if self.email_enabled and self.email_address:
            recipients['email'] = self.email_address
        
        if self.telegram_enabled and self.telegram_chat_id:
            recipients['telegram'] = self.telegram_chat_id
        
        if self.slack_enabled and self.slack_channel:
            recipients['slack'] = self.slack_channel
        
        if self.teams_enabled and self.teams_webhook:
            recipients['teams'] = self.teams_webhook
        
        if self.sms_enabled and self.sms_number:
            recipients['sms'] = self.sms_number
        
        return recipients
    
    def should_notify(self, alert):
        """Check if this profile should send notifications for the given alert."""
        if not self.enabled:
            return False
        
        # Check severity threshold
        severity_levels = {'info': 0, 'warning': 1, 'critical': 2}
        alert_level = severity_levels.get(alert.severity, 0)
        min_level = severity_levels.get(self.min_severity, 1)
        
        if alert_level < min_level:
            return False
        
        # Check quiet hours
        if self.quiet_hours_start and self.quiet_hours_end:
            try:
                from zoneinfo import ZoneInfo
                tz = ZoneInfo(self.quiet_hours_timezone)
                current_time = timezone.now().astimezone(tz).time()
                
                if self.quiet_hours_start <= self.quiet_hours_end:
                    # Same day quiet hours
                    if self.quiet_hours_start <= current_time <= self.quiet_hours_end:
                        return False
                else:
                    # Overnight quiet hours
                    if current_time >= self.quiet_hours_start or current_time <= self.quiet_hours_end:
                        return False
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Error checking quiet hours: {e}")
        
        return True


class NotificationLog(models.Model):
    """
    Log of sent notifications for tracking and debugging.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('failed', 'Failed'),
        ('retrying', 'Retrying'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Notification details
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='notification_logs')
    profile = models.ForeignKey(NotificationProfile, on_delete=models.CASCADE, related_name='notification_logs')
    
    # Channel and recipient
    channel = models.CharField(max_length=20)
    recipient = models.CharField(max_length=255)
    
    # Message content
    subject = models.CharField(max_length=255)
    message = models.TextField()
    
    # Status and timing
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    sent_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    retry_count = models.IntegerField(default=0)
    max_retries = models.IntegerField(default=3)
    
    # Escalation tracking
    escalation_level = models.IntegerField(default=0)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'monitoring_notification_log'
        verbose_name = 'Notification Log'
        verbose_name_plural = 'Notification Logs'
        indexes = [
            models.Index(fields=['alert', 'status']),
            models.Index(fields=['channel', 'status']),
            models.Index(fields=['sent_at']),
            models.Index(fields=['escalation_level']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.channel} notification for {self.alert.title} - {self.status}"
    
    def mark_sent(self):
        """Mark notification as successfully sent."""
        self.status = 'sent'
        self.sent_at = timezone.now()
        self.save(update_fields=['status', 'sent_at', 'updated_at'])
    
    def mark_failed(self, error_message):
        """Mark notification as failed with error message."""
        self.status = 'failed'
        self.error_message = error_message
        self.save(update_fields=['status', 'error_message', 'updated_at'])
    
    def increment_retry(self):
        """Increment retry count and update status."""
        self.retry_count += 1
        
        if self.retry_count >= self.max_retries:
            self.status = 'failed'
            self.error_message = f"Max retries ({self.max_retries}) exceeded"
        else:
            self.status = 'retrying'
        
        self.save(update_fields=['retry_count', 'status', 'error_message', 'updated_at'])


class EscalationRule(models.Model):
    """
    Rules for alert escalation based on various criteria.
    """
    CONDITION_CHOICES = [
        ('time_based', 'Time Based'),
        ('severity_based', 'Severity Based'),
        ('location_based', 'Location Based'),
        ('group_based', 'Group Based'),
        ('check_type_based', 'Check Type Based'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Rule identification
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    priority = models.IntegerField(default=0, help_text="Higher priority rules are evaluated first")
    
    # Conditions
    condition_type = models.CharField(max_length=20, choices=CONDITION_CHOICES)
    condition_config = models.JSONField(default=dict, help_text="Configuration for the condition")
    
    # Escalation settings
    escalation_interval_minutes = models.IntegerField(default=30)
    max_escalation_level = models.IntegerField(default=3)
    
    # Target profiles for each escalation level
    level_1_profiles = models.ManyToManyField(
        NotificationProfile, 
        blank=True, 
        related_name='escalation_level_1_rules'
    )
    level_2_profiles = models.ManyToManyField(
        NotificationProfile, 
        blank=True, 
        related_name='escalation_level_2_rules'
    )
    level_3_profiles = models.ManyToManyField(
        NotificationProfile, 
        blank=True, 
        related_name='escalation_level_3_rules'
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_escalation_rules')

    class Meta:
        db_table = 'monitoring_escalation_rule'
        verbose_name = 'Escalation Rule'
        verbose_name_plural = 'Escalation Rules'
        ordering = ['-priority', 'name']

    def __str__(self):
        return self.name
    
    def matches_alert(self, alert):
        """Check if this escalation rule matches the given alert."""
        if not self.enabled:
            return False
        
        config = self.condition_config
        
        if self.condition_type == 'severity_based':
            required_severities = config.get('severities', [])
            return alert.severity in required_severities
        
        elif self.condition_type == 'location_based':
            required_locations = config.get('location_ids', [])
            return str(alert.host.location.id) in required_locations
        
        elif self.condition_type == 'group_based':
            required_groups = config.get('group_ids', [])
            return str(alert.host.group.id) in required_groups
        
        elif self.condition_type == 'check_type_based':
            required_check_types = config.get('check_types', [])
            return alert.check_type in required_check_types
        
        elif self.condition_type == 'time_based':
            # Time-based rules always match (timing is handled elsewhere)
            return True
        
        return False
    
    def get_profiles_for_level(self, level):
        """Get notification profiles for the specified escalation level."""
        if level == 1:
            return list(self.level_1_profiles.all())
        elif level == 2:
            return list(self.level_2_profiles.all())
        elif level == 3:
            return list(self.level_3_profiles.all())
        else:
            return []