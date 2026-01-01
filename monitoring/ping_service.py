"""
Ping monitoring service that integrates with Django models.

This service provides ping monitoring functionality that works with
the Host and PingResult models, including status updates and alerting.
"""
import asyncio
import logging
import time
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import transaction
from django.conf import settings
from .models import Host, PingResult, Alert
from .ping_monitor import PingMonitor, PingResult as PingResultData, PingThresholds

logger = logging.getLogger(__name__)


class PingMonitoringService:
    """
    Service for managing ping monitoring of hosts with database integration.
    """
    
    def __init__(self):
        """Initialize the ping monitoring service."""
        self.ping_monitor = PingMonitor()
        
        # Get monitoring settings
        monitoring_settings = getattr(settings, 'MONITORING_SETTINGS', {})
        self.max_concurrent_pings = monitoring_settings.get('MAX_CONCURRENT_PINGS', 50)
        self.ping_history_retention_days = monitoring_settings.get('PING_HISTORY_RETENTION_DAYS', 30)
        
    async def ping_host(self, host: Host) -> PingResult:
        """
        Ping a single host and store the result.
        
        Args:
            host: Host model instance to ping
            
        Returns:
            PingResult model instance with the ping results
        """
        if not host.ping_enabled or not host.monitoring_enabled:
            logger.debug(f"Ping monitoring disabled for host {host.hostname}")
            return None
        
        # Skip if host is in maintenance
        if host.in_maintenance and host.is_in_maintenance():
            logger.debug(f"Host {host.hostname} is in maintenance, skipping ping")
            return None
        
        try:
            # Get host-specific thresholds
            thresholds = host.get_ping_thresholds()
            self.ping_monitor.thresholds = thresholds
            
            # Perform ping
            start_time = time.time()
            ping_result = await self.ping_monitor.ping_host(host.hostname, host.ip_address)
            check_duration = time.time() - start_time
            
            # Evaluate status
            status = self.ping_monitor.evaluate_status(ping_result)
            status_details = self.ping_monitor.get_status_details(ping_result)
            
            # Create PingResult record
            with transaction.atomic():
                db_result = PingResult.objects.create(
                    host=host,
                    success=ping_result.success,
                    latency=ping_result.latency,
                    packet_loss=ping_result.packet_loss,
                    packets_sent=ping_result.packets_sent,
                    packets_received=ping_result.packets_received,
                    status=status,
                    status_reason=status_details.get('status_reason', ''),
                    error_message=ping_result.error_message or '',
                    check_duration=check_duration
                )
                
                # Update host status and timestamps
                old_status = host.status
                host.status = status if not host.in_maintenance else 'maintenance'
                host.last_check = timezone.now()
                
                if ping_result.success:
                    host.last_seen = timezone.now()
                
                host.save(update_fields=['status', 'last_check', 'last_seen'])
                
                # Handle status changes and alerting
                await self._handle_status_change(host, old_status, status, ping_result, status_details)
                
                logger.info(f"Ping completed for {host.hostname}: {status} (latency: {ping_result.latency}ms, loss: {ping_result.packet_loss}%)")
                
                return db_result
                
        except Exception as e:
            logger.error(f"Error pinging host {host.hostname}: {e}")
            
            # Create error result
            with transaction.atomic():
                db_result = PingResult.objects.create(
                    host=host,
                    success=False,
                    packet_loss=100.0,
                    packets_sent=host.ping_packet_count,
                    packets_received=0,
                    status='down',
                    status_reason='Ping check failed',
                    error_message=str(e),
                    check_duration=time.time() - start_time if 'start_time' in locals() else None
                )
                
                # Update host status
                old_status = host.status
                host.status = 'down' if not host.in_maintenance else 'maintenance'
                host.last_check = timezone.now()
                host.save(update_fields=['status', 'last_check'])
                
                # Handle status change
                await self._handle_status_change(host, old_status, 'down', None, {'status_reason': f'Ping check failed: {str(e)}'})
                
                return db_result
    
    async def ping_multiple_hosts(self, hosts: List[Host]) -> List[PingResult]:
        """
        Ping multiple hosts concurrently.
        
        Args:
            hosts: List of Host model instances to ping
            
        Returns:
            List of PingResult model instances
        """
        # Filter hosts that should be pinged
        pingable_hosts = [
            host for host in hosts 
            if host.ping_enabled and host.monitoring_enabled and not (host.in_maintenance and host.is_in_maintenance())
        ]
        
        if not pingable_hosts:
            logger.info("No hosts to ping")
            return []
        
        logger.info(f"Starting ping monitoring for {len(pingable_hosts)} hosts")
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent_pings)
        
        async def ping_with_semaphore(host: Host) -> PingResult:
            async with semaphore:
                return await self.ping_host(host)
        
        # Execute pings concurrently
        tasks = [ping_with_semaphore(host) for host in pingable_hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and handle exceptions
        ping_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                host = pingable_hosts[i]
                logger.error(f"Ping task failed for {host.hostname}: {result}")
                # Create error result
                try:
                    error_result = PingResult.objects.create(
                        host=host,
                        success=False,
                        packet_loss=100.0,
                        packets_sent=host.ping_packet_count,
                        packets_received=0,
                        status='down',
                        status_reason='Ping task failed',
                        error_message=str(result)
                    )
                    ping_results.append(error_result)
                except Exception as e:
                    logger.error(f"Failed to create error result for {host.hostname}: {e}")
            elif result is not None:
                ping_results.append(result)
        
        logger.info(f"Completed ping monitoring for {len(ping_results)} hosts")
        return ping_results
    
    async def ping_all_hosts(self) -> List[PingResult]:
        """
        Ping all hosts that have ping monitoring enabled.
        
        Returns:
            List of PingResult model instances
        """
        hosts = Host.objects.filter(
            monitoring_enabled=True,
            ping_enabled=True
        ).select_related('location', 'group')
        
        return await self.ping_multiple_hosts(list(hosts))
    
    async def _handle_status_change(self, host: Host, old_status: str, new_status: str, 
                                  ping_result: Optional[PingResultData], status_details: Dict[str, Any]):
        """
        Handle host status changes and create alerts if necessary.
        
        Args:
            host: Host that changed status
            old_status: Previous status
            new_status: New status
            ping_result: Ping result data
            status_details: Status evaluation details
        """
        if old_status == new_status:
            return
        
        logger.info(f"Host {host.hostname} status changed: {old_status} -> {new_status}")
        
        # Clear acknowledgment if host recovered
        if old_status in ['down', 'critical', 'warning'] and new_status == 'up':
            if host.acknowledged:
                host.acknowledged = False
                host.acknowledged_by = None
                host.acknowledged_at = None
                host.acknowledgment_comment = ''
                host.save(update_fields=['acknowledged', 'acknowledged_by', 'acknowledged_at', 'acknowledgment_comment'])
                logger.info(f"Cleared acknowledgment for recovered host {host.hostname}")
        
        # Create or update alerts
        await self._manage_alerts(host, old_status, new_status, ping_result, status_details)
    
    async def _manage_alerts(self, host: Host, old_status: str, new_status: str,
                           ping_result: Optional[PingResultData], status_details: Dict[str, Any]):
        """
        Manage alerts based on status changes.
        
        Args:
            host: Host that changed status
            old_status: Previous status
            new_status: New status
            ping_result: Ping result data
            status_details: Status evaluation details
        """
        # Resolve existing alerts if host is up
        if new_status == 'up':
            active_alerts = Alert.objects.filter(
                host=host,
                status='active',
                check_type='ping'
            )
            
            for alert in active_alerts:
                alert.resolve()
                logger.info(f"Resolved alert {alert.id} for host {host.hostname}")
            
            return
        
        # Create new alert for problematic status
        if new_status in ['down', 'critical', 'warning']:
            # Check if there's already an active alert
            existing_alert = Alert.objects.filter(
                host=host,
                status='active',
                check_type='ping'
            ).first()
            
            if existing_alert:
                # Update existing alert
                existing_alert.last_seen = timezone.now()
                existing_alert.description = status_details.get('status_reason', f'Host is {new_status}')
                if ping_result:
                    existing_alert.current_value = ping_result.latency or ping_result.packet_loss
                existing_alert.save()
                logger.info(f"Updated existing alert {existing_alert.id} for host {host.hostname}")
            else:
                # Create new alert
                severity_map = {
                    'warning': 'warning',
                    'critical': 'critical',
                    'down': 'critical'
                }
                
                title = f"Host {host.hostname} is {new_status.upper()}"
                description = status_details.get('status_reason', f'Host is {new_status}')
                
                alert = Alert.objects.create(
                    host=host,
                    title=title,
                    description=description,
                    severity=severity_map.get(new_status, 'warning'),
                    check_type='ping',
                    metric_name='ping_status',
                    current_value=ping_result.latency if ping_result and ping_result.latency else ping_result.packet_loss if ping_result else None
                )
                
                logger.info(f"Created new alert {alert.id} for host {host.hostname}: {title}")
                
                # Process alert correlation and deduplication
                try:
                    from .correlation_service import correlation_service
                    correlation_result = correlation_service.process_new_alert(alert)
                    logger.info(f"Alert correlation result for {alert.id}: {correlation_result}")
                except Exception as e:
                    logger.error(f"Error processing alert correlation for {alert.id}: {e}")
                
                # Trigger notification for new alert (only if not suppressed or deduplicated)
                if alert.status == 'active':
                    try:
                        from .tasks.notification_tasks import send_alert_notification
                        send_alert_notification.delay(str(alert.id))
                    except Exception as e:
                        logger.error(f"Failed to trigger notification for alert {alert.id}: {e}")
    
    def cleanup_old_ping_results(self, days: Optional[int] = None) -> int:
        """
        Clean up old ping results to manage database size.
        
        Args:
            days: Number of days to retain (defaults to configured retention)
            
        Returns:
            Number of records deleted
        """
        retention_days = days or self.ping_history_retention_days
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        
        deleted_count, _ = PingResult.objects.filter(
            timestamp__lt=cutoff_date
        ).delete()
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old ping results older than {retention_days} days")
        
        return deleted_count
    
    def get_host_ping_summary(self, host: Host, hours: int = 24) -> Dict[str, Any]:
        """
        Get ping summary statistics for a host.
        
        Args:
            host: Host to get summary for
            hours: Number of hours to look back
            
        Returns:
            Dictionary with ping statistics
        """
        since = timezone.now() - timedelta(hours=hours)
        
        ping_results = PingResult.objects.filter(
            host=host,
            timestamp__gte=since
        ).order_by('-timestamp')
        
        if not ping_results.exists():
            return {
                'total_checks': 0,
                'success_rate': 0.0,
                'avg_latency': None,
                'avg_packet_loss': 0.0,
                'status_distribution': {},
                'last_check': None,
                'current_status': host.status
            }
        
        total_checks = ping_results.count()
        successful_checks = ping_results.filter(success=True).count()
        success_rate = (successful_checks / total_checks) * 100
        
        # Calculate averages for successful pings
        successful_pings = ping_results.filter(success=True, latency__isnull=False)
        avg_latency = None
        if successful_pings.exists():
            latencies = [r.latency for r in successful_pings if r.latency is not None]
            avg_latency = sum(latencies) / len(latencies) if latencies else None
        
        # Calculate average packet loss
        packet_losses = [r.packet_loss for r in ping_results]
        avg_packet_loss = sum(packet_losses) / len(packet_losses) if packet_losses else 0.0
        
        # Status distribution
        status_counts = {}
        for result in ping_results:
            status_counts[result.status] = status_counts.get(result.status, 0) + 1
        
        return {
            'total_checks': total_checks,
            'success_rate': round(success_rate, 2),
            'avg_latency': round(avg_latency, 2) if avg_latency else None,
            'avg_packet_loss': round(avg_packet_loss, 2),
            'status_distribution': status_counts,
            'last_check': ping_results.first().timestamp,
            'current_status': host.status
        }


# Convenience functions for synchronous usage
def ping_host_sync(host: Host) -> PingResult:
    """Synchronous wrapper for ping_host."""
    try:
        # Try to get the current event loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If there's already a running loop, we need to run in a thread
            import concurrent.futures
            import threading
            
            def run_in_thread():
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                try:
                    service = PingMonitoringService()
                    return new_loop.run_until_complete(service.ping_host(host))
                finally:
                    new_loop.close()
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(run_in_thread)
                return future.result(timeout=30)
        else:
            # No running loop, we can use asyncio.run
            service = PingMonitoringService()
            return asyncio.run(service.ping_host(host))
    except RuntimeError:
        # No event loop, create one
        service = PingMonitoringService()
        return asyncio.run(service.ping_host(host))


def ping_multiple_hosts_sync(hosts: List[Host]) -> List[PingResult]:
    """Synchronous wrapper for ping_multiple_hosts."""
    try:
        # Try to get the current event loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If there's already a running loop, we need to run in a thread
            import concurrent.futures
            import threading
            
            def run_in_thread():
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                try:
                    service = PingMonitoringService()
                    return new_loop.run_until_complete(service.ping_multiple_hosts(hosts))
                finally:
                    new_loop.close()
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(run_in_thread)
                return future.result(timeout=60)
        else:
            # No running loop, we can use asyncio.run
            service = PingMonitoringService()
            return asyncio.run(service.ping_multiple_hosts(hosts))
    except RuntimeError:
        # No event loop, create one
        service = PingMonitoringService()
        return asyncio.run(service.ping_multiple_hosts(hosts))


def ping_all_hosts_sync() -> List[PingResult]:
    """Synchronous wrapper for ping_all_hosts."""
    try:
        # Try to get the current event loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If there's already a running loop, we need to run in a thread
            import concurrent.futures
            import threading
            
            def run_in_thread():
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                try:
                    service = PingMonitoringService()
                    return new_loop.run_until_complete(service.ping_all_hosts())
                finally:
                    new_loop.close()
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(run_in_thread)
                return future.result(timeout=120)
        else:
            # No running loop, we can use asyncio.run
            service = PingMonitoringService()
            return asyncio.run(service.ping_all_hosts())
    except RuntimeError:
        # No event loop, create one
        service = PingMonitoringService()
        return asyncio.run(service.ping_all_hosts())