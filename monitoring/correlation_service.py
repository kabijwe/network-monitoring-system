"""
Alert correlation and deduplication service.

This module provides:
- Alert correlation based on host, location, and time
- Alert deduplication to reduce noise
- Root cause analysis for related alerts
- Maintenance window alert suppression
"""
import logging
from typing import List, Dict, Any, Optional, Set
from datetime import timedelta
from django.utils import timezone
from django.db.models import Q, Count
from collections import defaultdict

from .models import Alert, Host, Location, DeviceGroup

logger = logging.getLogger(__name__)


class AlertCorrelationService:
    """Service for correlating and deduplicating alerts."""
    
    # Time window for correlation (minutes)
    CORRELATION_WINDOW_MINUTES = 15
    
    # Maximum alerts to correlate together
    MAX_CORRELATION_GROUP_SIZE = 10
    
    def __init__(self):
        self.correlation_rules = {
            'location_based': self._correlate_by_location,
            'group_based': self._correlate_by_group,
            'check_type_based': self._correlate_by_check_type,
            'cascade_based': self._correlate_cascade_failures,
        }
    
    def process_new_alert(self, alert: Alert) -> Dict[str, Any]:
        """
        Process a new alert for correlation and deduplication.
        
        Args:
            alert: New alert to process
            
        Returns:
            Dictionary with correlation results
        """
        results = {
            'alert_id': str(alert.id),
            'correlated': False,
            'deduplicated': False,
            'suppressed': False,
            'correlation_group': None,
            'actions_taken': []
        }
        
        try:
            # Check if alert should be suppressed due to maintenance
            if self._is_maintenance_suppressed(alert):
                alert.status = 'suppressed'
                alert.save()
                results['suppressed'] = True
                results['actions_taken'].append('maintenance_suppressed')
                logger.info(f"Alert {alert.id} suppressed due to maintenance window")
                return results
            
            # Check for duplicate alerts
            duplicate = self._find_duplicate_alert(alert)
            if duplicate:
                self._handle_duplicate_alert(alert, duplicate)
                results['deduplicated'] = True
                results['actions_taken'].append('deduplicated')
                logger.info(f"Alert {alert.id} deduplicated with {duplicate.id}")
                return results
            
            # Find correlated alerts
            correlated_alerts = self._find_correlated_alerts(alert)
            if correlated_alerts:
                correlation_group = self._create_correlation_group(alert, correlated_alerts)
                results['correlated'] = True
                results['correlation_group'] = correlation_group
                results['actions_taken'].append('correlated')
                logger.info(f"Alert {alert.id} correlated with {len(correlated_alerts)} other alerts")
            
            return results
            
        except Exception as e:
            logger.error(f"Error processing alert correlation for {alert.id}: {e}")
            results['error'] = str(e)
            return results
    
    def _is_maintenance_suppressed(self, alert: Alert) -> bool:
        """Check if alert should be suppressed due to maintenance windows."""
        host = alert.host
        
        # Check host-specific maintenance
        if host.is_in_maintenance():
            return True
        
        # Check location-wide maintenance
        # This would require a MaintenanceWindow model - for now, use host maintenance
        return False
    
    def _find_duplicate_alert(self, alert: Alert) -> Optional[Alert]:
        """Find existing duplicate alert for the same issue."""
        # Look for active alerts on the same host with same check type
        time_threshold = timezone.now() - timedelta(hours=1)
        
        duplicate = Alert.objects.filter(
            host=alert.host,
            check_type=alert.check_type,
            metric_name=alert.metric_name,
            status='active',
            first_seen__gte=time_threshold
        ).exclude(id=alert.id).first()
        
        return duplicate
    
    def _handle_duplicate_alert(self, new_alert: Alert, existing_alert: Alert):
        """Handle a duplicate alert by updating the existing one."""
        # Update existing alert with latest information
        existing_alert.last_seen = timezone.now()
        existing_alert.current_value = new_alert.current_value
        existing_alert.description = new_alert.description
        existing_alert.save()
        
        # Mark new alert as resolved/duplicate
        new_alert.status = 'resolved'
        new_alert.resolved_at = timezone.now()
        new_alert.save()
    
    def _find_correlated_alerts(self, alert: Alert) -> List[Alert]:
        """Find alerts that should be correlated with the given alert."""
        correlated = []
        
        # Define time window for correlation
        time_window_start = timezone.now() - timedelta(minutes=self.CORRELATION_WINDOW_MINUTES)
        
        # Get active alerts within time window
        candidate_alerts = Alert.objects.filter(
            status='active',
            first_seen__gte=time_window_start
        ).exclude(id=alert.id).select_related('host', 'host__location', 'host__group')
        
        # Apply correlation rules
        for rule_name, rule_func in self.correlation_rules.items():
            rule_matches = rule_func(alert, candidate_alerts)
            correlated.extend(rule_matches)
        
        # Remove duplicates and limit size
        correlated = list(set(correlated))[:self.MAX_CORRELATION_GROUP_SIZE]
        
        return correlated
    
    def _correlate_by_location(self, alert: Alert, candidates: List[Alert]) -> List[Alert]:
        """Correlate alerts from the same location."""
        location_alerts = []
        
        for candidate in candidates:
            if (candidate.host.location == alert.host.location and 
                candidate.severity in ['warning', 'critical']):
                location_alerts.append(candidate)
        
        # Only correlate if there are multiple alerts in the location
        return location_alerts if len(location_alerts) >= 2 else []
    
    def _correlate_by_group(self, alert: Alert, candidates: List[Alert]) -> List[Alert]:
        """Correlate alerts from the same device group."""
        group_alerts = []
        
        for candidate in candidates:
            if (candidate.host.group == alert.host.group and 
                candidate.check_type == alert.check_type):
                group_alerts.append(candidate)
        
        return group_alerts if len(group_alerts) >= 2 else []
    
    def _correlate_by_check_type(self, alert: Alert, candidates: List[Alert]) -> List[Alert]:
        """Correlate alerts of the same check type across multiple hosts."""
        check_type_alerts = []
        
        for candidate in candidates:
            if (candidate.check_type == alert.check_type and 
                candidate.metric_name == alert.metric_name and
                candidate.severity == alert.severity):
                check_type_alerts.append(candidate)
        
        return check_type_alerts if len(check_type_alerts) >= 3 else []
    
    def _correlate_cascade_failures(self, alert: Alert, candidates: List[Alert]) -> List[Alert]:
        """Correlate alerts that might be cascade failures."""
        cascade_alerts = []
        
        # Look for ping failures that might be caused by network issues
        if alert.check_type == 'ping' and alert.severity == 'critical':
            for candidate in candidates:
                if (candidate.check_type == 'ping' and 
                    candidate.severity == 'critical' and
                    candidate.host.location == alert.host.location):
                    cascade_alerts.append(candidate)
        
        return cascade_alerts if len(cascade_alerts) >= 2 else []
    
    def _create_correlation_group(self, primary_alert: Alert, correlated_alerts: List[Alert]) -> Dict[str, Any]:
        """Create a correlation group for related alerts."""
        group_id = f"corr_{primary_alert.id}_{int(timezone.now().timestamp())}"
        
        # Update all alerts with correlation information
        correlation_data = {
            'correlation_group_id': group_id,
            'correlation_primary': str(primary_alert.id),
            'correlation_count': len(correlated_alerts) + 1,
            'correlation_created': timezone.now().isoformat()
        }
        
        # Update primary alert
        if not primary_alert.additional_data:
            primary_alert.additional_data = {}
        primary_alert.additional_data.update(correlation_data)
        primary_alert.save()
        
        # Update correlated alerts
        for alert in correlated_alerts:
            if not alert.additional_data:
                alert.additional_data = {}
            alert.additional_data.update(correlation_data)
            alert.save()
        
        return {
            'group_id': group_id,
            'primary_alert': str(primary_alert.id),
            'correlated_alerts': [str(a.id) for a in correlated_alerts],
            'total_count': len(correlated_alerts) + 1
        }
    
    def get_correlation_summary(self, time_hours: int = 24) -> Dict[str, Any]:
        """Get correlation summary for the specified time period."""
        time_threshold = timezone.now() - timedelta(hours=time_hours)
        
        # Get alerts with correlation data
        correlated_alerts = Alert.objects.filter(
            first_seen__gte=time_threshold,
            additional_data__has_key='correlation_group_id'
        )
        
        # Group by correlation group
        groups = defaultdict(list)
        for alert in correlated_alerts:
            group_id = alert.additional_data.get('correlation_group_id')
            if group_id:
                groups[group_id].append(alert)
        
        # Get suppressed alerts
        suppressed_count = Alert.objects.filter(
            first_seen__gte=time_threshold,
            status='suppressed'
        ).count()
        
        # Get deduplicated alerts (resolved within short time)
        deduplicated_count = Alert.objects.filter(
            first_seen__gte=time_threshold,
            status='resolved',
            resolved_at__lte=timezone.now() - timedelta(minutes=5)
        ).count()
        
        return {
            'time_period_hours': time_hours,
            'correlation_groups': len(groups),
            'correlated_alerts': len(correlated_alerts),
            'suppressed_alerts': suppressed_count,
            'deduplicated_alerts': deduplicated_count,
            'groups_detail': [
                {
                    'group_id': group_id,
                    'alert_count': len(alerts),
                    'primary_alert': alerts[0].additional_data.get('correlation_primary'),
                    'locations': list(set(a.host.location.name for a in alerts)),
                    'check_types': list(set(a.check_type for a in alerts))
                }
                for group_id, alerts in groups.items()
            ]
        }
    
    def cleanup_old_correlations(self, days: int = 7) -> Dict[str, Any]:
        """Clean up old correlation data from resolved alerts."""
        cutoff_date = timezone.now() - timedelta(days=days)
        
        # Find old resolved alerts with correlation data
        old_alerts = Alert.objects.filter(
            status='resolved',
            resolved_at__lt=cutoff_date,
            additional_data__has_key='correlation_group_id'
        )
        
        cleaned_count = 0
        for alert in old_alerts:
            # Remove correlation data
            if 'correlation_group_id' in alert.additional_data:
                del alert.additional_data['correlation_group_id']
            if 'correlation_primary' in alert.additional_data:
                del alert.additional_data['correlation_primary']
            if 'correlation_count' in alert.additional_data:
                del alert.additional_data['correlation_count']
            if 'correlation_created' in alert.additional_data:
                del alert.additional_data['correlation_created']
            
            alert.save()
            cleaned_count += 1
        
        logger.info(f"Cleaned correlation data from {cleaned_count} old alerts")
        
        return {
            'cleaned_count': cleaned_count,
            'cutoff_date': cutoff_date.isoformat()
        }
    
    def force_correlate_alerts(self, alert_ids: List[str], primary_alert_id: str) -> Dict[str, Any]:
        """Manually correlate a set of alerts."""
        try:
            alerts = Alert.objects.filter(id__in=alert_ids)
            primary_alert = Alert.objects.get(id=primary_alert_id)
            
            if primary_alert not in alerts:
                return {
                    'success': False,
                    'error': 'Primary alert must be in the alert list'
                }
            
            # Remove primary from correlated list
            correlated_alerts = [a for a in alerts if a.id != primary_alert.id]
            
            # Create correlation group
            correlation_group = self._create_correlation_group(primary_alert, correlated_alerts)
            
            return {
                'success': True,
                'correlation_group': correlation_group
            }
            
        except Exception as e:
            logger.error(f"Error in manual correlation: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def break_correlation_group(self, group_id: str) -> Dict[str, Any]:
        """Break apart a correlation group."""
        try:
            # Find all alerts in the group
            alerts = Alert.objects.filter(
                additional_data__correlation_group_id=group_id
            )
            
            updated_count = 0
            for alert in alerts:
                # Remove correlation data
                if alert.additional_data:
                    alert.additional_data.pop('correlation_group_id', None)
                    alert.additional_data.pop('correlation_primary', None)
                    alert.additional_data.pop('correlation_count', None)
                    alert.additional_data.pop('correlation_created', None)
                    alert.save()
                    updated_count += 1
            
            logger.info(f"Broke correlation group {group_id}, updated {updated_count} alerts")
            
            return {
                'success': True,
                'group_id': group_id,
                'updated_alerts': updated_count
            }
            
        except Exception as e:
            logger.error(f"Error breaking correlation group {group_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }


# Global correlation service instance
correlation_service = AlertCorrelationService()