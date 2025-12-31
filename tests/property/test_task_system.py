"""
Property-based tests for Celery task system functionality.

This module contains property-based tests that validate the correctness
of the Celery task system including task scheduling, execution, error handling,
and monitoring task orchestration.

Tests validate Properties 14-15 from the design document:
- Property 14: Ping monitoring completeness (task execution)
- Property 15: SNMP protocol support (task execution)
"""

# Configure Django settings if not already configured
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nms.settings')

import django
django.setup()

import pytest
import asyncio
import time
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from hypothesis import given, strategies as st, settings, assume, example
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, invariant
from hypothesis.extra.django import TestCase as HypothesisTestCase
from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from datetime import datetime, timedelta
from celery import current_app
from celery.result import AsyncResult

from monitoring.models import Host, Location, DeviceGroup, PingResult, MonitoringMetric
from monitoring.tasks import (
    ping_monitoring_task, snmp_monitoring_task, service_monitoring_task,
    schedule_monitoring_tasks, process_alert_escalations, cleanup_old_data,
    health_check_task, get_task_status, schedule_host_monitoring,
    get_monitoring_statistics
)
from nms.celery import app, get_celery_worker_status, get_task_queue_lengths


# Test data strategies
@st.composite
def valid_host_data(draw):
    """Generate valid host data for task testing."""
    hostname = draw(st.text(min_size=1, max_size=50, alphabet=st.characters(
        whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-.'
    )).filter(lambda x: x and not x.startswith('.') and not x.endswith('.')))
    
    # Generate valid IP address
    ip_parts = [draw(st.integers(min_value=1, max_value=254)) for _ in range(4)]
    ip_address = '.'.join(map(str, ip_parts))
    
    return {
        'hostname': hostname,
        'ip_address': ip_address,
        'monitoring_enabled': draw(st.booleans()),
        'ping_enabled': draw(st.booleans()),
        'snmp_enabled': draw(st.booleans()),
        'service_checks_enabled': draw(st.booleans())
    }


@st.composite
def task_configuration_strategy(draw):
    """Generate task configuration parameters."""
    return {
        'max_retries': draw(st.integers(min_value=0, max_value=5)),
        'retry_delay': draw(st.integers(min_value=10, max_value=300)),
        'timeout': draw(st.integers(min_value=30, max_value=600))
    }


class TestTaskSystemProperties(HypothesisTestCase):
    """Property-based tests for Celery task system."""
    
    def setUp(self):
        """Set up test environment."""
        self.location = Location.objects.create(
            name="Task Test Location",
            address="Task Test Address"
        )
        self.group = DeviceGroup.objects.create(
            name="Task Test Group",
            description="Task test group"
        )
    
    @given(host_data=valid_host_data())
    @settings(max_examples=30, deadline=10000)
    def test_property_ping_task_execution_completeness(self, host_data):
        """
        Property 14: Ping monitoring completeness (task execution)
        
        For any host with ping monitoring enabled, the ping monitoring task
        should execute completely and produce consistent results.
        """
        # Create host
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            **host_data
        )
        
        # Mock ping execution
        with patch('monitoring.tasks.ping_host_sync') as mock_ping, \
             patch('monitoring.tasks.PingResult.objects.create') as mock_create:
            
            # Configure mock ping result
            from monitoring.ping_monitor import PingResult as PingResultData
            mock_ping_result = PingResultData(
                success=True,
                latency=50.0,
                packet_loss=0.0,
                packets_sent=4,
                packets_received=4,
                error_message=''
            )
            mock_ping.return_value = mock_ping_result
            
            # Mock database creation
            mock_db_result = Mock()
            mock_db_result.id = 1
            mock_create.return_value = mock_db_result
            
            # Execute ping monitoring task
            result = ping_monitoring_task(str(host.id))
            
            # Verify task execution completeness
            assert isinstance(result, dict)
            assert 'status' in result
            assert 'host' in result
            
            if host.monitoring_enabled and host.ping_enabled:
                # Should execute ping monitoring
                assert result['status'] in ['success', 'error', 'failed']
                assert result['host'] == host.hostname
                
                if result['status'] == 'success':
                    assert 'result' in result
                    assert 'success' in result['result']
                    assert 'latency' in result['result']
                    assert 'packet_loss' in result['result']
                    assert 'status' in result['result']
                    
                    # Verify ping was called with correct parameters
                    mock_ping.assert_called_once_with(
                        host.hostname,
                        host.ip_address,
                        host.get_ping_thresholds()
                    )
                    
                    # Verify database record was created
                    mock_create.assert_called_once()
                    
            else:
                # Should be disabled
                assert result['status'] == 'disabled'
    
    @given(host_data=valid_host_data())
    @settings(max_examples=20, deadline=10000)
    def test_property_snmp_task_execution_completeness(self, host_data):
        """
        Property 15: SNMP protocol support (task execution)
        
        For any host with SNMP monitoring enabled, the SNMP monitoring task
        should execute and handle all configured collectors properly.
        """
        # Create host
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            **host_data
        )
        
        # Mock SNMP availability and execution
        with patch('monitoring.tasks.is_snmp_available') as mock_available, \
             patch('monitoring.tasks.collect_snmp_metrics') as mock_collect:
            
            mock_available.return_value = True
            
            # Configure mock SNMP results
            mock_results = {
                'system_metrics': Mock(success=True, metrics={'sysUpTime': 12345}),
                'interface_metrics': Mock(success=True, metrics={'ifInOctets': 1000}),
                'environmental_metrics': Mock(success=False, error_message='Timeout')
            }
            
            # Create async mock for collect_snmp_metrics
            async def mock_collect_async(host_obj, collectors=None):
                return mock_results
            
            mock_collect.return_value = mock_collect_async(host)
            
            # Execute SNMP monitoring task
            result = snmp_monitoring_task(str(host.id))
            
            # Verify task execution completeness
            assert isinstance(result, dict)
            assert 'status' in result
            assert 'host' in result
            
            if host.monitoring_enabled and host.snmp_enabled:
                # Should execute SNMP monitoring
                assert result['status'] in ['success', 'error', 'failed']
                assert result['host'] == host.hostname
                
                if result['status'] == 'success':
                    assert 'results' in result
                    
                    # Verify result structure
                    for collector_name, collector_result in result['results'].items():
                        assert isinstance(collector_result, dict)
                        assert 'success' in collector_result
                        assert 'error_message' in collector_result
                        assert 'metrics_count' in collector_result
                        
                        # Verify metrics count is non-negative
                        assert collector_result['metrics_count'] >= 0
                        
            else:
                # Should be disabled
                assert result['status'] == 'disabled'
    
    @given(host_data=valid_host_data())
    @settings(max_examples=20, deadline=10000)
    def test_property_service_task_execution_completeness(self, host_data):
        """
        Property: Service monitoring task execution completeness
        
        For any host with service monitoring enabled, the service monitoring task
        should execute and handle all configured services properly.
        """
        # Create host
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            tcp_ports='80,443',
            udp_ports='53',
            http_urls='http://example.com',
            **host_data
        )
        
        # Mock service monitoring execution
        with patch('monitoring.tasks.check_host_services') as mock_check:
            
            # Configure mock service results
            from monitoring.service_monitor import ServiceCheckResult
            mock_results = {
                'tcp_ports': [
                    ServiceCheckResult(success=True, response_time=10.0),
                    ServiceCheckResult(success=True, response_time=15.0)
                ],
                'udp_ports': [
                    ServiceCheckResult(success=True, response_time=5.0)
                ],
                'http_endpoints': [
                    ServiceCheckResult(success=True, response_time=200.0, status_code=200)
                ]
            }
            
            # Create async mock
            async def mock_check_async(host_obj):
                return mock_results
            
            mock_check.return_value = mock_check_async(host)
            
            # Execute service monitoring task
            result = service_monitoring_task(str(host.id))
            
            # Verify task execution completeness
            assert isinstance(result, dict)
            assert 'status' in result
            assert 'host' in result
            
            if host.monitoring_enabled and host.service_checks_enabled:
                # Should execute service monitoring
                assert result['status'] in ['success', 'error', 'failed']
                assert result['host'] == host.hostname
                
                if result['status'] == 'success':
                    assert 'results' in result
                    
                    # Verify result structure
                    for service_type, service_results in result['results'].items():
                        assert service_type in ['tcp_ports', 'udp_ports', 'http_endpoints']
                        assert isinstance(service_results, list)
                        
                        for service_result in service_results:
                            assert isinstance(service_result, dict)
                            assert 'success' in service_result
                            assert 'response_time' in service_result
                            assert 'error_message' in service_result
                            
                            # Verify response time is non-negative
                            assert service_result['response_time'] >= 0
                            
            else:
                # Should be disabled
                assert result['status'] == 'disabled'
    
    @given(
        num_hosts=st.integers(min_value=0, max_value=10),
        monitoring_enabled_ratio=st.floats(min_value=0.0, max_value=1.0)
    )
    @settings(max_examples=20, deadline=10000)
    def test_property_task_scheduling_consistency(self, num_hosts, monitoring_enabled_ratio):
        """
        Property: Task scheduling consistency
        
        The task scheduler should consistently schedule tasks for all enabled hosts
        and return accurate statistics about scheduled tasks.
        """
        # Clear existing hosts
        Host.objects.filter(location=self.location).delete()
        
        # Create hosts with varying monitoring settings
        hosts = []
        for i in range(num_hosts):
            monitoring_enabled = i < (num_hosts * monitoring_enabled_ratio)
            
            host = Host.objects.create(
                location=self.location,
                group=self.group,
                hostname=f'test-host-{i}',
                ip_address=f'192.168.1.{i + 1}',
                monitoring_enabled=monitoring_enabled,
                ping_enabled=monitoring_enabled,
                snmp_enabled=monitoring_enabled and (i % 2 == 0),  # Half have SNMP
                service_checks_enabled=monitoring_enabled and (i % 3 == 0)  # Third have services
            )
            hosts.append(host)
        
        # Mock task execution
        with patch('monitoring.tasks.ping_monitoring_task.delay') as mock_ping, \
             patch('monitoring.tasks.snmp_monitoring_task.delay') as mock_snmp, \
             patch('monitoring.tasks.service_monitoring_task.delay') as mock_service, \
             patch('monitoring.tasks.is_snmp_available') as mock_snmp_available:
            
            mock_snmp_available.return_value = True
            
            # Configure mock task results
            mock_task_result = Mock()
            mock_task_result.id = 'test-task-id'
            mock_ping.return_value = mock_task_result
            mock_snmp.return_value = mock_task_result
            mock_service.return_value = mock_task_result
            
            # Execute task scheduling
            result = schedule_monitoring_tasks()
            
            # Verify scheduling consistency
            assert isinstance(result, dict)
            assert 'status' in result
            assert 'scheduled_tasks' in result
            assert 'total_hosts' in result
            
            if result['status'] == 'success':
                scheduled = result['scheduled_tasks']
                
                # Verify task counts are consistent with host configuration
                enabled_hosts = [h for h in hosts if h.monitoring_enabled]
                ping_enabled_hosts = [h for h in enabled_hosts if h.ping_enabled]
                snmp_enabled_hosts = [h for h in enabled_hosts if h.snmp_enabled]
                service_enabled_hosts = [h for h in enabled_hosts if h.service_checks_enabled]
                
                assert scheduled['ping'] == len(ping_enabled_hosts)
                assert scheduled['snmp'] == len(snmp_enabled_hosts)
                assert scheduled['service'] == len(service_enabled_hosts)
                
                # Verify total hosts count (function returns count of monitoring-enabled hosts)
                assert result['total_hosts'] == len(enabled_hosts)
                
                # Verify task scheduling calls
                assert mock_ping.call_count == len(ping_enabled_hosts)
                assert mock_snmp.call_count == len(snmp_enabled_hosts)
                assert mock_service.call_count == len(service_enabled_hosts)
    
    @given(task_config=task_configuration_strategy())
    @settings(max_examples=20, deadline=5000)
    def test_property_task_error_handling_consistency(self, task_config):
        """
        Property: Task error handling consistency
        
        Tasks should handle errors consistently and provide proper error information
        regardless of the type of error encountered.
        """
        # Create test host
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            hostname='error-test-host',
            ip_address='192.168.1.100',
            monitoring_enabled=True,
            ping_enabled=True
        )
        
        # Test various error scenarios
        error_scenarios = [
            Exception("Generic error"),
            ConnectionError("Connection failed"),
            TimeoutError("Operation timed out"),
            ValueError("Invalid value"),
        ]
        
        for error in error_scenarios:
            with patch('monitoring.tasks.ping_host_sync') as mock_ping:
                mock_ping.side_effect = error
                
                # Execute task (should handle error gracefully)
                result = ping_monitoring_task(str(host.id))
                
                # Verify error handling consistency
                assert isinstance(result, dict)
                assert 'status' in result
                
                # Should not crash, should return error status
                assert result['status'] in ['error', 'failed']
                
                if 'message' in result:
                    # Error message should contain information about the error
                    assert isinstance(result['message'], str)
                    assert len(result['message']) > 0
    
    def test_property_task_status_tracking_consistency(self):
        """
        Property: Task status tracking consistency
        
        Task status tracking should provide consistent information about
        task execution state and results.
        """
        # Test with mock task ID
        test_task_id = 'test-task-12345'
        
        # Mock AsyncResult
        with patch('monitoring.tasks.AsyncResult') as mock_async_result:
            mock_result = Mock()
            mock_result.status = 'SUCCESS'
            mock_result.result = {'test': 'data'}
            mock_result.traceback = None
            mock_result.successful.return_value = True
            mock_result.failed.return_value = False
            
            mock_async_result.return_value = mock_result
            
            # Get task status
            status = get_task_status(test_task_id)
            
            # Verify status consistency
            assert isinstance(status, dict)
            assert 'task_id' in status
            assert 'status' in status
            assert 'result' in status
            assert 'traceback' in status
            assert 'successful' in status
            assert 'failed' in status
            
            assert status['task_id'] == test_task_id
            assert status['status'] == 'SUCCESS'
            assert status['result'] == {'test': 'data'}
            assert status['successful'] is True
            assert status['failed'] is False
    
    def test_property_monitoring_statistics_consistency(self):
        """
        Property: Monitoring statistics consistency
        
        Monitoring statistics should provide consistent and accurate
        information about the system state.
        """
        # Create test data
        host1 = Host.objects.create(
            location=self.location,
            group=self.group,
            hostname='stats-host-1',
            ip_address='192.168.1.101',
            monitoring_enabled=True,
            ping_enabled=True,
            snmp_enabled=True,
            service_checks_enabled=False
        )
        
        host2 = Host.objects.create(
            location=self.location,
            group=self.group,
            hostname='stats-host-2',
            ip_address='192.168.1.102',
            monitoring_enabled=False,
            ping_enabled=False,
            snmp_enabled=False,
            service_checks_enabled=False
        )
        
        # Get monitoring statistics
        stats = get_monitoring_statistics()
        
        # Verify statistics consistency
        assert isinstance(stats, dict)
        assert 'hosts' in stats
        assert 'alerts' in stats
        assert 'monitoring_data' in stats
        assert 'system' in stats
        
        # Verify host statistics
        host_stats = stats['hosts']
        assert 'total' in host_stats
        assert 'monitoring_enabled' in host_stats
        assert 'ping_enabled' in host_stats
        assert 'snmp_enabled' in host_stats
        assert 'service_checks_enabled' in host_stats
        
        # Verify counts are consistent
        assert host_stats['total'] >= 2  # At least our test hosts
        assert host_stats['monitoring_enabled'] >= 1  # At least host1
        assert host_stats['ping_enabled'] >= 1  # At least host1
        assert host_stats['snmp_enabled'] >= 1  # At least host1
        
        # All counts should be non-negative
        for key, value in host_stats.items():
            assert isinstance(value, int)
            assert value >= 0
        
        # Monitoring enabled should be <= total
        assert host_stats['monitoring_enabled'] <= host_stats['total']
        assert host_stats['ping_enabled'] <= host_stats['total']
        assert host_stats['snmp_enabled'] <= host_stats['total']
        assert host_stats['service_checks_enabled'] <= host_stats['total']


class TestTaskSystemExamples(TestCase):
    """Example-based tests for specific task system scenarios."""
    
    def setUp(self):
        """Set up test environment."""
        self.location = Location.objects.create(
            name="Example Location",
            address="Example Address"
        )
        self.group = DeviceGroup.objects.create(
            name="Example Group",
            description="Example group"
        )
    
    def test_celery_app_configuration(self):
        """Test Celery app is properly configured."""
        # Verify app is configured
        assert app.main == 'nms'
        
        # Verify beat schedule is configured
        beat_schedule = app.conf.beat_schedule
        assert 'schedule-monitoring-tasks' in beat_schedule
        assert 'process-alert-escalations' in beat_schedule
        assert 'health-check' in beat_schedule
        assert 'cleanup-old-data' in beat_schedule
        
        # Verify task routes are configured
        task_routes = app.conf.task_routes
        assert 'monitoring.tasks.ping_monitoring_task' in task_routes
        assert 'monitoring.tasks.snmp_monitoring_task' in task_routes
        assert 'monitoring.tasks.service_monitoring_task' in task_routes
    
    def test_task_scheduling_with_no_hosts(self):
        """Test task scheduling when no hosts are configured."""
        # Clear all hosts
        Host.objects.all().delete()
        
        # Mock task execution
        with patch('monitoring.tasks.ping_monitoring_task.delay') as mock_ping, \
             patch('monitoring.tasks.snmp_monitoring_task.delay') as mock_snmp, \
             patch('monitoring.tasks.service_monitoring_task.delay') as mock_service:
            
            # Execute task scheduling
            result = schedule_monitoring_tasks()
            
            # Should succeed with zero tasks scheduled
            assert result['status'] == 'success'
            assert result['scheduled_tasks']['ping'] == 0
            assert result['scheduled_tasks']['snmp'] == 0
            assert result['scheduled_tasks']['service'] == 0
            assert result['total_hosts'] == 0
            
            # No tasks should be scheduled
            mock_ping.assert_not_called()
            mock_snmp.assert_not_called()
            assert not mock_service.called
    
    def test_host_monitoring_scheduling(self):
        """Test scheduling monitoring for a specific host."""
        # Create test host
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            hostname='schedule-test-host',
            ip_address='192.168.1.200',
            monitoring_enabled=True,
            ping_enabled=True,
            snmp_enabled=True,
            service_checks_enabled=True
        )
        
        # Mock task execution
        with patch('monitoring.tasks.ping_monitoring_task.delay') as mock_ping, \
             patch('monitoring.tasks.snmp_monitoring_task.delay') as mock_snmp, \
             patch('monitoring.tasks.service_monitoring_task.delay') as mock_service, \
             patch('monitoring.tasks.is_snmp_available') as mock_snmp_available:
            
            mock_snmp_available.return_value = True
            
            # Configure mock task results
            mock_task_result = Mock()
            mock_task_result.id = 'test-task-id'
            mock_ping.return_value = mock_task_result
            mock_snmp.return_value = mock_task_result
            mock_service.return_value = mock_task_result
            
            # Schedule monitoring for specific host
            task_ids = schedule_host_monitoring(host)
            
            # Verify all tasks were scheduled
            assert 'ping' in task_ids
            assert 'snmp' in task_ids
            assert 'service' in task_ids
            
            # Verify task calls
            mock_ping.assert_called_once_with(str(host.id))
            mock_snmp.assert_called_once_with(str(host.id))
            mock_service.assert_called_once_with(str(host.id))
    
    def test_health_check_task_execution(self):
        """Test health check task execution."""
        # Mock cache operations
        with patch('django.core.cache.cache.set') as mock_set, \
             patch('django.core.cache.cache.get') as mock_get, \
             patch('monitoring.tasks.is_snmp_available') as mock_snmp:
            
            mock_get.return_value = 'ok'
            mock_snmp.return_value = True
            
            # Execute health check
            result = health_check_task()
            
            # Verify health check structure
            assert isinstance(result, dict)
            assert 'database' in result
            assert 'redis' in result
            assert 'snmp' in result
            assert 'hosts_monitored' in result
            assert 'active_alerts' in result
            assert 'last_ping_results' in result
            assert 'overall_health' in result
            assert 'timestamp' in result
            
            # Verify health status types
            assert isinstance(result['database'], bool)
            assert isinstance(result['redis'], bool)
            assert isinstance(result['snmp'], bool)
            assert isinstance(result['hosts_monitored'], int)
            assert isinstance(result['active_alerts'], int)
            assert isinstance(result['last_ping_results'], int)
            assert isinstance(result['overall_health'], bool)
    
    def test_cleanup_task_execution(self):
        """Test data cleanup task execution."""
        # Create old test data
        old_time = timezone.now() - timedelta(days=100)
        
        host = Host.objects.create(
            location=self.location,
            group=self.group,
            hostname='cleanup-test-host',
            ip_address='192.168.1.201'
        )
        
        # Create old ping result
        old_ping = PingResult.objects.create(
            host=host,
            success=True,
            latency=10.0,
            packet_loss=0.0,
            packets_sent=4,
            packets_received=4,
            status='up'
        )
        old_ping.timestamp = old_time
        old_ping.save()
        
        # Execute cleanup
        result = cleanup_old_data()
        
        # Verify cleanup structure
        assert isinstance(result, dict)
        assert 'status' in result
        
        if result['status'] == 'success':
            assert 'cleanup_stats' in result
            cleanup_stats = result['cleanup_stats']
            
            assert 'ping_results' in cleanup_stats
            assert 'metrics' in cleanup_stats
            assert 'alerts' in cleanup_stats
            
            # All cleanup counts should be non-negative integers
            for key, value in cleanup_stats.items():
                assert isinstance(value, int)
                assert value >= 0


if __name__ == '__main__':
    pytest.main([__file__])