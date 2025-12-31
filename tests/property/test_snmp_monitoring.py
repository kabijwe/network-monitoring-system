"""
Property-based tests for SNMP monitoring system.

These tests validate the universal correctness properties of SNMP monitoring
including protocol support, conditional metrics collection, and data integrity.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from hypothesis import given, strategies as st, settings, assume
from hypothesis.extra.django import TestCase as HypothesisTestCase
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, invariant
from django.test import TestCase
from django.utils import timezone

from monitoring.models import Host, Location, DeviceGroup, MonitoringMetric
from monitoring.snmp_monitor import (
    SNMPConfig, SNMPResult, SNMPCollector, SystemMetricsCollector,
    InterfaceMetricsCollector, EnvironmentalMetricsCollector,
    OpticalInterfaceCollector, SNMPMonitoringService,
    collect_snmp_metrics, is_snmp_available
)


class TestSNMPProtocolSupport(HypothesisTestCase):
    """Property 15: SNMP protocol support validation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.location = Location.objects.create(name='Test Location')
        self.group = DeviceGroup.objects.create(name='Test Group')
    
    @given(
        version=st.sampled_from(['2c', '3']),
        community=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))),
        username=st.text(min_size=0, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))),
        auth_protocol=st.sampled_from(['', 'MD5', 'SHA']),
        priv_protocol=st.sampled_from(['', 'DES', 'AES']),
        port=st.integers(min_value=1, max_value=65535),
        timeout=st.integers(min_value=1, max_value=60),
        retries=st.integers(min_value=0, max_value=10)
    )
    @settings(max_examples=50, deadline=5000)
    def test_snmp_config_creation_properties(self, version, community, username, 
                                           auth_protocol, priv_protocol, port, timeout, retries):
        """Test SNMP configuration creation properties."""
        # Property: SNMP configuration should be valid for supported versions
        config = SNMPConfig(
            version=version,
            community=community,
            username=username,
            auth_protocol=auth_protocol,
            priv_protocol=priv_protocol,
            port=port,
            timeout=timeout,
            retries=retries
        )
        
        # Invariant: Configuration should maintain input values
        assert config.version == version
        assert config.community == community
        assert config.username == username
        assert config.auth_protocol == auth_protocol
        assert config.priv_protocol == priv_protocol
        assert config.port == port
        assert config.timeout == timeout
        assert config.retries == retries
        
        # Property: Port should be valid
        assert 1 <= config.port <= 65535
        
        # Property: Timeout should be positive
        assert config.timeout > 0
        
        # Property: Retries should be non-negative
        assert config.retries >= 0
    
    @given(
        hostname=st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pd'))),
        ip_address=st.sampled_from(['127.0.0.1', '192.168.1.1', '10.0.0.1', '172.16.0.1']),
        snmp_version=st.sampled_from(['2c', '3']),
        snmp_community=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd')))
    )
    @settings(max_examples=30, deadline=3000)
    def test_host_snmp_configuration_properties(self, hostname, ip_address, snmp_version, snmp_community):
        """Test host SNMP configuration properties."""
        # Create host with SNMP configuration
        host = Host.objects.create(
            hostname=hostname,
            ip_address=ip_address,
            location=self.location,
            group=self.group,
            snmp_enabled=True,
            snmp_version=snmp_version,
            snmp_community=snmp_community
        )
        
        # Property: Host should have valid SNMP configuration
        assert host.snmp_enabled is True
        assert host.snmp_version in ['2c', '3']
        assert len(host.snmp_community) > 0
        
        # Property: SNMP configuration should be retrievable
        service = SNMPMonitoringService()
        config = service.get_snmp_config(host)
        
        assert config.version == host.snmp_version
        assert config.community == host.snmp_community
        assert config.port == 161  # Default SNMP port
    
    @given(
        collector_name=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))),
        oids=st.dictionaries(
            keys=st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))),
            values=st.text(min_size=7, max_size=50, alphabet=st.characters(whitelist_categories=('Nd', 'Pc'))),
            min_size=1,
            max_size=10
        )
    )
    @settings(max_examples=20, deadline=2000)
    def test_snmp_collector_properties(self, collector_name, oids):
        """Test SNMP collector properties."""
        # Filter OIDs to ensure they look like valid SNMP OIDs
        valid_oids = {
            name: oid for name, oid in oids.items() 
            if '.' in oid and all(part.isdigit() for part in oid.split('.') if part)
        }
        
        assume(len(valid_oids) > 0)
        
        # Property: Collector should be created with valid configuration
        collector = SNMPCollector(collector_name, valid_oids)
        
        assert collector.name == collector_name
        assert collector.oids == valid_oids
        assert len(collector.oids) > 0
        
        # Property: All OIDs should be strings
        for oid in collector.oids.values():
            assert isinstance(oid, str)
            assert '.' in oid


class TestConditionalMetricsCollection(HypothesisTestCase):
    """Property 16: Conditional metrics collection validation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.location = Location.objects.create(name='Test Location')
        self.group = DeviceGroup.objects.create(name='Test Group')
    
    @given(
        device_type=st.sampled_from(['switch', 'router', 'ap', 'sm', 'firewall', 'server', 'other']),
        hostname=st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pd'))),
        device_name=st.text(min_size=0, max_size=100, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Zs')))
    )
    @settings(max_examples=50, deadline=3000)
    def test_optical_interface_collection_conditions(self, device_type, hostname, device_name):
        """Test optical interface collection conditional logic."""
        # Create host
        host = Host.objects.create(
            hostname=hostname,
            ip_address='192.168.1.1',
            device_type=device_type,
            device_name=device_name,
            location=self.location,
            group=self.group,
            snmp_enabled=True
        )
        
        # Property: Optical collection should be conditional based on device type
        collector = OpticalInterfaceCollector()
        should_collect = collector._should_collect_optical(host)
        
        # Property: Switches and routers should typically have optical interfaces
        if device_type in ['switch', 'router']:
            assert should_collect is True
        
        # Property: Decision should be consistent for same input
        should_collect_2 = collector._should_collect_optical(host)
        assert should_collect == should_collect_2
        
        # Property: Optical keywords in hostname/device_name should trigger collection
        optical_keywords = ['sfp', 'fiber', 'optical', 'gbic', 'xfp']
        host_text = f"{hostname} {device_name}".lower()
        
        has_optical_keyword = any(keyword in host_text for keyword in optical_keywords)
        if has_optical_keyword:
            assert should_collect is True
    
    @given(
        collectors=st.lists(
            st.sampled_from(['system', 'interfaces', 'environmental', 'optical']),
            min_size=1,
            max_size=4,
            unique=True
        ),
        snmp_enabled=st.booleans(),
        monitoring_enabled=st.booleans()
    )
    @settings(max_examples=30, deadline=3000)
    def test_collector_selection_properties(self, collectors, snmp_enabled, monitoring_enabled):
        """Test collector selection properties."""
        # Create host
        host = Host.objects.create(
            hostname='test-host',
            ip_address='192.168.1.1',
            location=self.location,
            group=self.group,
            monitoring_enabled=monitoring_enabled,
            snmp_enabled=snmp_enabled
        )
        
        service = SNMPMonitoringService()
        
        # Property: If SNMP is disabled, no collection should occur
        if not snmp_enabled or not monitoring_enabled:
            with patch('monitoring.snmp_monitor.is_snmp_available', return_value=True):
                result = asyncio.run(service.collect_metrics(host, collectors))
                assert result == {}
        
        # Property: Available collectors should match service collectors
        available_collectors = list(service.collectors.keys())
        expected_collectors = ['system', 'interfaces', 'environmental', 'optical']
        assert set(available_collectors) == set(expected_collectors)
        
        # Property: Requested collectors should be subset of available
        for collector in collectors:
            assert collector in available_collectors


class SNMPMonitoringStateMachine(RuleBasedStateMachine):
    """Stateful property testing for SNMP monitoring system."""
    
    def __init__(self):
        super().__init__()
        self.hosts = []
        self.metrics_collected = []
        self.collection_attempts = 0
    
    @initialize()
    def setup(self):
        """Initialize the state machine."""
        # Use get_or_create to avoid unique constraint violations
        self.location, _ = Location.objects.get_or_create(
            name='Test Location',
            defaults={'description': 'Test location for SNMP monitoring'}
        )
        self.group, _ = DeviceGroup.objects.get_or_create(
            name='Test Group',
            defaults={'description': 'Test group for SNMP monitoring'}
        )
    
    @rule(
        hostname=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pd'))),
        device_type=st.sampled_from(['switch', 'router', 'server']),
        snmp_enabled=st.booleans()
    )
    def add_host(self, hostname, device_type, snmp_enabled):
        """Add a host to the monitoring system."""
        # Avoid duplicate hostnames
        assume(not any(h.hostname == hostname for h in self.hosts))
        
        host = Host.objects.create(
            hostname=hostname,
            ip_address=f'192.168.1.{len(self.hosts) + 1}',
            device_type=device_type,
            location=self.location,
            group=self.group,
            monitoring_enabled=True,
            snmp_enabled=snmp_enabled,
            snmp_community='public'
        )
        
        self.hosts.append(host)
    
    @rule(
        collectors=st.lists(
            st.sampled_from(['system', 'interfaces', 'environmental', 'optical']),
            min_size=1,
            max_size=4,
            unique=True
        )
    )
    def collect_metrics(self, collectors):
        """Attempt to collect metrics from hosts."""
        assume(len(self.hosts) > 0)
        
        service = SNMPMonitoringService()
        
        for host in self.hosts:
            self.collection_attempts += 1
            
            # Mock SNMP collection to avoid actual network calls
            with patch('monitoring.snmp_monitor.is_snmp_available', return_value=True), \
                 patch.object(SNMPCollector, 'collect', new_callable=AsyncMock) as mock_collect:
                
                # Mock successful collection
                mock_result = SNMPResult(
                    success=host.snmp_enabled,
                    metrics={'test_metric': 42} if host.snmp_enabled else {},
                    error_message='' if host.snmp_enabled else 'SNMP disabled'
                )
                mock_collect.return_value = mock_result
                
                # Collect metrics
                results = asyncio.run(service.collect_metrics(host, collectors))
                
                if host.snmp_enabled:
                    self.metrics_collected.extend(results.keys())
    
    @invariant()
    def metrics_collection_invariants(self):
        """Invariants that should always hold."""
        # Invariant: Collection attempts should be non-negative
        assert self.collection_attempts >= 0
        
        # Invariant: Number of hosts should be non-negative
        assert len(self.hosts) >= 0
        
        # Invariant: All hosts should have valid IP addresses
        for host in self.hosts:
            assert host.ip_address is not None
            assert len(host.ip_address.split('.')) == 4  # Basic IPv4 validation
        
        # Invariant: SNMP-enabled hosts should have community strings
        for host in self.hosts:
            if host.snmp_enabled:
                assert host.snmp_community is not None
                assert len(host.snmp_community) > 0


class TestSNMPDataIntegrity(HypothesisTestCase):
    """Test SNMP data integrity and consistency."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.location = Location.objects.create(name='Test Location')
        self.group = DeviceGroup.objects.create(name='Test Group')
    
    @given(
        metric_values=st.dictionaries(
            keys=st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))),
            values=st.one_of(
                st.integers(min_value=0, max_value=2**32-1),
                st.floats(min_value=0.0, max_value=1000000.0, allow_nan=False, allow_infinity=False),
                st.text(min_size=0, max_size=100, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Zs')))
            ),
            min_size=1,
            max_size=20
        )
    )
    @settings(max_examples=30, deadline=3000)
    def test_snmp_result_data_integrity(self, metric_values):
        """Test SNMP result data integrity properties."""
        # Property: SNMP results should preserve data integrity
        result = SNMPResult(
            success=True,
            metrics=metric_values
        )
        
        # Invariant: Success status should be preserved
        assert result.success is True
        
        # Invariant: Metrics should be preserved exactly
        assert result.metrics == metric_values
        
        # Invariant: Timestamp should be set
        assert result.timestamp is not None
        
        # Property: Metrics should be accessible
        for key, value in metric_values.items():
            assert key in result.metrics
            assert result.metrics[key] == value
    
    @given(
        system_metrics=st.dictionaries(
            keys=st.sampled_from(['system_uptime', 'cpu_usage', 'memory_used', 'memory_free']),
            values=st.integers(min_value=0, max_value=2**31-1),
            min_size=1,
            max_size=4
        )
    )
    @settings(max_examples=20, deadline=2000)
    def test_system_metrics_processing(self, system_metrics):
        """Test system metrics processing properties."""
        collector = SystemMetricsCollector()
        
        # Create dummy host
        host = Host.objects.create(
            hostname='test-host',
            ip_address='192.168.1.1',
            location=self.location,
            group=self.group
        )
        
        # Property: Metrics processing should be deterministic
        processed_1 = collector.process_metrics(system_metrics, host)
        processed_2 = collector.process_metrics(system_metrics, host)
        
        assert processed_1 == processed_2
        
        # Property: Original metrics should be preserved
        for key, value in system_metrics.items():
            if key in processed_1:
                assert processed_1[key] == value
        
        # Property: Uptime conversion should be correct
        if 'system_uptime' in system_metrics:
            uptime_ticks = system_metrics['system_uptime']
            if 'uptime_seconds' in processed_1:
                expected_seconds = uptime_ticks / 100
                assert abs(processed_1['uptime_seconds'] - expected_seconds) < 0.01
        
        # Property: Memory utilization calculation should be valid
        if 'memory_used' in system_metrics and 'memory_free' in system_metrics:
            used = system_metrics['memory_used']
            free = system_metrics['memory_free']
            total = used + free
            
            if total > 0 and 'memory_utilization_percent' in processed_1:
                expected_util = (used / total) * 100
                assert abs(processed_1['memory_utilization_percent'] - expected_util) < 0.01
                assert 0 <= processed_1['memory_utilization_percent'] <= 100


# Test runner for property-based tests
TestSNMPMonitoringStateMachine = SNMPMonitoringStateMachine.TestCase


@pytest.mark.django_db
class TestSNMPIntegration:
    """Integration tests for SNMP monitoring system."""
    
    def test_snmp_availability_check(self):
        """Test SNMP availability check."""
        # Property: SNMP availability should be deterministic
        available_1 = is_snmp_available()
        available_2 = is_snmp_available()
        
        assert available_1 == available_2
        assert isinstance(available_1, bool)
    
    def test_snmp_service_initialization(self):
        """Test SNMP service initialization."""
        service = SNMPMonitoringService()
        
        # Property: Service should have all expected collectors
        expected_collectors = ['system', 'interfaces', 'environmental', 'optical']
        assert set(service.collectors.keys()) == set(expected_collectors)
        
        # Property: Each collector should be properly initialized
        for name, collector in service.collectors.items():
            assert isinstance(collector, SNMPCollector)
            assert collector.name == name
            assert hasattr(collector, 'oids')