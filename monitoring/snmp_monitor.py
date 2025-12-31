"""
SNMP monitoring system for network devices.

This module provides SNMP v2c and v3 support for collecting various metrics
from network devices including interface statistics, system metrics, and
environmental data.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings

try:
    from pysnmp.hlapi.asyncio import *
    from pysnmp.proto.rfc1902 import Counter32, Counter64, Gauge32, Integer, OctetString
    from pysnmp.error import PySnmpError
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False
    logging.warning("pysnmp not available. SNMP monitoring will be disabled.")

from .models import Host, MonitoringMetric

logger = logging.getLogger(__name__)


@dataclass
class SNMPConfig:
    """SNMP configuration for a host."""
    version: str  # '2c' or '3'
    community: str = 'public'  # For v2c
    username: str = ''  # For v3
    auth_protocol: str = ''  # For v3: 'MD5' or 'SHA'
    auth_password: str = ''  # For v3
    priv_protocol: str = ''  # For v3: 'DES' or 'AES'
    priv_password: str = ''  # For v3
    port: int = 161
    timeout: int = 5
    retries: int = 3


@dataclass
class SNMPResult:
    """Result of an SNMP operation."""
    success: bool
    error_message: str = ''
    metrics: Dict[str, Any] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = timezone.now()
        if self.metrics is None:
            self.metrics = {}


class SNMPCollector:
    """Base class for SNMP metric collectors."""
    
    def __init__(self, name: str, oids: Dict[str, str]):
        """
        Initialize SNMP collector.
        
        Args:
            name: Name of the collector
            oids: Dictionary mapping metric names to OIDs
        """
        self.name = name
        self.oids = oids
    
    async def collect(self, host: Host, snmp_config: SNMPConfig) -> SNMPResult:
        """
        Collect metrics from the host.
        
        Args:
            host: Host to collect from
            snmp_config: SNMP configuration
            
        Returns:
            SNMPResult with collected metrics
        """
        if not PYSNMP_AVAILABLE:
            return SNMPResult(
                success=False,
                error_message="pysnmp library not available"
            )
        
        try:
            metrics = {}
            
            # Create SNMP engine and context
            snmp_engine = SnmpEngine()
            
            # Configure authentication based on version
            if snmp_config.version == '2c':
                auth_data = CommunityData(snmp_config.community)
            elif snmp_config.version == '3':
                auth_data = self._create_v3_auth(snmp_config)
            else:
                return SNMPResult(
                    success=False,
                    error_message=f"Unsupported SNMP version: {snmp_config.version}"
                )
            
            # Configure transport
            transport = UdpTransportTarget(
                (host.ip_address, snmp_config.port),
                timeout=snmp_config.timeout,
                retries=snmp_config.retries
            )
            
            # Collect each metric
            for metric_name, oid in self.oids.items():
                try:
                    value = await self._get_snmp_value(
                        snmp_engine, auth_data, transport, oid
                    )
                    if value is not None:
                        metrics[metric_name] = value
                except Exception as e:
                    logger.warning(f"Failed to collect {metric_name} from {host.hostname}: {e}")
                    continue
            
            # Process collected metrics
            processed_metrics = self.process_metrics(metrics, host)
            
            return SNMPResult(
                success=True,
                metrics=processed_metrics
            )
            
        except Exception as e:
            logger.error(f"SNMP collection failed for {host.hostname}: {e}")
            return SNMPResult(
                success=False,
                error_message=str(e)
            )
    
    def _create_v3_auth(self, config: SNMPConfig):
        """Create SNMP v3 authentication data."""
        auth_protocol_map = {
            'MD5': usmHMACMD5AuthProtocol,
            'SHA': usmHMACSHAAuthProtocol,
            '': usmNoAuthProtocol
        }
        
        priv_protocol_map = {
            'DES': usmDESPrivProtocol,
            'AES': usmAesCfb128Protocol,
            '': usmNoPrivProtocol
        }
        
        auth_protocol = auth_protocol_map.get(config.auth_protocol, usmNoAuthProtocol)
        priv_protocol = priv_protocol_map.get(config.priv_protocol, usmNoPrivProtocol)
        
        return UsmUserData(
            config.username,
            authKey=config.auth_password if config.auth_password else None,
            privKey=config.priv_password if config.priv_password else None,
            authProtocol=auth_protocol,
            privProtocol=priv_protocol
        )
    
    async def _get_snmp_value(self, snmp_engine, auth_data, transport, oid):
        """Get a single SNMP value."""
        iterator = getCmd(
            snmp_engine,
            auth_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        
        error_indication, error_status, error_index, var_binds = await iterator
        
        if error_indication:
            raise Exception(f"SNMP error indication: {error_indication}")
        
        if error_status:
            raise Exception(f"SNMP error status: {error_status.prettyPrint()}")
        
        if var_binds:
            name, value = var_binds[0]
            return self._convert_snmp_value(value)
        
        return None
    
    def _convert_snmp_value(self, value):
        """Convert SNMP value to Python type."""
        if isinstance(value, (Counter32, Counter64, Gauge32, Integer)):
            return int(value)
        elif isinstance(value, OctetString):
            try:
                return str(value)
            except UnicodeDecodeError:
                return value.asOctets().hex()
        else:
            return str(value)
    
    def process_metrics(self, metrics: Dict[str, Any], host: Host) -> Dict[str, Any]:
        """
        Process raw metrics. Override in subclasses for custom processing.
        
        Args:
            metrics: Raw metrics from SNMP
            host: Host being monitored
            
        Returns:
            Processed metrics
        """
        return metrics


class SystemMetricsCollector(SNMPCollector):
    """Collector for system metrics (CPU, memory, uptime)."""
    
    def __init__(self):
        oids = {
            'system_description': '1.3.6.1.2.1.1.1.0',  # sysDescr
            'system_uptime': '1.3.6.1.2.1.1.3.0',      # sysUpTime
            'system_contact': '1.3.6.1.2.1.1.4.0',     # sysContact
            'system_name': '1.3.6.1.2.1.1.5.0',        # sysName
            'system_location': '1.3.6.1.2.1.1.6.0',    # sysLocation
            'cpu_usage': '1.3.6.1.4.1.9.9.109.1.1.1.1.7.1',  # Cisco CPU usage (if available)
            'memory_used': '1.3.6.1.4.1.9.9.48.1.1.1.5.1',   # Cisco memory used (if available)
            'memory_free': '1.3.6.1.4.1.9.9.48.1.1.1.6.1',   # Cisco memory free (if available)
        }
        super().__init__('system_metrics', oids)
    
    def process_metrics(self, metrics: Dict[str, Any], host: Host) -> Dict[str, Any]:
        """Process system metrics."""
        processed = {}
        
        # Convert uptime from timeticks to seconds
        if 'system_uptime' in metrics:
            uptime_ticks = metrics['system_uptime']
            uptime_seconds = uptime_ticks / 100  # Timeticks are in 1/100th seconds
            processed['uptime_seconds'] = uptime_seconds
            processed['uptime_days'] = uptime_seconds / 86400
        
        # Calculate memory utilization percentage
        if 'memory_used' in metrics and 'memory_free' in metrics:
            used = metrics['memory_used']
            free = metrics['memory_free']
            total = used + free
            if total > 0:
                processed['memory_utilization_percent'] = (used / total) * 100
                processed['memory_total'] = total
        
        # Copy other metrics as-is
        for key, value in metrics.items():
            if key not in processed:
                processed[key] = value
        
        return processed


class InterfaceMetricsCollector(SNMPCollector):
    """Collector for interface statistics."""
    
    def __init__(self):
        # Base OIDs for interface table
        self.base_oids = {
            'if_index': '1.3.6.1.2.1.2.2.1.1',      # ifIndex
            'if_descr': '1.3.6.1.2.1.2.2.1.2',      # ifDescr
            'if_type': '1.3.6.1.2.1.2.2.1.3',       # ifType
            'if_mtu': '1.3.6.1.2.1.2.2.1.4',        # ifMtu
            'if_speed': '1.3.6.1.2.1.2.2.1.5',      # ifSpeed
            'if_admin_status': '1.3.6.1.2.1.2.2.1.7',  # ifAdminStatus
            'if_oper_status': '1.3.6.1.2.1.2.2.1.8',   # ifOperStatus
            'if_in_octets': '1.3.6.1.2.1.2.2.1.10',    # ifInOctets
            'if_in_ucast_pkts': '1.3.6.1.2.1.2.2.1.11', # ifInUcastPkts
            'if_in_errors': '1.3.6.1.2.1.2.2.1.14',    # ifInErrors
            'if_out_octets': '1.3.6.1.2.1.2.2.1.16',   # ifOutOctets
            'if_out_ucast_pkts': '1.3.6.1.2.1.2.2.1.17', # ifOutUcastPkts
            'if_out_errors': '1.3.6.1.2.1.2.2.1.20',   # ifOutErrors
        }
        super().__init__('interface_metrics', {})
    
    async def collect(self, host: Host, snmp_config: SNMPConfig) -> SNMPResult:
        """Collect interface metrics using SNMP walk."""
        if not PYSNMP_AVAILABLE:
            return SNMPResult(
                success=False,
                error_message="pysnmp library not available"
            )
        
        try:
            interfaces = {}
            
            # Create SNMP engine and context
            snmp_engine = SnmpEngine()
            
            # Configure authentication
            if snmp_config.version == '2c':
                auth_data = CommunityData(snmp_config.community)
            elif snmp_config.version == '3':
                auth_data = self._create_v3_auth(snmp_config)
            else:
                return SNMPResult(
                    success=False,
                    error_message=f"Unsupported SNMP version: {snmp_config.version}"
                )
            
            # Configure transport
            transport = UdpTransportTarget(
                (host.ip_address, snmp_config.port),
                timeout=snmp_config.timeout,
                retries=snmp_config.retries
            )
            
            # Walk interface table for each metric
            for metric_name, base_oid in self.base_oids.items():
                try:
                    async for (error_indication, error_status, error_index, var_binds) in nextCmd(
                        snmp_engine,
                        auth_data,
                        transport,
                        ContextData(),
                        ObjectType(ObjectIdentity(base_oid)),
                        lexicographicMode=False
                    ):
                        if error_indication:
                            logger.warning(f"SNMP walk error for {metric_name}: {error_indication}")
                            break
                        
                        if error_status:
                            logger.warning(f"SNMP walk error status for {metric_name}: {error_status}")
                            break
                        
                        for var_bind in var_binds:
                            name, value = var_bind
                            oid_str = str(name)
                            
                            # Extract interface index from OID
                            if oid_str.startswith(base_oid + '.'):
                                if_index = oid_str[len(base_oid) + 1:]
                                
                                if if_index not in interfaces:
                                    interfaces[if_index] = {}
                                
                                interfaces[if_index][metric_name] = self._convert_snmp_value(value)
                
                except Exception as e:
                    logger.warning(f"Failed to walk {metric_name}: {e}")
                    continue
            
            # Process interfaces
            processed_interfaces = self.process_interfaces(interfaces, host)
            
            return SNMPResult(
                success=True,
                metrics={'interfaces': processed_interfaces}
            )
            
        except Exception as e:
            logger.error(f"Interface SNMP collection failed for {host.hostname}: {e}")
            return SNMPResult(
                success=False,
                error_message=str(e)
            )
    
    def process_interfaces(self, interfaces: Dict[str, Dict], host: Host) -> Dict[str, Dict]:
        """Process interface data."""
        processed = {}
        
        for if_index, interface_data in interfaces.items():
            # Skip interfaces without description
            if 'if_descr' not in interface_data:
                continue
            
            if_name = interface_data.get('if_descr', f'Interface {if_index}')
            
            # Calculate utilization if speed is available
            if 'if_speed' in interface_data and interface_data['if_speed'] > 0:
                speed_bps = interface_data['if_speed']
                
                # Calculate input/output utilization (would need previous values for rate calculation)
                # For now, just store the raw counters
                interface_data['if_speed_mbps'] = speed_bps / 1000000
            
            # Determine interface status
            admin_status = interface_data.get('if_admin_status', 0)
            oper_status = interface_data.get('if_oper_status', 0)
            
            interface_data['status'] = 'up' if admin_status == 1 and oper_status == 1 else 'down'
            interface_data['admin_status_text'] = 'up' if admin_status == 1 else 'down'
            interface_data['oper_status_text'] = 'up' if oper_status == 1 else 'down'
            
            processed[if_name] = interface_data
        
        return processed


class EnvironmentalMetricsCollector(SNMPCollector):
    """Collector for environmental metrics (temperature, power, fans)."""
    
    def __init__(self):
        # Common environmental OIDs (Cisco-specific, can be extended for other vendors)
        oids = {
            # Cisco environmental monitoring
            'temp_sensor_1': '1.3.6.1.4.1.9.9.13.1.3.1.3.1',  # Temperature sensor 1
            'temp_sensor_2': '1.3.6.1.4.1.9.9.13.1.3.1.3.2',  # Temperature sensor 2
            'power_supply_1': '1.3.6.1.4.1.9.9.13.1.5.1.3.1', # Power supply 1 status
            'power_supply_2': '1.3.6.1.4.1.9.9.13.1.5.1.3.2', # Power supply 2 status
            'fan_status': '1.3.6.1.4.1.9.9.13.1.4.1.3.1',     # Fan status
        }
        super().__init__('environmental_metrics', oids)
    
    def process_metrics(self, metrics: Dict[str, Any], host: Host) -> Dict[str, Any]:
        """Process environmental metrics."""
        processed = {}
        
        # Process temperature sensors
        for key, value in metrics.items():
            if key.startswith('temp_sensor') and value is not None:
                # Temperature is usually in Celsius
                processed[key] = value
                processed[f"{key}_fahrenheit"] = (value * 9/5) + 32
        
        # Process power supply status
        for key, value in metrics.items():
            if key.startswith('power_supply') and value is not None:
                # 1 = normal, 2 = warning, 3 = critical, 4 = shutdown, 5 = not present
                status_map = {1: 'normal', 2: 'warning', 3: 'critical', 4: 'shutdown', 5: 'not_present'}
                processed[f"{key}_status"] = status_map.get(value, 'unknown')
        
        # Process fan status
        if 'fan_status' in metrics and metrics['fan_status'] is not None:
            # 1 = normal, 2 = warning, 3 = critical, 4 = shutdown, 5 = not present
            status_map = {1: 'normal', 2: 'warning', 3: 'critical', 4: 'shutdown', 5: 'not_present'}
            processed['fan_status_text'] = status_map.get(metrics['fan_status'], 'unknown')
        
        # Copy other metrics
        for key, value in metrics.items():
            if key not in processed:
                processed[key] = value
        
        return processed


class OpticalInterfaceCollector(SNMPCollector):
    """Collector for optical interface metrics (SFP/SFP+ modules)."""
    
    def __init__(self):
        # Optical monitoring OIDs (vendor-specific, these are examples)
        oids = {
            # Cisco optical monitoring (examples)
            'optical_rx_power': '1.3.6.1.4.1.9.9.202.1.1.1.1.4',  # RX power
            'optical_tx_power': '1.3.6.1.4.1.9.9.202.1.1.1.1.5',  # TX power
            'optical_temperature': '1.3.6.1.4.1.9.9.202.1.1.1.1.6', # Temperature
            'optical_voltage': '1.3.6.1.4.1.9.9.202.1.1.1.1.7',   # Voltage
            'optical_current': '1.3.6.1.4.1.9.9.202.1.1.1.1.8',   # Current
        }
        super().__init__('optical_metrics', oids)
    
    async def collect(self, host: Host, snmp_config: SNMPConfig) -> SNMPResult:
        """Collect optical metrics only if host has optical interfaces."""
        # Check if host should have optical monitoring
        if not self._should_collect_optical(host):
            return SNMPResult(
                success=True,
                metrics={'optical_interfaces': {}},
                error_message="No optical interfaces detected"
            )
        
        return await super().collect(host, snmp_config)
    
    def _should_collect_optical(self, host: Host) -> bool:
        """Determine if host should have optical interface monitoring."""
        # Check device type and other indicators
        optical_device_types = ['switch', 'router']
        
        if host.device_type in optical_device_types:
            return True
        
        # Check if hostname/description suggests optical interfaces
        optical_keywords = ['sfp', 'fiber', 'optical', 'gbic', 'xfp']
        host_text = f"{host.hostname} {host.device_name}".lower()
        
        return any(keyword in host_text for keyword in optical_keywords)
    
    def process_metrics(self, metrics: Dict[str, Any], host: Host) -> Dict[str, Any]:
        """Process optical metrics."""
        processed = {}
        
        # Convert power values from dBm to mW if needed
        for key, value in metrics.items():
            if 'power' in key and value is not None:
                # Assume value is in dBm, convert to mW
                processed[f"{key}_dbm"] = value
                processed[f"{key}_mw"] = 10 ** (value / 10)
            else:
                processed[key] = value
        
        return {'optical_interfaces': processed}


class SNMPMonitoringService:
    """Main SNMP monitoring service."""
    
    def __init__(self):
        """Initialize SNMP monitoring service."""
        self.collectors = {
            'system': SystemMetricsCollector(),
            'interfaces': InterfaceMetricsCollector(),
            'environmental': EnvironmentalMetricsCollector(),
            'optical': OpticalInterfaceCollector(),
        }
        
        # Default SNMP settings from Django configuration
        self.default_timeout = getattr(settings, 'MONITORING_SETTINGS', {}).get('SNMP_TIMEOUT', 10)
    
    def get_snmp_config(self, host: Host) -> SNMPConfig:
        """Get SNMP configuration for a host."""
        return SNMPConfig(
            version=host.snmp_version,
            community=host.snmp_community,
            port=161,
            timeout=self.default_timeout,
            retries=3
        )
    
    async def collect_metrics(self, host: Host, collectors: List[str] = None) -> Dict[str, SNMPResult]:
        """
        Collect metrics from a host using specified collectors.
        
        Args:
            host: Host to collect from
            collectors: List of collector names to use (default: all)
            
        Returns:
            Dictionary mapping collector names to results
        """
        if not host.snmp_enabled:
            logger.debug(f"SNMP disabled for host {host.hostname}")
            return {}
        
        if collectors is None:
            collectors = list(self.collectors.keys())
        
        snmp_config = self.get_snmp_config(host)
        results = {}
        
        # Collect metrics from each collector
        for collector_name in collectors:
            if collector_name not in self.collectors:
                logger.warning(f"Unknown collector: {collector_name}")
                continue
            
            collector = self.collectors[collector_name]
            
            try:
                result = await collector.collect(host, snmp_config)
                results[collector_name] = result
                
                if result.success:
                    logger.debug(f"Successfully collected {collector_name} metrics from {host.hostname}")
                    
                    # Store metrics in database
                    await self._store_metrics(host, collector_name, result.metrics)
                else:
                    logger.warning(f"Failed to collect {collector_name} metrics from {host.hostname}: {result.error_message}")
            
            except Exception as e:
                logger.error(f"Error collecting {collector_name} metrics from {host.hostname}: {e}")
                results[collector_name] = SNMPResult(
                    success=False,
                    error_message=str(e)
                )
        
        return results
    
    async def _store_metrics(self, host: Host, collector_name: str, metrics: Dict[str, Any]):
        """Store collected metrics in the database."""
        if not metrics:
            return
        
        try:
            # Store metrics based on collector type
            if collector_name == 'system':
                await self._store_system_metrics(host, metrics)
            elif collector_name == 'interfaces':
                await self._store_interface_metrics(host, metrics)
            elif collector_name == 'environmental':
                await self._store_environmental_metrics(host, metrics)
            elif collector_name == 'optical':
                await self._store_optical_metrics(host, metrics)
        
        except Exception as e:
            logger.error(f"Error storing {collector_name} metrics for {host.hostname}: {e}")
    
    async def _store_system_metrics(self, host: Host, metrics: Dict[str, Any]):
        """Store system metrics."""
        for metric_name, value in metrics.items():
            if value is not None:
                await self._create_metric(host, 'snmp_system', metric_name, value)
    
    async def _store_interface_metrics(self, host: Host, metrics: Dict[str, Any]):
        """Store interface metrics."""
        interfaces = metrics.get('interfaces', {})
        
        for interface_name, interface_data in interfaces.items():
            for metric_name, value in interface_data.items():
                if value is not None and isinstance(value, (int, float)):
                    await self._create_metric(
                        host, 'snmp_interface', metric_name, value, interface=interface_name
                    )
    
    async def _store_environmental_metrics(self, host: Host, metrics: Dict[str, Any]):
        """Store environmental metrics."""
        for metric_name, value in metrics.items():
            if value is not None and isinstance(value, (int, float)):
                await self._create_metric(host, 'snmp_environmental', metric_name, value)
    
    async def _store_optical_metrics(self, host: Host, metrics: Dict[str, Any]):
        """Store optical metrics."""
        optical_data = metrics.get('optical_interfaces', {})
        
        for metric_name, value in optical_data.items():
            if value is not None and isinstance(value, (int, float)):
                await self._create_metric(host, 'snmp_optical', metric_name, value)
    
    async def _create_metric(self, host: Host, metric_type: str, metric_name: str, 
                           value: float, interface: str = ''):
        """Create a monitoring metric record."""
        try:
            # Use Django's database-sync-to-async for database operations
            from asgiref.sync import sync_to_async
            
            create_metric = sync_to_async(MonitoringMetric.objects.create)
            
            await create_metric(
                host=host,
                metric_type=metric_type,
                metric_name=metric_name,
                value=float(value),
                interface=interface,
                additional_data={}
            )
        
        except Exception as e:
            logger.error(f"Error creating metric record: {e}")


# Convenience functions
async def collect_snmp_metrics(host: Host, collectors: List[str] = None) -> Dict[str, SNMPResult]:
    """Collect SNMP metrics from a host."""
    service = SNMPMonitoringService()
    return await service.collect_metrics(host, collectors)


def get_snmp_collectors() -> List[str]:
    """Get list of available SNMP collectors."""
    return ['system', 'interfaces', 'environmental', 'optical']


def is_snmp_available() -> bool:
    """Check if SNMP monitoring is available."""
    return PYSNMP_AVAILABLE