"""
Network discovery system for automatic device detection and classification.

This module provides functionality for discovering network devices through
subnet scanning, device identification, and approval workflow management.
"""

import logging
import asyncio
import ipaddress
import socket
import time
from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.utils import timezone
from django.conf import settings
from django.db import transaction

from .models import Host, Location, DeviceGroup, DiscoveredDevice
from .ping_monitor import ping_host_sync
from .snmp_monitor import collect_snmp_metrics, is_snmp_available
from .simple_ping import ping_host_simple

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryResult:
    """Result of device discovery."""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    os_info: Optional[str] = None
    snmp_community: Optional[str] = None
    snmp_version: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    ping_success: bool = False
    ping_latency: float = 0.0
    snmp_success: bool = False
    discovery_method: str = 'ping'
    confidence_score: float = 0.0
    additional_data: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=timezone.now)


@dataclass
class DiscoveryConfig:
    """Configuration for network discovery."""
    subnets: List[str] = field(default_factory=list)
    ping_timeout: int = 2
    snmp_timeout: int = 5
    snmp_communities: List[str] = field(default_factory=lambda: ['public', 'private'])
    snmp_versions: List[str] = field(default_factory=lambda: ['2c', '3'])
    port_scan_enabled: bool = False
    port_scan_ports: List[int] = field(default_factory=lambda: [22, 23, 80, 443, 161, 162])
    max_concurrent_scans: int = 50
    device_classification_enabled: bool = True
    auto_approve_known_devices: bool = False
    discovery_interval_hours: int = 24


class DeviceClassifier:
    """Device type classification based on discovery data."""
    
    # Device type patterns based on SNMP sysDescr, hostname, or services
    DEVICE_PATTERNS = {
        'router': {
            'snmp_patterns': [
                'cisco.*router', 'juniper.*router', 'mikrotik.*router',
                'routeros', 'ios.*router', 'junos'
            ],
            'hostname_patterns': [
                'router', 'rtr', 'gw', 'gateway', 'border'
            ],
            'ports': [22, 23, 80, 443, 161],
            'confidence_boost': 0.3
        },
        'switch': {
            'snmp_patterns': [
                'cisco.*switch', 'juniper.*switch', 'hp.*switch',
                'procurve', 'catalyst', 'nexus'
            ],
            'hostname_patterns': [
                'switch', 'sw', 'access', 'core', 'distribution'
            ],
            'ports': [22, 23, 80, 443, 161],
            'confidence_boost': 0.3
        },
        'firewall': {
            'snmp_patterns': [
                'palo alto', 'fortinet', 'checkpoint', 'sonicwall',
                'pfsense', 'opnsense', 'asa', 'srx'
            ],
            'hostname_patterns': [
                'firewall', 'fw', 'security', 'utm', 'ngfw'
            ],
            'ports': [22, 80, 443, 4433, 8080, 8443],
            'confidence_boost': 0.4
        },
        'server': {
            'snmp_patterns': [
                'linux', 'windows.*server', 'ubuntu', 'centos',
                'redhat', 'debian', 'freebsd'
            ],
            'hostname_patterns': [
                'server', 'srv', 'host', 'node', 'vm'
            ],
            'ports': [22, 80, 443, 3389, 5985, 5986],
            'confidence_boost': 0.2
        },
        'access_point': {
            'snmp_patterns': [
                'cisco.*ap', 'aruba.*ap', 'ubiquiti.*ap',
                'unifi', 'aironet', 'wireless'
            ],
            'hostname_patterns': [
                'ap', 'wifi', 'wireless', 'wlan', 'access'
            ],
            'ports': [22, 80, 443, 161],
            'confidence_boost': 0.4
        },
        'printer': {
            'snmp_patterns': [
                'hp.*printer', 'canon.*printer', 'epson.*printer',
                'xerox', 'brother.*printer', 'lexmark'
            ],
            'hostname_patterns': [
                'printer', 'print', 'hp', 'canon', 'epson'
            ],
            'ports': [80, 443, 515, 631, 9100],
            'confidence_boost': 0.5
        },
        'camera': {
            'snmp_patterns': [
                'axis.*camera', 'hikvision', 'dahua', 'vivotek',
                'ip.*camera', 'network.*camera'
            ],
            'hostname_patterns': [
                'camera', 'cam', 'ipcam', 'cctv', 'surveillance'
            ],
            'ports': [80, 443, 554, 8080],
            'confidence_boost': 0.5
        },
        'ups': {
            'snmp_patterns': [
                'apc.*ups', 'eaton.*ups', 'tripp.*lite',
                'cyberpower', 'ups'
            ],
            'hostname_patterns': [
                'ups', 'power', 'battery', 'pdu'
            ],
            'ports': [80, 443, 161, 3052],
            'confidence_boost': 0.4
        }
    }
    
    def classify_device(self, discovery_result: DiscoveryResult) -> Tuple[str, float]:
        """
        Classify device type based on discovery data.
        
        Args:
            discovery_result: Discovery result to classify
            
        Returns:
            Tuple of (device_type, confidence_score)
        """
        best_type = 'unknown'
        best_score = 0.0
        
        for device_type, patterns in self.DEVICE_PATTERNS.items():
            score = 0.0
            
            # Check SNMP patterns
            if discovery_result.os_info:
                for pattern in patterns.get('snmp_patterns', []):
                    if self._pattern_match(pattern, discovery_result.os_info.lower()):
                        score += 0.4
                        break
            
            # Check hostname patterns
            if discovery_result.hostname:
                for pattern in patterns.get('hostname_patterns', []):
                    if pattern in discovery_result.hostname.lower():
                        score += 0.3
                        break
            
            # Check open ports
            expected_ports = set(patterns.get('ports', []))
            open_ports = set(discovery_result.open_ports)
            if expected_ports and open_ports:
                port_match_ratio = len(expected_ports & open_ports) / len(expected_ports)
                score += port_match_ratio * 0.2
            
            # Apply confidence boost
            if score > 0:
                score += patterns.get('confidence_boost', 0.0)
                score = min(score, 1.0)  # Cap at 1.0
            
            if score > best_score:
                best_score = score
                best_type = device_type
        
        return best_type, best_score
    
    def _pattern_match(self, pattern: str, text: str) -> bool:
        """Simple pattern matching with wildcards."""
        import re
        # Convert simple wildcard pattern to regex
        regex_pattern = pattern.replace('*', '.*')
        return bool(re.search(regex_pattern, text, re.IGNORECASE))


class NetworkScanner:
    """Network scanner for device discovery."""
    
    def __init__(self, config: DiscoveryConfig):
        """Initialize network scanner with configuration."""
        self.config = config
        self.classifier = DeviceClassifier()
    
    async def discover_subnet(self, subnet: str) -> List[DiscoveryResult]:
        """
        Discover devices in a subnet.
        
        Args:
            subnet: Subnet in CIDR notation (e.g., '192.168.1.0/24')
            
        Returns:
            List of discovered devices
        """
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            logger.info(f"Starting discovery for subnet {subnet}")
            
            # Generate list of IP addresses to scan
            ip_addresses = [str(ip) for ip in network.hosts()]
            
            # Limit the number of IPs to scan for large subnets
            if len(ip_addresses) > 1000:
                logger.warning(f"Subnet {subnet} has {len(ip_addresses)} hosts, limiting to first 1000")
                ip_addresses = ip_addresses[:1000]
            
            # Perform concurrent ping sweep
            discovered_devices = await self._ping_sweep(ip_addresses)
            
            # Perform detailed discovery on responsive hosts
            if discovered_devices:
                logger.info(f"Found {len(discovered_devices)} responsive hosts in {subnet}")
                detailed_results = await self._detailed_discovery(discovered_devices)
                return detailed_results
            
            return []
            
        except Exception as e:
            logger.error(f"Error discovering subnet {subnet}: {e}")
            return []
    
    async def _ping_sweep(self, ip_addresses: List[str]) -> List[DiscoveryResult]:
        """
        Perform ping sweep to find responsive hosts.
        
        Args:
            ip_addresses: List of IP addresses to ping
            
        Returns:
            List of responsive hosts
        """
        responsive_hosts = []
        
        # Use ThreadPoolExecutor for concurrent pings
        with ThreadPoolExecutor(max_workers=self.config.max_concurrent_scans) as executor:
            # Submit ping tasks
            future_to_ip = {
                executor.submit(self._ping_host, ip): ip 
                for ip in ip_addresses
            }
            
            # Collect results
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result and result.ping_success:
                        responsive_hosts.append(result)
                except Exception as e:
                    logger.debug(f"Ping failed for {ip}: {e}")
        
        return responsive_hosts
    
    def _ping_host(self, ip_address: str) -> Optional[DiscoveryResult]:
        """
        Ping a single host.
        
        Args:
            ip_address: IP address to ping
            
        Returns:
            DiscoveryResult if host is responsive, None otherwise
        """
        try:
            # Use simple ping for discovery
            success, latency = ping_host_simple(ip_address, timeout=self.config.ping_timeout)
            
            if success:
                return DiscoveryResult(
                    ip_address=ip_address,
                    ping_success=True,
                    ping_latency=latency,
                    discovery_method='ping'
                )
            
            return None
            
        except Exception as e:
            logger.debug(f"Ping error for {ip_address}: {e}")
            return None
    
    async def _detailed_discovery(self, ping_results: List[DiscoveryResult]) -> List[DiscoveryResult]:
        """
        Perform detailed discovery on responsive hosts.
        
        Args:
            ping_results: List of hosts that responded to ping
            
        Returns:
            List of detailed discovery results
        """
        detailed_results = []
        
        # Process hosts concurrently
        semaphore = asyncio.Semaphore(self.config.max_concurrent_scans)
        
        async def process_host(result: DiscoveryResult) -> DiscoveryResult:
            async with semaphore:
                return await self._discover_host_details(result)
        
        # Create tasks for all hosts
        tasks = [process_host(result) for result in ping_results]
        
        # Wait for all tasks to complete
        completed_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and collect results
        for result in completed_results:
            if isinstance(result, DiscoveryResult):
                detailed_results.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Error in detailed discovery: {result}")
        
        return detailed_results
    
    async def _discover_host_details(self, result: DiscoveryResult) -> DiscoveryResult:
        """
        Discover detailed information about a host.
        
        Args:
            result: Basic discovery result from ping
            
        Returns:
            Enhanced discovery result with detailed information
        """
        try:
            # Resolve hostname
            result.hostname = await self._resolve_hostname(result.ip_address)
            
            # Try SNMP discovery
            if is_snmp_available():
                await self._snmp_discovery(result)
            
            # Port scanning (if enabled)
            if self.config.port_scan_enabled:
                result.open_ports = await self._scan_ports(result.ip_address)
            
            # Device classification
            if self.config.device_classification_enabled:
                device_type, confidence = self.classifier.classify_device(result)
                result.device_type = device_type
                result.confidence_score = confidence
            
            return result
            
        except Exception as e:
            logger.error(f"Error in detailed discovery for {result.ip_address}: {e}")
            return result
    
    async def _resolve_hostname(self, ip_address: str) -> Optional[str]:
        """Resolve hostname for IP address."""
        try:
            loop = asyncio.get_event_loop()
            hostname, _, _ = await loop.run_in_executor(
                None, socket.gethostbyaddr, ip_address
            )
            return hostname
        except Exception:
            return None
    
    async def _snmp_discovery(self, result: DiscoveryResult):
        """
        Attempt SNMP discovery for a host.
        
        Args:
            result: Discovery result to enhance with SNMP data
        """
        try:
            # Create temporary host object for SNMP collection
            from .models import Host, Location, DeviceGroup
            
            # Get or create default location and group for discovery
            location, _ = Location.objects.get_or_create(
                name='Discovery',
                defaults={'address': 'Auto-discovery location'}
            )
            group, _ = DeviceGroup.objects.get_or_create(
                name='Discovered',
                defaults={'description': 'Auto-discovered devices'}
            )
            
            # Try different SNMP communities and versions
            for community in self.config.snmp_communities:
                for version in self.config.snmp_versions:
                    try:
                        # Create temporary host for SNMP testing
                        temp_host = Host(
                            hostname=result.hostname or result.ip_address,
                            ip_address=result.ip_address,
                            location=location,
                            group=group,
                            snmp_enabled=True,
                            snmp_version=version,
                            snmp_community=community,
                            snmp_timeout=self.config.snmp_timeout
                        )
                        
                        # Try to collect SNMP metrics
                        snmp_results = await collect_snmp_metrics(
                            temp_host, 
                            collectors=['system_metrics']
                        )
                        
                        if snmp_results and snmp_results.get('system_metrics', {}).success:
                            result.snmp_success = True
                            result.snmp_community = community
                            result.snmp_version = version
                            
                            # Extract system information
                            metrics = snmp_results['system_metrics'].metrics
                            if metrics:
                                result.os_info = metrics.get('sysDescr', '')
                                result.vendor = self._extract_vendor(result.os_info)
                                result.additional_data.update({
                                    'sysName': metrics.get('sysName', ''),
                                    'sysLocation': metrics.get('sysLocation', ''),
                                    'sysContact': metrics.get('sysContact', ''),
                                    'sysUpTime': metrics.get('sysUpTime', 0)
                                })
                            
                            # Found working SNMP, stop trying
                            return
                            
                    except Exception as e:
                        logger.debug(f"SNMP discovery failed for {result.ip_address} with {community}/{version}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"SNMP discovery error for {result.ip_address}: {e}")
    
    def _extract_vendor(self, sys_descr: str) -> Optional[str]:
        """Extract vendor information from SNMP sysDescr."""
        if not sys_descr:
            return None
        
        vendors = {
            'cisco': ['cisco', 'catalyst', 'nexus', 'asr', 'isr'],
            'juniper': ['juniper', 'junos', 'srx', 'mx', 'ex'],
            'hp': ['hp', 'hewlett', 'procurve', 'aruba'],
            'dell': ['dell', 'powerconnect', 'force10'],
            'netgear': ['netgear', 'prosafe'],
            'ubiquiti': ['ubiquiti', 'unifi', 'edgemax'],
            'mikrotik': ['mikrotik', 'routeros'],
            'fortinet': ['fortinet', 'fortigate'],
            'palo_alto': ['palo alto', 'pan-os'],
            'checkpoint': ['checkpoint', 'gaia'],
            'linux': ['linux', 'ubuntu', 'centos', 'redhat', 'debian'],
            'windows': ['windows', 'microsoft']
        }
        
        sys_descr_lower = sys_descr.lower()
        for vendor, keywords in vendors.items():
            if any(keyword in sys_descr_lower for keyword in keywords):
                return vendor
        
        return None
    
    async def _scan_ports(self, ip_address: str) -> List[int]:
        """
        Scan common ports on a host.
        
        Args:
            ip_address: IP address to scan
            
        Returns:
            List of open ports
        """
        open_ports = []
        
        async def check_port(port: int) -> Optional[int]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip_address, port),
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                return port
            except Exception:
                return None
        
        # Check ports concurrently
        tasks = [check_port(port) for port in self.config.port_scan_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect open ports
        for result in results:
            if isinstance(result, int):
                open_ports.append(result)
        
        return sorted(open_ports)


class DiscoveryService:
    """Main discovery service for managing network discovery operations."""
    
    def __init__(self, config: Optional[DiscoveryConfig] = None):
        """Initialize discovery service."""
        self.config = config or self._get_default_config()
        self.scanner = NetworkScanner(self.config)
    
    def _get_default_config(self) -> DiscoveryConfig:
        """Get default discovery configuration from Django settings."""
        discovery_settings = getattr(settings, 'DISCOVERY_SETTINGS', {})
        
        return DiscoveryConfig(
            subnets=discovery_settings.get('SUBNETS', ['192.168.1.0/24']),
            ping_timeout=discovery_settings.get('PING_TIMEOUT', 2),
            snmp_timeout=discovery_settings.get('SNMP_TIMEOUT', 5),
            snmp_communities=discovery_settings.get('SNMP_COMMUNITIES', ['public', 'private']),
            snmp_versions=discovery_settings.get('SNMP_VERSIONS', ['2c']),
            port_scan_enabled=discovery_settings.get('PORT_SCAN_ENABLED', False),
            port_scan_ports=discovery_settings.get('PORT_SCAN_PORTS', [22, 23, 80, 443, 161]),
            max_concurrent_scans=discovery_settings.get('MAX_CONCURRENT_SCANS', 50),
            device_classification_enabled=discovery_settings.get('DEVICE_CLASSIFICATION_ENABLED', True),
            auto_approve_known_devices=discovery_settings.get('AUTO_APPROVE_KNOWN_DEVICES', False),
            discovery_interval_hours=discovery_settings.get('DISCOVERY_INTERVAL_HOURS', 24)
        )
    
    async def run_discovery(self, subnets: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run network discovery on specified subnets.
        
        Args:
            subnets: List of subnets to scan (uses config default if None)
            
        Returns:
            Discovery results summary
        """
        start_time = time.time()
        subnets = subnets or self.config.subnets
        
        logger.info(f"Starting network discovery for subnets: {subnets}")
        
        all_results = []
        subnet_stats = {}
        
        # Discover each subnet
        for subnet in subnets:
            try:
                subnet_results = await self.scanner.discover_subnet(subnet)
                all_results.extend(subnet_results)
                
                subnet_stats[subnet] = {
                    'discovered_count': len(subnet_results),
                    'device_types': self._count_device_types(subnet_results)
                }
                
            except Exception as e:
                logger.error(f"Error discovering subnet {subnet}: {e}")
                subnet_stats[subnet] = {
                    'error': str(e),
                    'discovered_count': 0
                }
        
        # Store discovery results
        stored_count = await self._store_discovery_results(all_results)
        
        # Process approval workflow
        approved_count = await self._process_approval_workflow(all_results)
        
        execution_time = time.time() - start_time
        
        summary = {
            'status': 'completed',
            'execution_time': execution_time,
            'subnets_scanned': len(subnets),
            'total_discovered': len(all_results),
            'stored_count': stored_count,
            'approved_count': approved_count,
            'subnet_stats': subnet_stats,
            'device_type_summary': self._count_device_types(all_results),
            'discovery_timestamp': timezone.now().isoformat()
        }
        
        logger.info(f"Discovery completed: {summary}")
        return summary
    
    def _count_device_types(self, results: List[DiscoveryResult]) -> Dict[str, int]:
        """Count devices by type."""
        type_counts = {}
        for result in results:
            device_type = result.device_type or 'unknown'
            type_counts[device_type] = type_counts.get(device_type, 0) + 1
        return type_counts
    
    async def _store_discovery_results(self, results: List[DiscoveryResult]) -> int:
        """
        Store discovery results in database.
        
        Args:
            results: List of discovery results
            
        Returns:
            Number of results stored
        """
        stored_count = 0
        
        try:
            from asgiref.sync import sync_to_async
            
            for result in results:
                try:
                    # Check if device already exists
                    existing_device = await sync_to_async(
                        DiscoveredDevice.objects.filter(ip_address=result.ip_address).first
                    )()
                    
                    if existing_device:
                        # Update existing device
                        existing_device.hostname = result.hostname
                        existing_device.device_type = result.device_type
                        existing_device.vendor = result.vendor
                        existing_device.os_info = result.os_info
                        existing_device.snmp_community = result.snmp_community
                        existing_device.snmp_version = result.snmp_version
                        existing_device.confidence_score = result.confidence_score
                        existing_device.last_seen = result.discovered_at
                        existing_device.additional_data = result.additional_data
                        
                        await sync_to_async(existing_device.save)()
                    else:
                        # Create new discovered device
                        await sync_to_async(DiscoveredDevice.objects.create)(
                            ip_address=result.ip_address,
                            hostname=result.hostname,
                            mac_address=result.mac_address,
                            device_type=result.device_type,
                            vendor=result.vendor,
                            os_info=result.os_info,
                            snmp_community=result.snmp_community,
                            snmp_version=result.snmp_version,
                            confidence_score=result.confidence_score,
                            discovery_method=result.discovery_method,
                            additional_data=result.additional_data,
                            discovered_at=result.discovered_at,
                            last_seen=result.discovered_at,
                            status='pending'
                        )
                    
                    stored_count += 1
                    
                except Exception as e:
                    logger.error(f"Error storing discovery result for {result.ip_address}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error in store_discovery_results: {e}")
        
        return stored_count
    
    async def _process_approval_workflow(self, results: List[DiscoveryResult]) -> int:
        """
        Process approval workflow for discovered devices.
        
        Args:
            results: List of discovery results
            
        Returns:
            Number of devices auto-approved
        """
        if not self.config.auto_approve_known_devices:
            return 0
        
        approved_count = 0
        
        try:
            from asgiref.sync import sync_to_async
            
            for result in results:
                try:
                    # Check if this is a known device (already exists as Host)
                    existing_host = await sync_to_async(
                        Host.objects.filter(ip_address=result.ip_address).first
                    )()
                    
                    if existing_host:
                        # Update existing host with discovery data
                        if result.hostname and not existing_host.hostname:
                            existing_host.hostname = result.hostname
                        
                        if result.device_type and not existing_host.device_type:
                            existing_host.device_type = result.device_type
                        
                        if result.snmp_community and not existing_host.snmp_community:
                            existing_host.snmp_community = result.snmp_community
                            existing_host.snmp_enabled = True
                        
                        existing_host.last_seen = timezone.now()
                        await sync_to_async(existing_host.save)()
                        
                        # Mark discovered device as approved
                        discovered_device = await sync_to_async(
                            DiscoveredDevice.objects.filter(ip_address=result.ip_address).first
                        )()
                        
                        if discovered_device:
                            discovered_device.status = 'approved'
                            discovered_device.approved_at = timezone.now()
                            await sync_to_async(discovered_device.save)()
                        
                        approved_count += 1
                    
                    elif result.confidence_score >= 0.8:
                        # Auto-approve high-confidence devices
                        discovered_device = await sync_to_async(
                            DiscoveredDevice.objects.filter(ip_address=result.ip_address).first
                        )()
                        
                        if discovered_device:
                            discovered_device.status = 'auto_approved'
                            discovered_device.approved_at = timezone.now()
                            await sync_to_async(discovered_device.save)()
                            approved_count += 1
                
                except Exception as e:
                    logger.error(f"Error in approval workflow for {result.ip_address}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error in process_approval_workflow: {e}")
        
        return approved_count
    
    def _map_device_type(self, device_type: Optional[str]) -> str:
        """Map discovery device type to Host model choices."""
        device_type_mapping = {
            'router': 'router',
            'switch': 'switch',
            'firewall': 'firewall',
            'server': 'server',
            'access_point': 'ap',
            'printer': 'other',
            'camera': 'other',
            'ups': 'other',
            'unknown': 'other'
        }
        return device_type_mapping.get(device_type, 'other')
    
    async def approve_discovered_device(self, device_id: int, location_id: int, 
                                      group_id: int, user_id: int) -> bool:
        """
        Approve a discovered device and add it to monitoring.
        
        Args:
            device_id: ID of discovered device
            location_id: Location to assign device to
            group_id: Group to assign device to
            user_id: ID of user approving the device
            
        Returns:
            True if successful, False otherwise
        """
        try:
            from asgiref.sync import sync_to_async
            
            # Get discovered device
            discovered_device = await sync_to_async(
                DiscoveredDevice.objects.get
            )(id=device_id)
            
            # Get location and group
            location = await sync_to_async(Location.objects.get)(id=location_id)
            group = await sync_to_async(DeviceGroup.objects.get)(id=group_id)
            
            # Create new host
            new_host = await sync_to_async(Host.objects.create)(
                hostname=discovered_device.hostname or discovered_device.ip_address,
                ip_address=discovered_device.ip_address,
                location=location,
                group=group,
                device_type=self._map_device_type(discovered_device.device_type),
                snmp_enabled=bool(discovered_device.snmp_community),
                snmp_community=discovered_device.snmp_community or 'public',
                snmp_version=discovered_device.snmp_version or '2c',
                monitoring_enabled=True,
                ping_enabled=True,
                created_by_id=user_id
            )
            
            # Update discovered device status
            discovered_device.status = 'approved'
            discovered_device.approved_at = timezone.now()
            discovered_device.approved_by_id = user_id
            discovered_device.host = new_host
            await sync_to_async(discovered_device.save)()
            
            logger.info(f"Approved discovered device {discovered_device.ip_address} as host {new_host.id}")
            return True
            
        except Exception as e:
            logger.error(f"Error approving discovered device {device_id}: {e}")
            return False
    
    async def reject_discovered_device(self, device_id: int, user_id: int, 
                                     reason: str = '') -> bool:
        """
        Reject a discovered device.
        
        Args:
            device_id: ID of discovered device
            user_id: ID of user rejecting the device
            reason: Reason for rejection
            
        Returns:
            True if successful, False otherwise
        """
        try:
            from asgiref.sync import sync_to_async
            
            discovered_device = await sync_to_async(
                DiscoveredDevice.objects.get
            )(id=device_id)
            
            discovered_device.status = 'rejected'
            discovered_device.rejected_at = timezone.now()
            discovered_device.rejected_by_id = user_id
            discovered_device.rejection_reason = reason
            await sync_to_async(discovered_device.save)()
            
            logger.info(f"Rejected discovered device {discovered_device.ip_address}: {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Error rejecting discovered device {device_id}: {e}")
            return False


# Convenience functions
async def run_network_discovery(subnets: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run network discovery with default configuration."""
    service = DiscoveryService()
    return await service.run_discovery(subnets)


async def discover_subnet(subnet: str) -> List[DiscoveryResult]:
    """Discover devices in a single subnet."""
    config = DiscoveryService()._get_default_config()
    scanner = NetworkScanner(config)
    return await scanner.discover_subnet(subnet)


def get_discovery_statistics() -> Dict[str, Any]:
    """Get discovery system statistics."""
    try:
        from django.db.models import Count
        
        stats = {
            'discovered_devices': {
                'total': DiscoveredDevice.objects.count(),
                'pending': DiscoveredDevice.objects.filter(status='pending').count(),
                'approved': DiscoveredDevice.objects.filter(status='approved').count(),
                'rejected': DiscoveredDevice.objects.filter(status='rejected').count(),
                'auto_approved': DiscoveredDevice.objects.filter(status='auto_approved').count(),
            },
            'device_types': dict(
                DiscoveredDevice.objects.values('device_type')
                .annotate(count=Count('device_type'))
                .values_list('device_type', 'count')
            ),
            'recent_discoveries': DiscoveredDevice.objects.filter(
                discovered_at__gte=timezone.now() - timedelta(days=7)
            ).count(),
            'last_discovery': None
        }
        
        # Get last discovery time
        last_discovery = DiscoveredDevice.objects.order_by('-discovered_at').first()
        if last_discovery:
            stats['last_discovery'] = last_discovery.discovered_at.isoformat()
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting discovery statistics: {e}")
        return {'error': str(e)}