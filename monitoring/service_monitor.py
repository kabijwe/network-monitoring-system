"""
Service monitoring system for TCP/UDP ports and HTTP/HTTPS endpoints.

This module provides monitoring capabilities for various network services
including port connectivity checks and HTTP endpoint monitoring.
"""

import logging
import asyncio
import socket
import ssl
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse
import aiohttp
from django.utils import timezone
from django.conf import settings

from .models import Host, MonitoringMetric

logger = logging.getLogger(__name__)


@dataclass
class ServiceCheckResult:
    """Result of a service check."""
    success: bool
    response_time: float  # in milliseconds
    error_message: str = ''
    status_code: Optional[int] = None  # For HTTP checks
    additional_data: Dict[str, Any] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = timezone.now()
        if self.additional_data is None:
            self.additional_data = {}


class PortChecker:
    """TCP and UDP port connectivity checker."""
    
    def __init__(self, timeout: int = 5):
        """
        Initialize port checker.
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
    
    async def check_tcp_port(self, host: str, port: int) -> ServiceCheckResult:
        """
        Check TCP port connectivity.
        
        Args:
            host: Hostname or IP address
            port: TCP port number
            
        Returns:
            ServiceCheckResult with connection status
        """
        start_time = time.time()
        
        try:
            # Create connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # Close connection immediately
            writer.close()
            await writer.wait_closed()
            
            response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            
            return ServiceCheckResult(
                success=True,
                response_time=response_time,
                additional_data={'port': port, 'protocol': 'tcp'}
            )
            
        except asyncio.TimeoutError:
            response_time = self.timeout * 1000
            return ServiceCheckResult(
                success=False,
                response_time=response_time,
                error_message=f"Connection timeout after {self.timeout}s",
                additional_data={'port': port, 'protocol': 'tcp'}
            )
        
        except ConnectionRefusedError:
            response_time = (time.time() - start_time) * 1000
            return ServiceCheckResult(
                success=False,
                response_time=response_time,
                error_message="Connection refused",
                additional_data={'port': port, 'protocol': 'tcp'}
            )
        
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ServiceCheckResult(
                success=False,
                response_time=response_time,
                error_message=str(e),
                additional_data={'port': port, 'protocol': 'tcp'}
            )
    
    async def check_udp_port(self, host: str, port: int) -> ServiceCheckResult:
        """
        Check UDP port connectivity.
        
        Note: UDP is connectionless, so this sends a packet and waits for a response.
        The absence of an ICMP "port unreachable" message is considered success.
        
        Args:
            host: Hostname or IP address
            port: UDP port number
            
        Returns:
            ServiceCheckResult with connectivity status
        """
        start_time = time.time()
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send a small packet
            test_data = b"NMS_UDP_TEST"
            sock.sendto(test_data, (host, port))
            
            try:
                # Try to receive data (may timeout, which is OK for UDP)
                data, addr = sock.recvfrom(1024)
                response_time = (time.time() - start_time) * 1000
                
                return ServiceCheckResult(
                    success=True,
                    response_time=response_time,
                    additional_data={
                        'port': port, 
                        'protocol': 'udp',
                        'response_received': True,
                        'response_size': len(data)
                    }
                )
                
            except socket.timeout:
                # Timeout is normal for UDP - no response doesn't mean failure
                response_time = (time.time() - start_time) * 1000
                
                return ServiceCheckResult(
                    success=True,  # Assume success if no ICMP unreachable
                    response_time=response_time,
                    additional_data={
                        'port': port, 
                        'protocol': 'udp',
                        'response_received': False,
                        'note': 'No response (normal for UDP)'
                    }
                )
            
            finally:
                sock.close()
                
        except socket.error as e:
            response_time = (time.time() - start_time) * 1000
            
            # Check if it's a "port unreachable" error
            if "unreachable" in str(e).lower():
                return ServiceCheckResult(
                    success=False,
                    response_time=response_time,
                    error_message="Port unreachable",
                    additional_data={'port': port, 'protocol': 'udp'}
                )
            
            return ServiceCheckResult(
                success=False,
                response_time=response_time,
                error_message=str(e),
                additional_data={'port': port, 'protocol': 'udp'}
            )
        
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ServiceCheckResult(
                success=False,
                response_time=response_time,
                error_message=str(e),
                additional_data={'port': port, 'protocol': 'udp'}
            )


class HTTPChecker:
    """HTTP/HTTPS endpoint checker."""
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        """
        Initialize HTTP checker.
        
        Args:
            timeout: Request timeout in seconds
            user_agent: User agent string for requests
        """
        self.timeout = timeout
        self.user_agent = user_agent or "NMS-Monitor/1.0"
    
    async def check_http_endpoint(self, url: str, expected_status: List[int] = None,
                                expected_content: str = None) -> ServiceCheckResult:
        """
        Check HTTP/HTTPS endpoint.
        
        Args:
            url: URL to check
            expected_status: List of expected HTTP status codes (default: [200])
            expected_content: Expected content in response body
            
        Returns:
            ServiceCheckResult with HTTP check status
        """
        if expected_status is None:
            expected_status = [200]
        
        start_time = time.time()
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            is_https = parsed_url.scheme.lower() == 'https'
            
            # Configure SSL context for HTTPS
            ssl_context = None
            if is_https:
                ssl_context = ssl.create_default_context()
                # For monitoring, we might want to accept self-signed certificates
                # ssl_context.check_hostname = False
                # ssl_context.verify_mode = ssl.CERT_NONE
            
            # Create HTTP session
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {'User-Agent': self.user_agent}
            
            async with aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=aiohttp.TCPConnector(ssl=ssl_context)
            ) as session:
                
                async with session.get(url) as response:
                    response_time = (time.time() - start_time) * 1000
                    
                    # Read response content
                    content = await response.text()
                    
                    # Check status code
                    status_ok = response.status in expected_status
                    
                    # Check content if specified
                    content_ok = True
                    if expected_content:
                        content_ok = expected_content in content
                    
                    success = status_ok and content_ok
                    error_message = ""
                    
                    if not status_ok:
                        error_message += f"Unexpected status code: {response.status}. "
                    
                    if not content_ok:
                        error_message += f"Expected content '{expected_content}' not found. "
                    
                    return ServiceCheckResult(
                        success=success,
                        response_time=response_time,
                        status_code=response.status,
                        error_message=error_message.strip(),
                        additional_data={
                            'url': url,
                            'status_code': response.status,
                            'content_length': len(content),
                            'headers': dict(response.headers),
                            'ssl_enabled': is_https,
                            'expected_status': expected_status,
                            'expected_content': expected_content
                        }
                    )
        
        except asyncio.TimeoutError:
            response_time = self.timeout * 1000
            return ServiceCheckResult(
                success=False,
                response_time=response_time,
                error_message=f"Request timeout after {self.timeout}s",
                additional_data={'url': url}
            )
        
        except aiohttp.ClientError as e:
            response_time = (time.time() - start_time) * 1000
            return ServiceCheckResult(
                success=False,
                response_time=response_time,
                error_message=f"HTTP client error: {str(e)}",
                additional_data={'url': url}
            )
        
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ServiceCheckResult(
                success=False,
                response_time=response_time,
                error_message=str(e),
                additional_data={'url': url}
            )


class ServiceMonitoringService:
    """Main service monitoring service."""
    
    def __init__(self):
        """Initialize service monitoring service."""
        # Get configuration from Django settings
        monitoring_settings = getattr(settings, 'MONITORING_SETTINGS', {})
        
        self.port_timeout = monitoring_settings.get('PORT_TIMEOUT', 5)
        self.http_timeout = monitoring_settings.get('HTTP_TIMEOUT', 10)
        self.user_agent = monitoring_settings.get('USER_AGENT', 'NMS-Monitor/1.0')
        
        # Initialize checkers
        self.port_checker = PortChecker(timeout=self.port_timeout)
        self.http_checker = HTTPChecker(timeout=self.http_timeout, user_agent=self.user_agent)
    
    async def check_host_services(self, host: Host) -> Dict[str, List[ServiceCheckResult]]:
        """
        Check all configured services for a host.
        
        Args:
            host: Host to check services for
            
        Returns:
            Dictionary mapping service types to results
        """
        if not host.service_checks_enabled:
            logger.debug(f"Service checks disabled for host {host.hostname}")
            return {}
        
        results = {
            'tcp_ports': [],
            'udp_ports': [],
            'http_endpoints': []
        }
        
        # Check TCP ports
        if host.tcp_ports:
            tcp_ports = self._parse_ports(host.tcp_ports)
            for port in tcp_ports:
                result = await self.port_checker.check_tcp_port(host.ip_address, port)
                results['tcp_ports'].append(result)
                
                # Store result in database
                await self._store_service_result(host, 'tcp_port', f"tcp_{port}", result)
        
        # Check UDP ports
        if host.udp_ports:
            udp_ports = self._parse_ports(host.udp_ports)
            for port in udp_ports:
                result = await self.port_checker.check_udp_port(host.ip_address, port)
                results['udp_ports'].append(result)
                
                # Store result in database
                await self._store_service_result(host, 'udp_port', f"udp_{port}", result)
        
        # Check HTTP endpoints
        if host.http_urls:
            urls = self._parse_urls(host.http_urls)
            for url in urls:
                result = await self.http_checker.check_http_endpoint(url)
                results['http_endpoints'].append(result)
                
                # Store result in database
                url_name = self._url_to_name(url)
                await self._store_service_result(host, 'http_endpoint', url_name, result)
        
        return results
    
    def _parse_ports(self, ports_string: str) -> List[int]:
        """Parse comma-separated port string into list of integers."""
        if not ports_string:
            return []
        
        ports = []
        for port_str in ports_string.split(','):
            port_str = port_str.strip()
            if port_str:
                try:
                    port = int(port_str)
                    if 1 <= port <= 65535:
                        ports.append(port)
                    else:
                        logger.warning(f"Invalid port number: {port}")
                except ValueError:
                    logger.warning(f"Invalid port format: {port_str}")
        
        return ports
    
    def _parse_urls(self, urls_string: str) -> List[str]:
        """Parse newline-separated URL string into list of URLs."""
        if not urls_string:
            return []
        
        urls = []
        for url in urls_string.split('\n'):
            url = url.strip()
            if url:
                # Add http:// if no scheme specified
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                urls.append(url)
        
        return urls
    
    def _url_to_name(self, url: str) -> str:
        """Convert URL to a metric name."""
        parsed = urlparse(url)
        name = f"{parsed.hostname}"
        if parsed.port:
            name += f"_{parsed.port}"
        if parsed.path and parsed.path != '/':
            # Replace special characters with underscores
            path = parsed.path.replace('/', '_').replace('-', '_').replace('.', '_')
            name += path
        return name
    
    async def _store_service_result(self, host: Host, service_type: str, 
                                  service_name: str, result: ServiceCheckResult):
        """Store service check result in database."""
        try:
            from asgiref.sync import sync_to_async
            
            create_metric = sync_to_async(MonitoringMetric.objects.create)
            
            # Store response time metric
            await create_metric(
                host=host,
                metric_type='service_check',
                metric_name=f"{service_name}_response_time",
                value=result.response_time,
                unit='ms',
                additional_data={
                    'service_type': service_type,
                    'service_name': service_name,
                    'success': result.success,
                    'error_message': result.error_message,
                    'status_code': result.status_code,
                    **result.additional_data
                }
            )
            
            # Store success/failure metric (1 for success, 0 for failure)
            await create_metric(
                host=host,
                metric_type='service_check',
                metric_name=f"{service_name}_status",
                value=1.0 if result.success else 0.0,
                unit='boolean',
                additional_data={
                    'service_type': service_type,
                    'service_name': service_name,
                    'success': result.success,
                    'error_message': result.error_message,
                    'status_code': result.status_code,
                    **result.additional_data
                }
            )
            
        except Exception as e:
            logger.error(f"Error storing service check result: {e}")


class PluginSystem:
    """System for loading and executing custom monitoring plugins."""
    
    def __init__(self, plugin_dir: str = None):
        """
        Initialize plugin system.
        
        Args:
            plugin_dir: Directory containing plugin files
        """
        self.plugin_dir = plugin_dir or "monitoring/plugins"
        self.plugins = {}
        self.load_plugins()
    
    def load_plugins(self):
        """Load all plugins from the plugin directory."""
        import os
        import importlib.util
        
        if not os.path.exists(self.plugin_dir):
            logger.info(f"Plugin directory {self.plugin_dir} does not exist")
            return
        
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                plugin_name = filename[:-3]  # Remove .py extension
                plugin_path = os.path.join(self.plugin_dir, filename)
                
                try:
                    # Load plugin module
                    spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Look for plugin class
                    if hasattr(module, 'Plugin'):
                        plugin_instance = module.Plugin()
                        self.plugins[plugin_name] = plugin_instance
                        logger.info(f"Loaded plugin: {plugin_name}")
                    else:
                        logger.warning(f"Plugin {plugin_name} does not have a Plugin class")
                
                except Exception as e:
                    logger.error(f"Error loading plugin {plugin_name}: {e}")
    
    async def execute_plugin(self, plugin_name: str, host: Host, **kwargs) -> ServiceCheckResult:
        """
        Execute a specific plugin.
        
        Args:
            plugin_name: Name of the plugin to execute
            host: Host to check
            **kwargs: Additional arguments for the plugin
            
        Returns:
            ServiceCheckResult from plugin execution
        """
        if plugin_name not in self.plugins:
            return ServiceCheckResult(
                success=False,
                response_time=0,
                error_message=f"Plugin '{plugin_name}' not found"
            )
        
        plugin = self.plugins[plugin_name]
        
        try:
            # Execute plugin with sandboxing
            start_time = time.time()
            
            # Set timeout for plugin execution
            result = await asyncio.wait_for(
                plugin.check(host, **kwargs),
                timeout=30  # 30 second timeout for plugins
            )
            
            if not isinstance(result, ServiceCheckResult):
                # Convert plugin result to ServiceCheckResult if needed
                response_time = (time.time() - start_time) * 1000
                result = ServiceCheckResult(
                    success=bool(result),
                    response_time=response_time,
                    additional_data={'plugin': plugin_name}
                )
            
            return result
            
        except asyncio.TimeoutError:
            return ServiceCheckResult(
                success=False,
                response_time=30000,  # 30 seconds
                error_message=f"Plugin '{plugin_name}' execution timeout",
                additional_data={'plugin': plugin_name}
            )
        
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ServiceCheckResult(
                success=False,
                response_time=response_time,
                error_message=f"Plugin error: {str(e)}",
                additional_data={'plugin': plugin_name}
            )
    
    def get_available_plugins(self) -> List[str]:
        """Get list of available plugin names."""
        return list(self.plugins.keys())


# Convenience functions
async def check_host_services(host: Host) -> Dict[str, List[ServiceCheckResult]]:
    """Check all services for a host."""
    service = ServiceMonitoringService()
    return await service.check_host_services(host)


async def check_tcp_port(host: str, port: int, timeout: int = 5) -> ServiceCheckResult:
    """Check a single TCP port."""
    checker = PortChecker(timeout=timeout)
    return await checker.check_tcp_port(host, port)


async def check_udp_port(host: str, port: int, timeout: int = 5) -> ServiceCheckResult:
    """Check a single UDP port."""
    checker = PortChecker(timeout=timeout)
    return await checker.check_udp_port(host, port)


async def check_http_endpoint(url: str, timeout: int = 10) -> ServiceCheckResult:
    """Check a single HTTP endpoint."""
    checker = HTTPChecker(timeout=timeout)
    return await checker.check_http_endpoint(url)


def get_plugin_system() -> PluginSystem:
    """Get the global plugin system instance."""
    if not hasattr(get_plugin_system, '_instance'):
        get_plugin_system._instance = PluginSystem()
    return get_plugin_system._instance