"""
Ping/ICMP monitoring service for network devices.

This module provides ping monitoring functionality with configurable thresholds,
latency measurement, and packet loss detection.
"""
import asyncio
import subprocess
import time
import logging
import platform
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings

logger = logging.getLogger(__name__)


@dataclass
class PingResult:
    """Result of a ping operation."""
    host: str
    ip_address: str
    success: bool
    latency: Optional[float] = None  # in milliseconds
    packet_loss: float = 0.0  # percentage
    packets_sent: int = 0
    packets_received: int = 0
    error_message: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = timezone.now()


@dataclass
class PingThresholds:
    """Ping monitoring thresholds."""
    warning_latency: float = 100.0  # milliseconds
    critical_latency: float = 500.0  # milliseconds
    warning_packet_loss: float = 5.0  # percentage
    critical_packet_loss: float = 20.0  # percentage
    timeout: int = 5  # seconds
    packet_count: int = 4  # number of ping packets


class PingMonitor:
    """
    Ping monitoring service with async support and configurable thresholds.
    """
    
    def __init__(self, thresholds: Optional[PingThresholds] = None):
        """Initialize ping monitor with optional custom thresholds."""
        self.thresholds = thresholds or PingThresholds()
        self.is_windows = platform.system().lower() == 'windows'
        self.is_linux = platform.system().lower() == 'linux'
        self.is_macos = platform.system().lower() == 'darwin'
        
        # Get monitoring settings from Django settings
        monitoring_settings = getattr(settings, 'MONITORING_SETTINGS', {})
        self.ping_timeout = monitoring_settings.get('PING_TIMEOUT', 5)
        
    async def ping_host(self, host: str, ip_address: str) -> PingResult:
        """
        Ping a single host asynchronously.
        
        Args:
            host: Hostname or device name
            ip_address: IP address to ping
            
        Returns:
            PingResult with ping statistics
        """
        try:
            # Build ping command based on OS
            cmd = self._build_ping_command(ip_address)
            
            # Execute ping command asynchronously
            start_time = time.time()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.ping_timeout + 2  # Add buffer to command timeout
                )
                execution_time = time.time() - start_time
                
                # Parse ping output
                result = self._parse_ping_output(
                    host, ip_address, stdout.decode(), stderr.decode(), process.returncode
                )
                
                logger.debug(f"Ping {ip_address} completed in {execution_time:.2f}s: {result}")
                return result
                
            except asyncio.TimeoutError:
                # Kill the process if it times out
                try:
                    process.kill()
                    await process.wait()
                except:
                    pass
                
                return PingResult(
                    host=host,
                    ip_address=ip_address,
                    success=False,
                    packet_loss=100.0,
                    packets_sent=self.thresholds.packet_count,
                    packets_received=0,
                    error_message=f"Ping timeout after {self.ping_timeout}s"
                )
                
        except Exception as e:
            logger.error(f"Ping error for {ip_address}: {e}")
            return PingResult(
                host=host,
                ip_address=ip_address,
                success=False,
                packet_loss=100.0,
                packets_sent=self.thresholds.packet_count,
                packets_received=0,
                error_message=str(e)
            )
    
    def _build_ping_command(self, ip_address: str) -> List[str]:
        """Build ping command based on operating system."""
        if self.is_windows:
            return [
                'ping',
                '-n', str(self.thresholds.packet_count),
                '-w', str(self.ping_timeout * 1000),  # Windows uses milliseconds
                ip_address
            ]
        else:  # Linux/macOS
            cmd = ['ping']
            
            if self.is_linux:
                cmd.extend([
                    '-c', str(self.thresholds.packet_count),
                    '-W', str(self.ping_timeout),
                    '-i', '0.2'  # 200ms interval between packets
                ])
            else:  # macOS
                cmd.extend([
                    '-c', str(self.thresholds.packet_count),
                    '-W', str(self.ping_timeout * 1000),  # macOS uses milliseconds
                    '-i', '0.2'
                ])
            
            cmd.append(ip_address)
            return cmd
    
    def _parse_ping_output(self, host: str, ip_address: str, stdout: str, stderr: str, returncode: int) -> PingResult:
        """Parse ping command output and extract statistics."""
        try:
            if returncode != 0 and stderr:
                return PingResult(
                    host=host,
                    ip_address=ip_address,
                    success=False,
                    packet_loss=100.0,
                    packets_sent=self.thresholds.packet_count,
                    packets_received=0,
                    error_message=stderr.strip()
                )
            
            # Parse based on OS
            if self.is_windows:
                return self._parse_windows_ping(host, ip_address, stdout)
            else:
                return self._parse_unix_ping(host, ip_address, stdout)
                
        except Exception as e:
            logger.error(f"Error parsing ping output for {ip_address}: {e}")
            return PingResult(
                host=host,
                ip_address=ip_address,
                success=False,
                packet_loss=100.0,
                packets_sent=self.thresholds.packet_count,
                packets_received=0,
                error_message=f"Parse error: {str(e)}"
            )
    
    def _parse_windows_ping(self, host: str, ip_address: str, output: str) -> PingResult:
        """Parse Windows ping output."""
        lines = output.strip().split('\n')
        
        packets_sent = self.thresholds.packet_count
        packets_received = 0
        latencies = []
        
        # Parse individual ping responses
        for line in lines:
            line = line.strip()
            if 'Reply from' in line and 'time=' in line:
                packets_received += 1
                # Extract latency: "time=1ms" or "time<1ms"
                try:
                    if 'time<' in line:
                        latency = 0.5  # Assume sub-millisecond
                    else:
                        time_part = line.split('time=')[1].split('ms')[0]
                        latency = float(time_part)
                    latencies.append(latency)
                except (IndexError, ValueError):
                    pass
            elif 'Request timed out' in line or 'Destination host unreachable' in line:
                # Packet loss, already counted by not incrementing packets_received
                pass
        
        # Calculate statistics
        packet_loss = ((packets_sent - packets_received) / packets_sent) * 100
        avg_latency = sum(latencies) / len(latencies) if latencies else None
        success = packets_received > 0
        
        return PingResult(
            host=host,
            ip_address=ip_address,
            success=success,
            latency=avg_latency,
            packet_loss=packet_loss,
            packets_sent=packets_sent,
            packets_received=packets_received
        )
    
    def _parse_unix_ping(self, host: str, ip_address: str, output: str) -> PingResult:
        """Parse Unix/Linux/macOS ping output."""
        lines = output.strip().split('\n')
        
        packets_sent = self.thresholds.packet_count
        packets_received = 0
        latencies = []
        
        # Parse individual ping responses
        for line in lines:
            line = line.strip()
            if 'bytes from' in line and 'time=' in line:
                packets_received += 1
                # Extract latency: "time=1.23 ms"
                try:
                    time_part = line.split('time=')[1].split(' ms')[0]
                    latency = float(time_part)
                    latencies.append(latency)
                except (IndexError, ValueError):
                    pass
        
        # Try to parse summary line for more accurate statistics
        for line in lines:
            if 'packets transmitted' in line and 'received' in line:
                try:
                    # Format: "4 packets transmitted, 4 received, 0% packet loss"
                    parts = line.split(',')
                    sent_part = parts[0].strip().split()[0]
                    received_part = parts[1].strip().split()[0]
                    packets_sent = int(sent_part)
                    packets_received = int(received_part)
                except (IndexError, ValueError):
                    pass
                break
        
        # Calculate statistics
        packet_loss = ((packets_sent - packets_received) / packets_sent) * 100 if packets_sent > 0 else 100
        avg_latency = sum(latencies) / len(latencies) if latencies else None
        success = packets_received > 0
        
        return PingResult(
            host=host,
            ip_address=ip_address,
            success=success,
            latency=avg_latency,
            packet_loss=packet_loss,
            packets_sent=packets_sent,
            packets_received=packets_received
        )
    
    async def ping_multiple_hosts(self, hosts: List[Tuple[str, str]], max_concurrent: int = 50) -> List[PingResult]:
        """
        Ping multiple hosts concurrently.
        
        Args:
            hosts: List of (hostname, ip_address) tuples
            max_concurrent: Maximum number of concurrent ping operations
            
        Returns:
            List of PingResult objects
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def ping_with_semaphore(host: str, ip: str) -> PingResult:
            async with semaphore:
                return await self.ping_host(host, ip)
        
        tasks = [ping_with_semaphore(host, ip) for host, ip in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle any exceptions
        ping_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                host, ip = hosts[i]
                logger.error(f"Ping task failed for {ip}: {result}")
                ping_results.append(PingResult(
                    host=host,
                    ip_address=ip,
                    success=False,
                    packet_loss=100.0,
                    packets_sent=self.thresholds.packet_count,
                    packets_received=0,
                    error_message=str(result)
                ))
            else:
                ping_results.append(result)
        
        return ping_results
    
    def evaluate_status(self, result: PingResult) -> str:
        """
        Evaluate ping result and return status based on thresholds.
        
        Args:
            result: PingResult to evaluate
            
        Returns:
            Status string: 'up', 'warning', 'critical', 'down'
        """
        if not result.success:
            return 'down'
        
        # Check for critical conditions first (worst case)
        is_critical = False
        is_warning = False
        
        # Check packet loss thresholds
        if result.packet_loss >= self.thresholds.critical_packet_loss:
            is_critical = True
        elif result.packet_loss >= self.thresholds.warning_packet_loss:
            is_warning = True
        
        # Check latency thresholds
        if result.latency is not None:
            if result.latency >= self.thresholds.critical_latency:
                is_critical = True
            elif result.latency >= self.thresholds.warning_latency:
                is_warning = True
        
        # Return worst status
        if is_critical:
            return 'critical'
        elif is_warning:
            return 'warning'
        
        return 'up'
    
    def get_status_details(self, result: PingResult) -> Dict:
        """
        Get detailed status information for a ping result.
        
        Args:
            result: PingResult to analyze
            
        Returns:
            Dictionary with detailed status information
        """
        status = self.evaluate_status(result)
        
        details = {
            'status': status,
            'success': result.success,
            'latency': result.latency,
            'packet_loss': result.packet_loss,
            'packets_sent': result.packets_sent,
            'packets_received': result.packets_received,
            'timestamp': result.timestamp,
            'thresholds': {
                'warning_latency': self.thresholds.warning_latency,
                'critical_latency': self.thresholds.critical_latency,
                'warning_packet_loss': self.thresholds.warning_packet_loss,
                'critical_packet_loss': self.thresholds.critical_packet_loss
            }
        }
        
        if result.error_message:
            details['error_message'] = result.error_message
        
        # Add status explanation
        if status == 'down':
            details['status_reason'] = 'Host unreachable'
        elif status == 'critical':
            reasons = []
            if result.packet_loss >= self.thresholds.critical_packet_loss:
                reasons.append(f'High packet loss: {result.packet_loss:.1f}%')
            if result.latency and result.latency >= self.thresholds.critical_latency:
                reasons.append(f'High latency: {result.latency:.1f}ms')
            details['status_reason'] = '; '.join(reasons)
        elif status == 'warning':
            reasons = []
            if result.packet_loss >= self.thresholds.warning_packet_loss:
                reasons.append(f'Elevated packet loss: {result.packet_loss:.1f}%')
            if result.latency and result.latency >= self.thresholds.warning_latency:
                reasons.append(f'Elevated latency: {result.latency:.1f}ms')
            details['status_reason'] = '; '.join(reasons)
        else:
            details['status_reason'] = 'Host responding normally'
        
        return details


# Convenience functions for synchronous usage
def ping_host_sync(host: str, ip_address: str, thresholds: Optional[PingThresholds] = None) -> PingResult:
    """Synchronous wrapper for ping_host."""
    monitor = PingMonitor(thresholds)
    return asyncio.run(monitor.ping_host(host, ip_address))


def ping_multiple_hosts_sync(hosts: List[Tuple[str, str]], max_concurrent: int = 50, 
                           thresholds: Optional[PingThresholds] = None) -> List[PingResult]:
    """Synchronous wrapper for ping_multiple_hosts."""
    monitor = PingMonitor(thresholds)
    return asyncio.run(monitor.ping_multiple_hosts(hosts, max_concurrent))