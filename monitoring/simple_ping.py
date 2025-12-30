"""
Simple synchronous ping implementation for Django views.
"""
import subprocess
import time
import platform
import logging
from typing import Dict, Any, Optional
from django.utils import timezone
from .models import Host, PingResult

logger = logging.getLogger(__name__)


def ping_host_simple(host: Host) -> Optional[PingResult]:
    """
    Simple synchronous ping implementation that works in Django views.
    
    Args:
        host: Host model instance to ping
        
    Returns:
        PingResult model instance or None if skipped
    """
    if not host.ping_enabled or not host.monitoring_enabled:
        logger.debug(f"Ping monitoring disabled for host {host.hostname}")
        return None
    
    # Skip if host is in maintenance
    if host.in_maintenance and host.is_in_maintenance():
        logger.debug(f"Host {host.hostname} is in maintenance, skipping ping")
        return None
    
    try:
        start_time = time.time()
        
        # Build ping command based on OS
        is_windows = platform.system().lower() == 'windows'
        
        if is_windows:
            cmd = [
                'ping',
                '-n', str(host.ping_packet_count),
                '-w', str(host.ping_timeout * 1000),  # Windows uses milliseconds
                host.ip_address
            ]
        else:  # Linux/macOS
            cmd = [
                'ping',
                '-c', str(host.ping_packet_count),
                '-W', str(host.ping_timeout),
                '-i', '0.2',  # 200ms interval between packets
                host.ip_address
            ]
        
        # Execute ping command
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=host.ping_timeout + 2  # Add buffer to command timeout
            )
            
            check_duration = time.time() - start_time
            
            # Parse ping output
            ping_data = _parse_ping_output(
                host.hostname, host.ip_address, result.stdout, result.stderr, 
                result.returncode, host.ping_packet_count, is_windows
            )
            
            # Evaluate status based on thresholds
            status = _evaluate_ping_status(ping_data, host)
            
            # Create PingResult record
            ping_result = PingResult.objects.create(
                host=host,
                success=ping_data['success'],
                latency=ping_data['latency'],
                packet_loss=ping_data['packet_loss'],
                packets_sent=ping_data['packets_sent'],
                packets_received=ping_data['packets_received'],
                status=status['status'],
                status_reason=status['reason'],
                error_message=ping_data.get('error_message', ''),
                check_duration=check_duration
            )
            
            # Update host status and timestamps
            old_status = host.status
            host.status = status['status'] if not host.in_maintenance else 'maintenance'
            host.last_check = timezone.now()
            
            if ping_data['success']:
                host.last_seen = timezone.now()
            
            host.save(update_fields=['status', 'last_check', 'last_seen'])
            
            logger.info(f"Ping completed for {host.hostname}: {status['status']} "
                       f"(latency: {ping_data['latency']}ms, loss: {ping_data['packet_loss']}%)")
            
            return ping_result
            
        except subprocess.TimeoutExpired:
            check_duration = time.time() - start_time
            
            # Create timeout result
            ping_result = PingResult.objects.create(
                host=host,
                success=False,
                packet_loss=100.0,
                packets_sent=host.ping_packet_count,
                packets_received=0,
                status='down',
                status_reason=f'Ping timeout after {host.ping_timeout}s',
                error_message=f'Ping timeout after {host.ping_timeout}s',
                check_duration=check_duration
            )
            
            # Update host status
            old_status = host.status
            host.status = 'down' if not host.in_maintenance else 'maintenance'
            host.last_check = timezone.now()
            host.save(update_fields=['status', 'last_check'])
            
            return ping_result
            
    except Exception as e:
        logger.error(f"Error pinging host {host.hostname}: {e}")
        
        # Create error result
        ping_result = PingResult.objects.create(
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
        
        return ping_result


def _parse_ping_output(hostname: str, ip_address: str, stdout: str, stderr: str, 
                      returncode: int, packet_count: int, is_windows: bool) -> Dict[str, Any]:
    """Parse ping command output and extract statistics."""
    try:
        if returncode != 0 and stderr:
            return {
                'success': False,
                'latency': None,
                'packet_loss': 100.0,
                'packets_sent': packet_count,
                'packets_received': 0,
                'error_message': stderr.strip()
            }
        
        if is_windows:
            return _parse_windows_ping(stdout, packet_count)
        else:
            return _parse_unix_ping(stdout, packet_count)
            
    except Exception as e:
        logger.error(f"Error parsing ping output for {ip_address}: {e}")
        return {
            'success': False,
            'latency': None,
            'packet_loss': 100.0,
            'packets_sent': packet_count,
            'packets_received': 0,
            'error_message': f'Parse error: {str(e)}'
        }


def _parse_windows_ping(output: str, packet_count: int) -> Dict[str, Any]:
    """Parse Windows ping output."""
    lines = output.strip().split('\n')
    
    packets_sent = packet_count
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
    
    return {
        'success': success,
        'latency': avg_latency,
        'packet_loss': packet_loss,
        'packets_sent': packets_sent,
        'packets_received': packets_received
    }


def _parse_unix_ping(output: str, packet_count: int) -> Dict[str, Any]:
    """Parse Unix/Linux/macOS ping output."""
    lines = output.strip().split('\n')
    
    packets_sent = packet_count
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
    
    return {
        'success': success,
        'latency': avg_latency,
        'packet_loss': packet_loss,
        'packets_sent': packets_sent,
        'packets_received': packets_received
    }


def _evaluate_ping_status(ping_data: Dict[str, Any], host: Host) -> Dict[str, str]:
    """Evaluate ping result and return status based on thresholds."""
    if not ping_data['success']:
        return {
            'status': 'down',
            'reason': 'Host unreachable'
        }
    
    # Check packet loss thresholds
    if ping_data['packet_loss'] >= host.ping_critical_packet_loss:
        return {
            'status': 'critical',
            'reason': f'High packet loss: {ping_data["packet_loss"]:.1f}%'
        }
    elif ping_data['packet_loss'] >= host.ping_warning_packet_loss:
        return {
            'status': 'warning',
            'reason': f'Elevated packet loss: {ping_data["packet_loss"]:.1f}%'
        }
    
    # Check latency thresholds
    if ping_data['latency'] is not None:
        if ping_data['latency'] >= host.ping_critical_latency:
            return {
                'status': 'critical',
                'reason': f'High latency: {ping_data["latency"]:.1f}ms'
            }
        elif ping_data['latency'] >= host.ping_warning_latency:
            return {
                'status': 'warning',
                'reason': f'Elevated latency: {ping_data["latency"]:.1f}ms'
            }
    
    return {
        'status': 'up',
        'reason': 'Host responding normally'
    }