"""
Management command to start the network monitoring system.

This command initializes the monitoring system, starts Celery workers,
and begins periodic monitoring tasks.
"""

import os
import sys
import time
import signal
import subprocess
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.db import connection
from monitoring.models import Host
from monitoring.tasks import health_check_task, get_monitoring_statistics


class Command(BaseCommand):
    help = 'Start the network monitoring system with Celery workers'
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.processes = []
        self.shutdown = False
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--workers',
            type=int,
            default=4,
            help='Number of Celery workers to start (default: 4)'
        )
        
        parser.add_argument(
            '--concurrency',
            type=int,
            default=2,
            help='Concurrency level per worker (default: 2)'
        )
        
        parser.add_argument(
            '--beat',
            action='store_true',
            help='Start Celery Beat scheduler'
        )
        
        parser.add_argument(
            '--flower',
            action='store_true',
            help='Start Flower monitoring interface'
        )
        
        parser.add_argument(
            '--log-level',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
            default='INFO',
            help='Log level for Celery workers'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be started without actually starting'
        )
    
    def handle(self, *args, **options):
        """Main command handler."""
        self.stdout.write(
            self.style.SUCCESS('🚀 Starting Network Monitoring System...')
        )
        
        # Validate system requirements
        if not self._check_system_requirements():
            raise CommandError('System requirements not met')
        
        # Show system status
        self._show_system_status()
        
        if options['dry_run']:
            self._show_dry_run(options)
            return
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        try:
            # Start Celery workers
            self._start_workers(options)
            
            # Start Celery Beat if requested
            if options['beat']:
                self._start_beat(options)
            
            # Start Flower if requested
            if options['flower']:
                self._start_flower(options)
            
            # Monitor processes
            self._monitor_processes()
            
        except KeyboardInterrupt:
            self.stdout.write('\n⚠️  Received interrupt signal')
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error starting monitoring system: {e}')
            )
        finally:
            self._cleanup()
    
    def _check_system_requirements(self):
        """Check if system requirements are met."""
        self.stdout.write('🔍 Checking system requirements...')
        
        # Check database connectivity
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            self.stdout.write('  ✅ Database connection: OK')
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Database connection: FAILED ({e})')
            )
            return False
        
        # Check Redis connectivity
        try:
            from django.core.cache import cache
            cache.set('health_check', 'ok', 30)
            if cache.get('health_check') == 'ok':
                self.stdout.write('  ✅ Redis connection: OK')
            else:
                raise Exception('Cache test failed')
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Redis connection: FAILED ({e})')
            )
            return False
        
        # Check if hosts exist
        host_count = Host.objects.count()
        enabled_hosts = Host.objects.filter(monitoring_enabled=True).count()
        
        self.stdout.write(f'  📊 Total hosts: {host_count}')
        self.stdout.write(f'  📊 Enabled hosts: {enabled_hosts}')
        
        if enabled_hosts == 0:
            self.stdout.write(
                self.style.WARNING('  ⚠️  No hosts enabled for monitoring')
            )
        
        return True
    
    def _show_system_status(self):
        """Show current system status."""
        self.stdout.write('\n📈 Current System Status:')
        
        try:
            stats = get_monitoring_statistics()
            
            self.stdout.write(f"  Hosts: {stats['hosts']['total']} total, {stats['hosts']['monitoring_enabled']} enabled")
            self.stdout.write(f"  Alerts: {stats['alerts']['active']} active, {stats['alerts']['acknowledged']} acknowledged")
            self.stdout.write(f"  Monitoring: Ping={stats['hosts']['ping_enabled']}, SNMP={stats['hosts']['snmp_enabled']}, Services={stats['hosts']['service_checks_enabled']}")
            
        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f'  ⚠️  Could not get system statistics: {e}')
            )
    
    def _show_dry_run(self, options):
        """Show what would be started in dry-run mode."""
        self.stdout.write('\n🔍 Dry Run - Commands that would be executed:')
        
        # Worker commands
        for i in range(options['workers']):
            queue_assignment = self._get_queue_for_worker(i, options['workers'])
            cmd = [
                'celery', '-A', 'nms', 'worker',
                '--loglevel', options['log_level'],
                '--concurrency', str(options['concurrency']),
                '--queues', queue_assignment,
                '--hostname', f'worker{i+1}@%h'
            ]
            self.stdout.write(f'  Worker {i+1}: {" ".join(cmd)}')
        
        # Beat command
        if options['beat']:
            cmd = ['celery', '-A', 'nms', 'beat', '--loglevel', options['log_level']]
            self.stdout.write(f'  Beat: {" ".join(cmd)}')
        
        # Flower command
        if options['flower']:
            cmd = ['celery', '-A', 'nms', 'flower', '--port=5555']
            self.stdout.write(f'  Flower: {" ".join(cmd)}')
    
    def _start_workers(self, options):
        """Start Celery workers."""
        self.stdout.write(f'\n🔧 Starting {options["workers"]} Celery workers...')
        
        for i in range(options['workers']):
            queue_assignment = self._get_queue_for_worker(i, options['workers'])
            
            cmd = [
                'celery', '-A', 'nms', 'worker',
                '--loglevel', options['log_level'],
                '--concurrency', str(options['concurrency']),
                '--queues', queue_assignment,
                '--hostname', f'worker{i+1}@%h'
            ]
            
            self.stdout.write(f'  Starting worker {i+1} (queues: {queue_assignment})...')
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=os.environ.copy()
            )
            
            self.processes.append({
                'name': f'worker{i+1}',
                'process': process,
                'cmd': cmd
            })
            
            # Give worker a moment to start
            time.sleep(1)
        
        self.stdout.write('  ✅ All workers started')
    
    def _start_beat(self, options):
        """Start Celery Beat scheduler."""
        self.stdout.write('\n⏰ Starting Celery Beat scheduler...')
        
        cmd = [
            'celery', '-A', 'nms', 'beat',
            '--loglevel', options['log_level'],
            '--scheduler', 'django_celery_beat.schedulers:DatabaseScheduler'
        ]
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ.copy()
        )
        
        self.processes.append({
            'name': 'beat',
            'process': process,
            'cmd': cmd
        })
        
        self.stdout.write('  ✅ Beat scheduler started')
    
    def _start_flower(self, options):
        """Start Flower monitoring interface."""
        self.stdout.write('\n🌸 Starting Flower monitoring interface...')
        
        cmd = [
            'celery', '-A', 'nms', 'flower',
            '--port=5555',
            '--url_prefix=flower'
        ]
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ.copy()
        )
        
        self.processes.append({
            'name': 'flower',
            'process': process,
            'cmd': cmd
        })
        
        self.stdout.write('  ✅ Flower started at http://localhost:5555/flower')
    
    def _get_queue_for_worker(self, worker_index, total_workers):
        """Assign queues to workers for load balancing."""
        # Define queue priorities and assignments
        queue_assignments = [
            'monitoring,default',  # High priority monitoring tasks
            'monitoring,alerts',   # Monitoring and alert processing
            'scheduler,maintenance',  # Scheduling and maintenance
            'alerts,default'       # Alert processing and general tasks
        ]
        
        # Cycle through assignments
        return queue_assignments[worker_index % len(queue_assignments)]
    
    def _monitor_processes(self):
        """Monitor running processes and handle failures."""
        self.stdout.write('\n🔄 Monitoring system started. Press Ctrl+C to stop.')
        self.stdout.write('📊 Process status:')
        
        for proc_info in self.processes:
            self.stdout.write(f'  ✅ {proc_info["name"]}: Running (PID: {proc_info["process"].pid})')
        
        # Monitor loop
        while not self.shutdown:
            time.sleep(5)
            
            # Check process health
            failed_processes = []
            for proc_info in self.processes:
                if proc_info['process'].poll() is not None:
                    failed_processes.append(proc_info)
            
            # Handle failed processes
            if failed_processes:
                for proc_info in failed_processes:
                    self.stdout.write(
                        self.style.ERROR(f'❌ Process {proc_info["name"]} has stopped')
                    )
                    
                    # Get error output
                    try:
                        _, stderr = proc_info['process'].communicate(timeout=1)
                        if stderr:
                            self.stdout.write(f'   Error: {stderr.decode().strip()}')
                    except:
                        pass
                
                # Remove failed processes from monitoring
                self.processes = [p for p in self.processes if p not in failed_processes]
                
                if not self.processes:
                    self.stdout.write(
                        self.style.ERROR('❌ All processes have stopped. Exiting.')
                    )
                    break
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.stdout.write(f'\n⚠️  Received signal {signum}. Shutting down gracefully...')
        self.shutdown = True
    
    def _cleanup(self):
        """Clean up processes on shutdown."""
        self.stdout.write('\n🧹 Cleaning up processes...')
        
        for proc_info in self.processes:
            try:
                self.stdout.write(f'  Stopping {proc_info["name"]}...')
                proc_info['process'].terminate()
                
                # Wait for graceful shutdown
                try:
                    proc_info['process'].wait(timeout=10)
                    self.stdout.write(f'  ✅ {proc_info["name"]} stopped gracefully')
                except subprocess.TimeoutExpired:
                    self.stdout.write(f'  ⚠️  Force killing {proc_info["name"]}...')
                    proc_info['process'].kill()
                    proc_info['process'].wait()
                    self.stdout.write(f'  ✅ {proc_info["name"]} force stopped')
                    
            except Exception as e:
                self.stdout.write(
                    self.style.WARNING(f'  ⚠️  Error stopping {proc_info["name"]}: {e}')
                )
        
        self.stdout.write(
            self.style.SUCCESS('\n✅ Network Monitoring System stopped successfully')
        )