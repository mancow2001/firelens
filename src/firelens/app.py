#!/usr/bin/env python3
"""
FireLens Monitor - Main Application
Enhanced modular version with persistent storage and multi-firewall support
"""

import gc
import logging
import signal
import sys
import time
from typing import Optional

import psutil

from .collectors import MultiFirewallCollector

# Import our modules
from .config import ConfigManager
from .database import MetricsDatabase
from .web_dashboard import WebDashboard

LOG = logging.getLogger("FireLens.main")


class GracefulKiller:
    """Handle graceful shutdown on SIGINT/SIGTERM"""

    def __init__(self):
        self.kill_now = False
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, *_):
        self.kill_now = True


class FireLensApp:
    """Main application class"""

    def __init__(self, config_file: str = "config.yaml"):
        self.config_manager = ConfigManager(config_file)
        self.database: Optional[MetricsDatabase] = None
        self.collector_manager: Optional[MultiFirewallCollector] = None
        self.web_dashboard: Optional[WebDashboard] = None
        self.killer = GracefulKiller()

        # Setup logging
        self._setup_logging()

        # Validate configuration
        self._validate_configuration()

        # Initialize components
        self._initialize_components()

    def _setup_logging(self):
        """Configure logging"""
        log_level = getattr(
            logging, self.config_manager.global_config.log_level.upper(), logging.INFO
        )

        logging.basicConfig(
            level=log_level,
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        LOG.info(f"Logging configured at {self.config_manager.global_config.log_level} level")

    def _validate_configuration(self):
        """Validate configuration and report errors"""
        errors = self.config_manager.validate_config()
        if errors:
            LOG.error("Configuration validation failed:")
            for error in errors:
                LOG.error(f"  - {error}")
            sys.exit(1)

        enabled_firewalls = self.config_manager.get_enabled_firewalls()
        if not enabled_firewalls:
            LOG.warning("No enabled firewalls found in configuration")
        else:
            LOG.info(f"Configuration valid - {len(enabled_firewalls)} enabled firewalls")

    def _initialize_components(self):
        """Initialize database, collectors, and web dashboard"""
        # Initialize database
        db_path = self.config_manager.global_config.database_path
        LOG.info(f"Initializing database: {db_path}")
        self.database = MetricsDatabase(db_path)

        # Initialize collector manager - ALWAYS create it for hot-reload support
        enabled_firewalls = self.config_manager.get_enabled_firewalls()
        if enabled_firewalls:
            LOG.info(f"Initializing collectors for {len(enabled_firewalls)} firewalls")
        else:
            LOG.info("Initializing collector manager (no firewalls yet - awaiting hot-add)")

        self.collector_manager = MultiFirewallCollector(
            enabled_firewalls if enabled_firewalls else {}, self.database
        )

        # Initialize web dashboard
        if self.config_manager.global_config.web_dashboard:
            LOG.info("Initializing web dashboard")
            self.web_dashboard = WebDashboard(
                self.database, self.config_manager, self.collector_manager
            )

    def start(self):
        """Start the monitoring application"""
        LOG.info("🚀 Starting FireLens Monitor")

        enabled_firewalls = self.config_manager.get_enabled_firewalls()

        # Start web dashboard if enabled
        if self.web_dashboard:
            ssl_config = self.config_manager.global_config.web_ssl
            ssl_cert = None
            ssl_key = None
            port = self.config_manager.global_config.web_port
            protocol = "http"

            # Handle SSL/TLS if enabled
            if ssl_config and ssl_config.enabled:
                try:
                    from .ssl_manager import SSLManager

                    ssl_manager = SSLManager(self.config_manager.global_config.certs_directory)

                    # Auto-generate self-signed cert if needed
                    if ssl_config.auto_generate and not ssl_manager.has_valid_certificate():
                        LOG.info("Generating self-signed SSL certificate...")
                        ssl_manager.generate_self_signed_cert(valid_days=365)

                    if ssl_manager.has_valid_certificate():
                        ssl_cert = str(ssl_manager.web_cert_path)
                        ssl_key = str(ssl_manager.web_key_path)
                        port = ssl_config.https_port
                        protocol = "https"

                        cert_info = ssl_manager.get_certificate_info()
                        if cert_info:
                            expires = cert_info.get("not_after", "unknown")
                            LOG.info(f"SSL enabled - Certificate expires: {expires}")
                            if cert_info.get("expiring_soon"):
                                days = cert_info.get("days_until_expiry", 0)
                                LOG.warning(f"SSL certificate expires in {days} days!")
                    else:
                        LOG.warning(
                            "SSL enabled but no valid certificate found - falling back to HTTP"
                        )
                        port = (
                            ssl_config.http_port
                            if ssl_config.http_port
                            else self.config_manager.global_config.web_port
                        )
                except ImportError:
                    LOG.warning("SSL manager not available - falling back to HTTP")
                except Exception as e:
                    LOG.error(f"Error setting up SSL: {e} - falling back to HTTP")

            self.web_dashboard.start_server(port=port, ssl_certfile=ssl_cert, ssl_keyfile=ssl_key)
            LOG.info(f"Web dashboard available at {protocol}://localhost:{port}")

            # Start HTTP redirect server if SSL is enabled and redirect is configured
            if ssl_config and ssl_config.enabled and ssl_config.redirect_http_to_https and ssl_cert:
                http_port = ssl_config.http_port or 8080
                https_port = ssl_config.https_port or 8443
                self.web_dashboard.start_http_redirect_server(
                    http_port=http_port, https_port=https_port
                )
                LOG.info(
                    f"HTTP redirect: http://localhost:{http_port} -> https://localhost:{https_port}"
                )

        # Start data collection - always start collector manager for hot-reload support
        if self.collector_manager:
            self.collector_manager.start_collection()
            if enabled_firewalls:
                LOG.info(f"📡 Started monitoring {len(enabled_firewalls)} firewalls:")
                for name, config in enabled_firewalls.items():
                    LOG.info(f"  - {name}: {config.host} (interval: {config.poll_interval}s)")
            else:
                LOG.warning("No enabled firewalls to monitor (add via admin panel for hot-reload)")

        # Database cleanup on startup
        if self.database:
            cleanup_days = 30  # Keep 30 days of data by default
            deleted = self.database.cleanup_old_metrics(cleanup_days)
            if deleted > 0:
                LOG.info(f"🧹 Cleaned up {deleted} old metrics (older than {cleanup_days} days)")

        LOG.info("✅ All services started successfully")

        # Main monitoring loop
        self._run_monitoring_loop()

    def stop(self):
        """Stop all services gracefully"""
        LOG.info("🛑 Stopping FireLens Monitor...")

        # Stop data collection
        if self.collector_manager:
            self.collector_manager.stop_collection()

        LOG.info("✅ Shutdown complete")

    def _run_monitoring_loop(self):
        """Main monitoring loop with periodic garbage collection and memory monitoring"""
        try:
            # Print status periodically
            status_interval = 300  # 5 minutes
            gc_interval = 300  # Run GC every 5 minutes
            memory_check_interval = 60  # Check memory every minute
            last_status_time = 0
            last_gc_time = 0
            last_memory_check = 0

            # Get process for memory monitoring
            process = psutil.Process()

            while not self.killer.kill_now:
                current_time = time.time()

                # Run garbage collection periodically to prevent memory leaks
                if current_time - last_gc_time >= gc_interval:
                    collected = gc.collect()
                    LOG.debug(f"🧹 Garbage collection: collected {collected} objects")
                    last_gc_time = current_time

                # Monitor memory usage
                if current_time - last_memory_check >= memory_check_interval:
                    try:
                        mem_info = process.memory_info()
                        mem_mb = mem_info.rss / (1024 * 1024)  # Convert to MB
                        mem_percent = process.memory_percent()

                        LOG.debug(f"💾 Memory: {mem_mb:.1f} MB ({mem_percent:.1f}%)")

                        # Warn if memory usage is high
                        if mem_percent > 80:
                            LOG.warning(
                                f"⚠️ High memory usage: {mem_mb:.1f} MB ({mem_percent:.1f}%)"
                            )
                        elif mem_mb > 500:  # Warn if over 500MB
                            LOG.warning(f"⚠️ Memory usage above 500MB: {mem_mb:.1f} MB")

                        last_memory_check = current_time
                    except Exception as e:
                        LOG.debug(f"Failed to get memory info: {e}")

                # Print status every 5 minutes
                if current_time - last_status_time >= status_interval:
                    self._print_status()
                    last_status_time = current_time

                # Sleep for 1 second
                time.sleep(1)

        except KeyboardInterrupt:
            LOG.info("Received interrupt signal")
        finally:
            self.stop()

    def _print_status(self):
        """Print current monitoring status"""
        if not self.collector_manager:
            return

        status = self.collector_manager.get_collector_status()
        active_count = sum(1 for s in status.values() if s["thread_alive"])

        LOG.info(f"📊 Status: {active_count}/{len(status)} collectors active")

        for name, collector_status in status.items():
            if collector_status["authenticated"] and collector_status["thread_alive"]:
                last_poll = collector_status["last_poll"]
                poll_count = collector_status["poll_count"]
                if last_poll:
                    LOG.info(f"  ✅ {name}: {poll_count} polls, last: {last_poll}")
                else:
                    LOG.info(f"  🟡 {name}: {poll_count} polls, starting up...")
            else:
                LOG.warning(f"  ❌ {name}: inactive or authentication failed")


# CLI entry point is now in cli.py
# This module exports FireLensApp for use by the CLI
