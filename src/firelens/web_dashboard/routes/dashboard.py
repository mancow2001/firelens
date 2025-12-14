"""
FireLens Monitor - Dashboard Routes
Public routes for viewing firewalls and API endpoints for metrics
"""

import gc
import html
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

LOG = logging.getLogger("FireLens.web")

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def enhanced_dashboard(request: Request):
    """Enhanced main dashboard showing all firewalls with interface data"""
    try:
        # Access shared state from app
        config_manager = request.app.state.config_manager
        database = request.app.state.database
        cache = request.app.state.cache
        templates = request.app.state.templates

        # AUTO-SYNC: Always sync all firewalls from config to database
        # This ensures new firewalls are registered (both enabled and disabled)
        # IMPORTANT: This must run BEFORE cache check to catch new firewalls
        enabled_fw_names = config_manager.get_enabled_firewalls()
        all_config_fw_names = list(config_manager.firewalls.keys())
        db_firewalls = database.get_all_firewalls()
        db_firewall_names = {fw["name"] for fw in db_firewalls}

        # Register any firewalls from config that aren't in database yet
        # (both enabled and disabled firewalls should appear on dashboard)
        newly_registered = []
        for fw_name in all_config_fw_names:
            if fw_name not in db_firewall_names:
                # Get the actual firewall config object
                fw_config = config_manager.get_firewall(fw_name)
                if fw_config:
                    database.register_firewall(fw_config.name, fw_config.host)
                    status = "enabled" if fw_name in enabled_fw_names else "disabled"
                    LOG.info(f"Auto-registered: {fw_config.name} at {fw_config.host} ({status})")
                    newly_registered.append(fw_name)
                else:
                    LOG.warning(f"Could not get config for firewall: {fw_name}")

        # Define cache key before conditional
        cache_key = "dashboard_overview"

        # Refresh database list if we registered any new firewalls
        if newly_registered:
            LOG.info(
                f"Registered {len(newly_registered)} new firewall(s): {', '.join(newly_registered)}"
            )
            db_firewalls = database.get_all_firewalls()
            # Don't use cache if we just registered new firewalls
            LOG.debug(f"Bypassing cache - just registered {len(newly_registered)} new firewall(s)")
        else:
            # Check cache only if no new registrations
            cached_data = cache.get(cache_key)
            if cached_data is not None:
                LOG.debug("Serving dashboard from cache (no new firewalls detected)")
                return cached_data

        # Get enhanced database stats
        database_stats = database.get_database_stats()

        # Prepare enhanced firewall data for template
        firewalls = []
        for fw_data in db_firewalls:
            name = fw_data["name"]

            # Get latest metrics (common metrics only - CPU is in vendor tables)
            latest_metrics_list = database.get_latest_metrics(name, 1)
            latest_metrics = latest_metrics_list[0] if latest_metrics_list else None

            # Get vendor type from config
            firewall_config = config_manager.get_firewall(name)
            vendor_type = firewall_config.type if firewall_config else "palo_alto"

            # Get vendor-specific metrics (CPU, etc.)
            vendor_metrics = None
            if vendor_type == "fortinet":
                vendor_metrics_list = database.get_fortinet_metrics(name, limit=1)
                vendor_metrics = vendor_metrics_list[0] if vendor_metrics_list else None
            elif vendor_type == "palo_alto":
                vendor_metrics_list = database.get_palo_alto_metrics(name, limit=1)
                vendor_metrics = vendor_metrics_list[0] if vendor_metrics_list else None

            # Get interface summary using enhanced configuration
            interface_summary = None
            if hasattr(database, "get_interface_metrics"):
                try:
                    # Get available interfaces from database
                    available_interfaces = database.get_available_interfaces(name)

                    # Use firewall_config to determine which interfaces should be monitored
                    monitored_interfaces = []

                    if firewall_config and hasattr(firewall_config, "should_monitor_interface"):
                        # Use config logic to filter interfaces
                        monitored_interfaces = [
                            iface
                            for iface in available_interfaces
                            if firewall_config.should_monitor_interface(iface)
                        ]
                    else:
                        # Fallback to all available interfaces
                        monitored_interfaces = available_interfaces

                    total_rx = 0
                    total_tx = 0

                    # Use batch query to get latest metrics for all interfaces
                    if monitored_interfaces:
                        latest_interface_metrics = database.get_latest_interface_summary(
                            name, monitored_interfaces
                        )
                        for interface_name, metrics in latest_interface_metrics.items():
                            total_rx += metrics.get("rx_mbps", 0) or 0
                            total_tx += metrics.get("tx_mbps", 0) or 0

                    if total_rx > 0 or total_tx > 0 or len(monitored_interfaces) > 0:
                        interface_summary = {
                            "total_rx": total_rx,
                            "total_tx": total_tx,
                            "interface_count": len(monitored_interfaces),
                            "monitored_interfaces": monitored_interfaces[:3],  # Show first 3
                            "total_interfaces": len(available_interfaces),
                        }
                except Exception as e:
                    LOG.debug(f"Could not get enhanced interface summary for {name}: {e}")

            # Get session summary
            session_summary = None
            if hasattr(database, "get_session_statistics"):
                try:
                    session_stats = database.get_session_statistics(name, limit=1)
                    if session_stats:
                        latest_session = session_stats[0]
                        session_summary = {
                            "active_sessions": latest_session.get("active_sessions", 0),
                            "max_sessions": latest_session.get("max_sessions", 0),
                            "session_utilization": (
                                latest_session.get("active_sessions", 0)
                                / max(latest_session.get("max_sessions", 1), 1)
                            )
                            * 100,
                        }
                except Exception as e:
                    LOG.debug(f"Could not get session summary for {name}: {e}")

            # Determine status
            status_class = "status-unknown"
            last_update = "Never"

            if latest_metrics:
                # Handle timestamp parsing safely (Python 3.6 compatible)
                timestamp_str = latest_metrics["timestamp"]
                if isinstance(timestamp_str, str):
                    # Use database's Python 3.6-compatible parser
                    from ...database import parse_iso_datetime

                    last_metric_time = parse_iso_datetime(timestamp_str)
                else:
                    last_metric_time = timestamp_str

                if last_metric_time.tzinfo is None:
                    last_metric_time = last_metric_time.replace(tzinfo=timezone.utc)

                time_diff = datetime.now(timezone.utc) - last_metric_time

                if time_diff.total_seconds() < 300:  # 5 minutes
                    status_class = "status-online"
                else:
                    status_class = "status-offline"

                last_update = last_metric_time.strftime("%Y-%m-%d %H:%M:%S")

            # CPU status classes - now from vendor-specific tables
            mgmt_cpu_class = "cpu-low"
            dp_cpu_class = "cpu-low"
            cpu_class = "cpu-low"  # For Fortinet single CPU

            if vendor_metrics:
                if vendor_type == "palo_alto":
                    mgmt_cpu = vendor_metrics.get("mgmt_cpu", 0) or 0
                    dp_cpu = vendor_metrics.get("data_plane_cpu_mean", 0) or 0

                    if mgmt_cpu > 80:
                        mgmt_cpu_class = "cpu-high"
                    elif mgmt_cpu > 60:
                        mgmt_cpu_class = "cpu-medium"

                    if dp_cpu > 80:
                        dp_cpu_class = "cpu-high"
                    elif dp_cpu > 60:
                        dp_cpu_class = "cpu-medium"
                elif vendor_type == "fortinet":
                    cpu_usage = vendor_metrics.get("cpu_usage", 0) or 0
                    if cpu_usage > 80:
                        cpu_class = "cpu-high"
                    elif cpu_usage > 60:
                        cpu_class = "cpu-medium"

            # Check if firewall is enabled in config
            firewall_enabled = name in enabled_fw_names

            # Override status for disabled firewalls
            if not firewall_enabled:
                status_class = "status-disabled"

            firewalls.append(
                {
                    "name": name,
                    "host": fw_data["host"],
                    "model": fw_data.get("model", ""),
                    "family": fw_data.get("family", ""),
                    "sw_version": fw_data.get("sw_version", ""),
                    "status_class": status_class,
                    "latest_metrics": latest_metrics,
                    "vendor_metrics": vendor_metrics,
                    "vendor_type": vendor_type,
                    "interface_summary": interface_summary,
                    "session_summary": session_summary,
                    "last_update": last_update,
                    "mgmt_cpu_class": mgmt_cpu_class,
                    "dp_cpu_class": dp_cpu_class,
                    "cpu_class": cpu_class,
                    "enabled": firewall_enabled,
                }
            )

        # Calculate uptime
        uptime_hours = 0
        if database_stats.get("earliest_metric"):
            earliest_str = database_stats["earliest_metric"]
            if isinstance(earliest_str, str):
                # Use database's Python 3.6-compatible parser
                from ...database import parse_iso_datetime

                earliest = parse_iso_datetime(earliest_str)
            else:
                earliest = earliest_str

            if earliest.tzinfo is None:
                earliest = earliest.replace(tzinfo=timezone.utc)

            uptime_hours = int((datetime.now(timezone.utc) - earliest).total_seconds() / 3600)

        response = templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "firewalls": firewalls,
                "database_stats": database_stats,
                "uptime_hours": uptime_hours,
            },
        )

        # Cache the response
        cache.set(cache_key, response)
        LOG.debug("Cached dashboard overview")

        return response

    except Exception as e:
        LOG.error(f"Enhanced dashboard error: {e}")
        import traceback

        traceback.print_exc()
        return HTMLResponse(f"<h1>Error loading enhanced dashboard</h1><p>{e}</p>", status_code=500)


@router.get("/firewall/{firewall_name}", response_class=HTMLResponse)
async def enhanced_firewall_detail(request: Request, firewall_name: str):
    """Enhanced detailed view for a specific firewall"""
    try:
        config_manager = request.app.state.config_manager
        database = request.app.state.database
        templates = request.app.state.templates

        LOG.info(f"Firewall detail page requested for: '{firewall_name}'")

        # Get firewall config - try exact match first
        firewall_config = config_manager.get_firewall(firewall_name)

        if not firewall_config:
            # Log all available firewalls for debugging
            all_firewalls = config_manager.list_firewalls()
            LOG.warning(f"Firewall '{firewall_name}' not found in config")
            LOG.warning(f"Available firewalls in config: {all_firewalls}")

            # Try case-insensitive match
            firewall_name_lower = firewall_name.lower()
            for fw_name in all_firewalls:
                if fw_name.lower() == firewall_name_lower:
                    LOG.info(f"Found case-insensitive match: '{fw_name}' for '{firewall_name}'")
                    firewall_config = config_manager.get_firewall(fw_name)
                    firewall_name = fw_name  # Use the correct case
                    break

        if not firewall_config:
            # Check if firewall exists in database but not in config
            db_firewalls = database.get_all_firewalls()
            db_fw_names = [fw["name"] for fw in db_firewalls]
            LOG.warning(f"Firewalls in database: {db_fw_names}")

            # Provide helpful error message with XSS protection
            all_firewalls = config_manager.list_firewalls()
            safe_firewall_name = html.escape(firewall_name)
            # Build firewall list with proper escaping for both URLs and display
            if all_firewalls:
                fw_list_html = "".join(
                    f'<li><a href="/firewall/{urllib.parse.quote(fw, safe="")}">'
                    f"{html.escape(fw)}</a></li>"
                    for fw in all_firewalls
                )
            else:
                fw_list_html = "<li><em>No firewalls configured</em></li>"

            error_html = f"""
            <html>
            <head><title>Firewall Not Found</title></head>
            <body style="font-family: Arial; padding: 40px; max-width: 800px; margin: 0 auto;">
                <h1 style="color: #e74c3c;">Firewall Not Found</h1>
                <p><strong>Requested firewall:</strong> <code>{safe_firewall_name}</code></p>
                <h2>Available firewalls in configuration:</h2>
                <ul>
                    {fw_list_html}
                </ul>
                <h2>Troubleshooting:</h2>
                <ul>
                    <li>Check that the firewall name matches exactly (case-sensitive)</li>
                    <li>Verify the firewall is defined in your config.yaml</li>
                    <li>Ensure the firewall has <code>enabled: true</code> in the config</li>
                    <li>Restart after config changes: <code>systemctl restart FireLens</code></li>
                </ul>
                <p><a href="/">&#8592; Back to Dashboard</a></p>
            </body>
            </html>
            """
            return HTMLResponse(error_html, status_code=404)

        # Check if firewall is disabled
        if not firewall_config.enabled:
            LOG.warning(f"Firewall '{firewall_name}' is disabled in configuration")

        LOG.info(f"Loading detail page for firewall: '{firewall_name}' at {firewall_config.host}")

        # Get firewall hardware info from database
        db_firewalls = database.get_all_firewalls()
        firewall_hw_info = next((fw for fw in db_firewalls if fw["name"] == firewall_name), {})

        # Note: Default time range (last 6 hours) is calculated client-side in JavaScript
        # to use the user's local timezone instead of server time
        return templates.TemplateResponse(
            "firewall_detail.html",
            {
                "request": request,
                "firewall_name": firewall_name,
                "firewall_host": firewall_config.host,
                "firewall_model": firewall_hw_info.get("model", ""),
                "firewall_family": firewall_hw_info.get("family", ""),
                "firewall_sw_version": firewall_hw_info.get("sw_version", ""),
                "vendor_type": getattr(firewall_config, "type", "palo_alto"),
            },
        )

    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        LOG.error(f"Enhanced firewall detail error: {e}")
        import traceback

        traceback.print_exc()
        return HTMLResponse(
            f"<h1>Error loading enhanced firewall details</h1><p>{e}</p>", status_code=500
        )


@router.get("/api/firewall/{firewall_name}/metrics")
async def get_firewall_metrics(
    request: Request,
    firewall_name: str,
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    limit: Optional[int] = Query(None),
    user_timezone: Optional[str] = Query(None),
):
    """API endpoint to get metrics for a specific firewall (existing)"""
    try:
        database = request.app.state.database

        start_dt = None
        end_dt = None

        if start_time:
            try:
                from ...database import parse_iso_datetime

                start_dt = parse_iso_datetime(start_time)
            except Exception as e:
                LOG.warning(f"Failed to parse start_time '{start_time}': {e}")

        if end_time:
            try:
                from ...database import parse_iso_datetime

                end_dt = parse_iso_datetime(end_time)
            except Exception as e:
                LOG.warning(f"Failed to parse end_time '{end_time}': {e}")

        metrics = database.get_metrics(firewall_name, start_dt, end_dt, limit)
        return JSONResponse(metrics)

    except Exception as e:
        LOG.error(f"API metrics error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/firewall/{firewall_name}/interfaces")
async def get_firewall_interfaces(
    request: Request,
    firewall_name: str,
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    limit: Optional[int] = Query(None),
    user_timezone: Optional[str] = Query(None),
):
    """NEW: API endpoint to get interface metrics for a specific firewall"""
    try:
        database = request.app.state.database

        if not hasattr(database, "get_interface_metrics"):
            raise HTTPException(status_code=501, detail="Interface metrics not supported")

        start_dt = None
        end_dt = None

        if start_time:
            try:
                from ...database import parse_iso_datetime

                start_dt = parse_iso_datetime(start_time)
            except Exception as e:
                LOG.warning(f"Failed to parse start_time '{start_time}': {e}")

        if end_time:
            try:
                from ...database import parse_iso_datetime

                end_dt = parse_iso_datetime(end_time)
            except Exception as e:
                LOG.warning(f"Failed to parse end_time '{end_time}': {e}")

        # Get all available interfaces for this firewall
        available_interfaces = database.get_available_interfaces(firewall_name)

        # FIXED: Use batch query to get all interfaces in single query (fixes N+1 problem)
        interface_data = database.get_interface_metrics_batch(
            firewall_name, available_interfaces, start_dt, end_dt, limit
        )

        iface_count = len(interface_data)
        LOG.info(f"Interface API - Found {iface_count} interfaces for {firewall_name}")
        LOG.debug(f"Interface API - Available interfaces: {available_interfaces}")
        return JSONResponse(interface_data)

    except Exception as e:
        LOG.error(f"API interface metrics error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/firewall/{firewall_name}/interface-config")
async def get_firewall_interface_config(request: Request, firewall_name: str):
    """NEW: API endpoint to get interface configuration for a firewall"""
    try:
        config_manager = request.app.state.config_manager
        database = request.app.state.database

        # Get firewall config from config manager
        firewall_config = config_manager.get_firewall(firewall_name)
        if not firewall_config:
            raise HTTPException(status_code=404, detail="Firewall not found")

        # Get available interfaces from database
        available_interfaces = []
        if hasattr(database, "get_available_interfaces"):
            available_interfaces = database.get_available_interfaces(firewall_name)

        # Get configured interfaces
        configured_interfaces = []
        if hasattr(firewall_config, "interface_configs") and firewall_config.interface_configs:
            configured_interfaces = [
                {
                    "name": ic.name,
                    "display_name": ic.display_name,
                    "enabled": ic.enabled,
                    "description": ic.description,
                }
                for ic in firewall_config.interface_configs
            ]

        # Get simple monitor list
        monitor_interfaces = []
        if hasattr(firewall_config, "monitor_interfaces") and firewall_config.monitor_interfaces:
            monitor_interfaces = firewall_config.monitor_interfaces

        # Get enabled interfaces using firewall config logic
        enabled_interfaces = []
        if hasattr(firewall_config, "get_enabled_interfaces"):
            enabled_interfaces = firewall_config.get_enabled_interfaces()

        config_info = {
            "firewall_name": firewall_name,
            "interface_monitoring": getattr(firewall_config, "interface_monitoring", False),
            "auto_discover_interfaces": getattr(firewall_config, "auto_discover_interfaces", False),
            "configured_interfaces": configured_interfaces,
            "monitor_interfaces": monitor_interfaces,
            "enabled_interfaces": enabled_interfaces,
            "available_interfaces": available_interfaces,
            "exclude_interfaces": getattr(firewall_config, "exclude_interfaces", []),
        }

        en_count = len(enabled_interfaces)
        av_count = len(available_interfaces)
        LOG.debug(f"Interface config for {firewall_name}: {en_count} enabled, {av_count} available")
        return JSONResponse(config_info)

    except Exception as e:
        LOG.error(f"API interface config error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/firewall/{firewall_name}/sessions")
async def get_firewall_sessions(
    request: Request,
    firewall_name: str,
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    limit: Optional[int] = Query(None),
    user_timezone: Optional[str] = Query(None),
):
    """NEW: API endpoint to get session statistics for a specific firewall"""
    try:
        database = request.app.state.database

        if not hasattr(database, "get_session_statistics"):
            raise HTTPException(status_code=501, detail="Session statistics not supported")

        start_dt = None
        end_dt = None

        if start_time:
            try:
                from ...database import parse_iso_datetime

                start_dt = parse_iso_datetime(start_time)
            except Exception as e:
                LOG.warning(f"Failed to parse start_time '{start_time}': {e}")

        if end_time:
            try:
                from ...database import parse_iso_datetime

                end_dt = parse_iso_datetime(end_time)
            except Exception as e:
                LOG.warning(f"Failed to parse end_time '{end_time}': {e}")

        session_stats = database.get_session_statistics(firewall_name, start_dt, end_dt, limit)

        LOG.info(f"Session API - Found {len(session_stats)} session records for {firewall_name}")
        return JSONResponse(session_stats)

    except Exception as e:
        LOG.error(f"API session statistics error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/firewall/{firewall_name}/vendor-metrics")
async def get_firewall_vendor_metrics(
    request: Request,
    firewall_name: str,
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    limit: Optional[int] = Query(None),
    user_timezone: Optional[str] = Query(None),
):
    """API endpoint to get vendor-specific metrics (Fortinet, Palo Alto, etc.)"""
    try:
        database = request.app.state.database
        config_manager = request.app.state.config_manager

        # Determine vendor type from config
        vendor_type = None
        for name, fw_config in config_manager.firewalls.items():
            if name.upper() == firewall_name.upper():
                vendor_type = getattr(fw_config, "type", "palo_alto")
                break

        if not vendor_type:
            raise HTTPException(status_code=404, detail=f"Firewall {firewall_name} not found")

        start_dt = None
        end_dt = None

        if start_time:
            try:
                from ...database import parse_iso_datetime

                start_dt = parse_iso_datetime(start_time)
            except Exception as e:
                LOG.warning(f"Failed to parse start_time '{start_time}': {e}")

        if end_time:
            try:
                from ...database import parse_iso_datetime

                end_dt = parse_iso_datetime(end_time)
            except Exception as e:
                LOG.warning(f"Failed to parse end_time '{end_time}': {e}")

        # Get vendor-specific metrics based on vendor type
        metrics = []
        if vendor_type == "fortinet":
            if hasattr(database, "get_fortinet_metrics"):
                metrics = database.get_fortinet_metrics(firewall_name, start_dt, end_dt, limit)
        elif vendor_type == "palo_alto":
            if hasattr(database, "get_palo_alto_metrics"):
                metrics = database.get_palo_alto_metrics(firewall_name, start_dt, end_dt, limit)
        # Add other vendors as needed

        LOG.info(
            f"Vendor metrics API - Found {len(metrics)} {vendor_type} records for {firewall_name}"
        )
        return JSONResponse({"vendor_type": vendor_type, "metrics": metrics})

    except HTTPException:
        raise
    except Exception as e:
        LOG.error(f"API vendor metrics error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/firewalls")
async def get_all_firewalls(request: Request):
    """API endpoint to get all firewalls (existing)"""
    try:
        database = request.app.state.database
        firewalls = database.get_all_firewalls()
        return JSONResponse(firewalls)
    except Exception as e:
        LOG.error(f"API firewalls error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/status")
async def get_enhanced_system_status(request: Request):
    """Enhanced API endpoint to get system status"""
    try:
        database = request.app.state.database
        config_manager = request.app.state.config_manager
        collector_manager = request.app.state.collector_manager

        status = {
            "database_stats": database.get_database_stats(),
            "config": {
                "firewalls": len(config_manager.firewalls),
                "enabled_firewalls": len(config_manager.get_enabled_firewalls()),
            },
            "enhanced_monitoring": True,
        }

        if collector_manager:
            status["collectors"] = collector_manager.get_collector_status()

        return JSONResponse(status)
    except Exception as e:
        LOG.error(f"API enhanced status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/health")
async def get_health_check(request: Request):
    """Health check endpoint with memory, queue, and database metrics"""
    try:
        import psutil

        database = request.app.state.database
        cache = request.app.state.cache
        collector_manager = request.app.state.collector_manager

        # Get process info
        process = psutil.Process()
        mem_info = process.memory_info()
        mem_mb = mem_info.rss / (1024 * 1024)
        mem_percent = process.memory_percent()

        # Get queue size if available
        queue_size = 0
        queue_full_warnings = 0
        if collector_manager and hasattr(collector_manager, "metrics_queue"):
            queue_size = collector_manager.metrics_queue.qsize()
            queue_full_warnings = getattr(collector_manager, "queue_full_warnings", 0)

        # Get database connection pool info
        pool_size = 0
        if hasattr(database, "_connection_pool"):
            pool_size = database._connection_pool.qsize()

        # Get cache stats
        cache_size = len(cache.cache) if cache else 0

        # Determine health status
        health_status = "healthy"
        issues = []

        if mem_percent > 80:
            health_status = "warning"
            issues.append(f"High memory usage: {mem_percent:.1f}%")

        if queue_size > 800:  # 80% of max queue size (1000)
            health_status = "warning"
            issues.append(f"Queue nearly full: {queue_size}/1000")

        if queue_full_warnings > 100:
            health_status = "critical"
            issues.append(f"Too many queue drops: {queue_full_warnings}")

        health_data = {
            "status": health_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "memory": {
                "rss_mb": round(mem_mb, 1),
                "percent": round(mem_percent, 1),
            },
            "queue": {"size": queue_size, "max_size": 1000, "drops": queue_full_warnings},
            "database": {"connection_pool_size": pool_size},
            "cache": {"entries": cache_size},
            "issues": issues,
            "gc_stats": {"collections": gc.get_count()},
        }

        return JSONResponse(health_data)

    except Exception as e:
        LOG.error(f"Health check error: {e}")
        return JSONResponse(
            {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            status_code=500,
        )
