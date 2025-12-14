"""
FireLens Monitor - Admin Routes
Admin dashboard and firewall management CRUD operations
"""
import logging
import re
import xml.etree.ElementTree as ET
from typing import Optional

import requests
from requests.exceptions import RequestException, SSLError, ConnectionError, Timeout

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..helpers import get_admin_user, get_csrf_token, validate_csrf, is_admin_enabled

LOG = logging.getLogger("FireLens.web")

router = APIRouter(prefix="/admin")


@router.get("", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    """Admin dashboard - firewall management"""
    if not is_admin_enabled(request):
        return HTMLResponse("<h1>Admin interface is disabled</h1>", status_code=403)

    user = get_admin_user(request)
    if not user:
        return RedirectResponse(url="/admin/login", status_code=302)

    templates = request.app.state.templates
    config_manager = request.app.state.config_manager
    collector_manager = request.app.state.collector_manager

    # Get all firewalls with their status
    firewalls = []
    for name, config in config_manager.firewalls.items():
        # Get collector status if available
        collector_status = "unknown"
        authenticated = False
        if collector_manager:
            status = collector_manager.get_collector_status()
            if name in status:
                collector_status = "running" if status[name].get('running') else "stopped"
                authenticated = status[name].get('authenticated', False)

        firewalls.append({
            'name': name,
            'host': config.host,
            'type': config.type,
            'enabled': config.enabled,
            'collector_status': collector_status,
            'authenticated': authenticated,
            'poll_interval': config.poll_interval,
            'verify_ssl': config.verify_ssl
        })

    # Import vendor types
    from ...config import SUPPORTED_VENDOR_TYPES

    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "user": user,
        "firewalls": firewalls,
        "vendor_types": SUPPORTED_VENDOR_TYPES,
        "csrf_token": get_csrf_token(request)
    })


@router.get("/firewall/add", response_class=HTMLResponse)
async def admin_add_firewall_page(request: Request):
    """Show add firewall form"""
    if not is_admin_enabled(request):
        return HTMLResponse("<h1>Admin interface is disabled</h1>", status_code=403)

    user = get_admin_user(request)
    if not user:
        return RedirectResponse(url="/admin/login", status_code=302)

    templates = request.app.state.templates
    from ...config import SUPPORTED_VENDOR_TYPES

    return templates.TemplateResponse("admin_firewall_form.html", {
        "request": request,
        "user": user,
        "firewall": None,
        "vendor_types": SUPPORTED_VENDOR_TYPES,
        "action": "add",
        "csrf_token": get_csrf_token(request)
    })


@router.get("/firewall/{name}/edit", response_class=HTMLResponse)
async def admin_edit_firewall_page(request: Request, name: str):
    """Show edit firewall form"""
    if not is_admin_enabled(request):
        return HTMLResponse("<h1>Admin interface is disabled</h1>", status_code=403)

    user = get_admin_user(request)
    if not user:
        return RedirectResponse(url="/admin/login", status_code=302)

    templates = request.app.state.templates
    config_manager = request.app.state.config_manager

    firewall = config_manager.get_firewall(name)
    if not firewall:
        raise HTTPException(status_code=404, detail="Firewall not found")

    from ...config import SUPPORTED_VENDOR_TYPES

    # Serialize interface_configs for the template
    interface_configs = []
    if firewall.interface_configs:
        for iface in firewall.interface_configs:
            interface_configs.append({
                'name': iface.name,
                'display_name': iface.display_name,
                'enabled': iface.enabled,
                'description': iface.description or ''
            })

    return templates.TemplateResponse("admin_firewall_form.html", {
        "request": request,
        "user": user,
        "firewall": {
            'name': firewall.name,
            'host': firewall.host,
            'username': firewall.username,
            'password': '********',  # Never expose password in edit form
            'type': firewall.type,
            'enabled': firewall.enabled,
            'verify_ssl': firewall.verify_ssl,
            'poll_interval': firewall.poll_interval,
            'dp_aggregation': firewall.dp_aggregation,
            'interface_monitoring': firewall.interface_monitoring,
            'auto_discover_interfaces': firewall.auto_discover_interfaces,
            'exclude_interfaces': firewall.exclude_interfaces or [],
            'interface_configs': interface_configs
        },
        "vendor_types": SUPPORTED_VENDOR_TYPES,
        "action": "edit",
        "csrf_token": get_csrf_token(request)
    })


# ==================== ADMIN API ENDPOINTS ====================

@router.get("/api/firewalls")
async def admin_api_list_firewalls(request: Request):
    """API: List all firewalls with status"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    config_manager = request.app.state.config_manager
    collector_manager = request.app.state.collector_manager

    firewalls = []
    for name, config in config_manager.firewalls.items():
        collector_status = "unknown"
        authenticated = False
        if collector_manager:
            status = collector_manager.get_collector_status()
            if name in status:
                collector_status = "running" if status[name].get('running') else "stopped"
                authenticated = status[name].get('authenticated', False)

        firewalls.append({
            'name': name,
            'host': config.host,
            'type': config.type,
            'enabled': config.enabled,
            'collector_status': collector_status,
            'authenticated': authenticated
        })

    return JSONResponse(firewalls)


@router.get("/api/firewalls/check-name")
async def admin_api_check_firewall_name(request: Request, name: str):
    """API: Check if a firewall name already exists"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    config_manager = request.app.state.config_manager
    exists = name in config_manager.firewalls

    return JSONResponse({"exists": exists, "name": name})


@router.get("/api/firewalls/{name}/rename-estimate")
async def admin_api_rename_estimate(request: Request, name: str):
    """API: Estimate the impact of renaming a firewall"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    database = request.app.state.database
    config_manager = request.app.state.config_manager

    if name not in config_manager.firewalls:
        raise HTTPException(status_code=404, detail="Firewall not found")

    counts = database.count_firewall_references(name)
    total = sum(counts.values())

    return JSONResponse({
        "firewall_name": name,
        "metrics_count": counts.get('metrics', 0),
        "interface_metrics_count": counts.get('interface_metrics', 0),
        "session_statistics_count": counts.get('session_statistics', 0),
        "total_rows": total,
        "estimated_seconds": round(total / 50000, 1)  # ~50K rows/sec estimate
    })


@router.post("/api/firewalls/{name}/rename")
async def admin_api_start_rename(request: Request, name: str):
    """API: Start a background rename task"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    data = await request.json()

    # Validate CSRF token
    csrf_token = data.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not validate_csrf(request, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    new_name = data.get('new_name')
    if not new_name:
        raise HTTPException(status_code=400, detail="new_name is required")

    database = request.app.state.database

    task_id, error = database.start_rename_task(name, new_name)
    if error:
        raise HTTPException(status_code=400, detail=error)

    LOG.info(f"Admin {user} started rename task {task_id}: '{name}' -> '{new_name}'")

    return JSONResponse({
        "status": "started",
        "task_id": task_id,
        "message": "Rename task started"
    })


@router.get("/api/rename-tasks/{task_id}")
async def admin_api_get_rename_status(request: Request, task_id: str):
    """API: Get status of a rename task"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    database = request.app.state.database
    status = database.get_rename_task_status(task_id)

    if not status:
        raise HTTPException(status_code=404, detail="Task not found")

    # If completed, update config manager and collector
    if status['status'] == 'completed':
        config_manager = request.app.state.config_manager
        collector_manager = request.app.state.collector_manager

        old_name = status['old_name']
        new_name = status['new_name']

        # Update config if not already done
        if old_name in config_manager.firewalls and new_name not in config_manager.firewalls:
            config_manager.rename_firewall(old_name, new_name)
            LOG.info(f"Config manager updated for rename: '{old_name}' -> '{new_name}'")

            # Hot-reload collector
            if collector_manager:
                try:
                    collector_manager.remove_collector(old_name)
                    fw_config = config_manager.get_firewall(new_name)
                    if fw_config and fw_config.enabled:
                        collector_manager.add_collector(new_name, fw_config)
                    LOG.info(f"Hot-reloaded collector for renamed firewall: '{new_name}'")
                except Exception as e:
                    LOG.warning(f"Could not hot-reload collector after rename: {e}")

    return JSONResponse(status)


@router.get("/api/firewalls/{name}")
async def admin_api_get_firewall(request: Request, name: str):
    """API: Get single firewall config"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    config_manager = request.app.state.config_manager
    firewall = config_manager.get_firewall(name)
    if not firewall:
        raise HTTPException(status_code=404, detail="Firewall not found")

    return JSONResponse({
        'name': firewall.name,
        'host': firewall.host,
        'username': firewall.username,
        'type': firewall.type,
        'enabled': firewall.enabled,
        'verify_ssl': firewall.verify_ssl,
        'poll_interval': firewall.poll_interval,
        'dp_aggregation': firewall.dp_aggregation,
        'interface_monitoring': firewall.interface_monitoring,
        'auto_discover_interfaces': firewall.auto_discover_interfaces,
        'exclude_interfaces': firewall.exclude_interfaces or []
    })


@router.post("/api/firewalls")
async def admin_api_add_firewall(request: Request):
    """API: Add new firewall"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    config_manager = request.app.state.config_manager
    collector_manager = request.app.state.collector_manager

    data = await request.json()

    # Validate CSRF token
    csrf_token = data.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not validate_csrf(request, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    # Validate required fields (vendor-aware)
    vendor_type = data.get('type', 'palo_alto')
    if vendor_type == 'fortinet':
        # Fortinet uses API token (password field), username is optional
        required = ['name', 'host', 'password']
    else:
        required = ['name', 'host', 'username', 'password']
    for field in required:
        if not data.get(field):
            raise HTTPException(status_code=400, detail=f"Missing required field: {field}")

    # Check name doesn't already exist
    if data['name'] in config_manager.firewalls:
        raise HTTPException(status_code=400, detail=f"Firewall '{data['name']}' already exists")

    # Validate name format
    if not re.match(r'^[a-zA-Z0-9_]+$', data['name']):
        raise HTTPException(status_code=400, detail="Name must contain only letters, numbers, and underscores")

    # Create firewall config
    from ...config import EnhancedFirewallConfig, InterfaceConfig

    exclude_interfaces = data.get('exclude_interfaces', [])
    if isinstance(exclude_interfaces, str):
        exclude_interfaces = [x.strip() for x in exclude_interfaces.split('\n') if x.strip()]

    # Parse interface_configs if provided
    interface_configs = None
    if 'interface_configs' in data and data['interface_configs']:
        interface_configs = []
        for iface_data in data['interface_configs']:
            interface_configs.append(InterfaceConfig(
                name=iface_data['name'],
                display_name=iface_data.get('display_name', iface_data['name']),
                enabled=iface_data.get('enabled', True),
                description=iface_data.get('description', '')
            ))

    # Handle boolean fields explicitly (checkboxes may not send value when unchecked)
    verify_ssl = data.get('verify_ssl')
    LOG.info(f"Add firewall - verify_ssl from request: {verify_ssl} (type: {type(verify_ssl).__name__})")
    if verify_ssl is None:
        verify_ssl = True  # Default if not provided
    enabled = data.get('enabled')
    if enabled is None:
        enabled = True
    LOG.info(f"Add firewall - final verify_ssl: {verify_ssl}, enabled: {enabled}")

    fw_config = EnhancedFirewallConfig(
        name=data['name'],
        host=data['host'],
        username=data.get('username', ''),  # Fortinet doesn't use username
        password=data['password'],
        type=data.get('type', 'palo_alto'),
        enabled=enabled,
        verify_ssl=verify_ssl,
        poll_interval=int(data.get('poll_interval', 60)),
        dp_aggregation=data.get('dp_aggregation', 'mean'),
        interface_monitoring=data.get('interface_monitoring', True),
        auto_discover_interfaces=data.get('auto_discover_interfaces', True),
        exclude_interfaces=exclude_interfaces,
        interface_configs=interface_configs
    )

    # Add to config manager (saves to YAML)
    config_manager.add_firewall(fw_config)
    LOG.info(f"Admin {user} added firewall: {data['name']}")

    # Hot reload: add collector if running
    if collector_manager and fw_config.enabled:
        try:
            collector_manager.add_collector(data['name'], fw_config)
            LOG.info(f"Hot-reloaded new collector for: {data['name']}")
        except Exception as e:
            LOG.warning(f"Could not hot-reload collector for {data['name']}: {e}")

    return JSONResponse({"status": "ok", "message": f"Firewall '{data['name']}' added"})


@router.put("/api/firewalls/{name}")
async def admin_api_update_firewall(request: Request, name: str):
    """API: Update firewall config"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    config_manager = request.app.state.config_manager
    collector_manager = request.app.state.collector_manager
    database = request.app.state.database

    existing = config_manager.get_firewall(name)
    if not existing:
        raise HTTPException(status_code=404, detail="Firewall not found")

    data = await request.json()

    # Validate CSRF token
    csrf_token = data.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not validate_csrf(request, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    # Check if rename is requested
    new_name = data.get('name', name)
    if new_name != name:
        # Validate new name doesn't already exist in config
        if config_manager.get_firewall(new_name):
            raise HTTPException(status_code=400, detail=f"Firewall '{new_name}' already exists")

        # Rename in database (cascades to all metrics tables)
        success, message = database.rename_firewall(name, new_name)
        if not success:
            raise HTTPException(status_code=400, detail=message)

        # Remove old firewall from config manager
        config_manager.remove_firewall(name)

        # Hot reload: remove old collector
        if collector_manager:
            try:
                collector_manager.remove_collector(name)
                LOG.info(f"Hot-removed old collector for renamed firewall: {name}")
            except Exception as e:
                LOG.warning(f"Could not hot-remove old collector for {name}: {e}")

        LOG.info(f"Admin {user} renamed firewall '{name}' to '{new_name}'")
        # Use new name for the rest of the operation
        name = new_name

    # Create updated config
    from ...config import EnhancedFirewallConfig, InterfaceConfig

    exclude_interfaces = data.get('exclude_interfaces', existing.exclude_interfaces or [])
    if isinstance(exclude_interfaces, str):
        exclude_interfaces = [x.strip() for x in exclude_interfaces.split('\n') if x.strip()]

    # Parse interface_configs if provided
    interface_configs = None
    if 'interface_configs' in data and data['interface_configs']:
        interface_configs = []
        for iface_data in data['interface_configs']:
            interface_configs.append(InterfaceConfig(
                name=iface_data['name'],
                display_name=iface_data.get('display_name', iface_data['name']),
                enabled=iface_data.get('enabled', True),
                description=iface_data.get('description', '')
            ))
    elif not data.get('auto_discover_interfaces', existing.auto_discover_interfaces):
        # Keep existing interface_configs if not using auto-discover and none provided
        interface_configs = existing.interface_configs

    fw_config = EnhancedFirewallConfig(
        name=name,
        host=data.get('host', existing.host),
        username=data.get('username', existing.username),
        password=data.get('password', existing.password),
        type=data.get('type', existing.type),
        enabled=data.get('enabled', existing.enabled),
        verify_ssl=data.get('verify_ssl', existing.verify_ssl),
        poll_interval=int(data.get('poll_interval', existing.poll_interval)),
        dp_aggregation=data.get('dp_aggregation', existing.dp_aggregation),
        interface_monitoring=data.get('interface_monitoring', existing.interface_monitoring),
        auto_discover_interfaces=data.get('auto_discover_interfaces', existing.auto_discover_interfaces),
        exclude_interfaces=exclude_interfaces,
        interface_configs=interface_configs
    )

    # Update config manager (saves to YAML)
    config_manager.add_firewall(fw_config)
    LOG.info(f"Admin {user} updated firewall: {name}")

    # Hot reload: update collector
    if collector_manager:
        try:
            collector_manager.update_collector(name, fw_config)
            LOG.info(f"Hot-reloaded updated collector for: {name}")
        except Exception as e:
            LOG.warning(f"Could not hot-reload collector for {name}: {e}")

    return JSONResponse({"status": "ok", "message": f"Firewall '{name}' updated"})


@router.delete("/api/firewalls/{name}")
async def admin_api_delete_firewall(request: Request, name: str):
    """API: Delete firewall"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    config_manager = request.app.state.config_manager
    collector_manager = request.app.state.collector_manager
    database = request.app.state.database
    cache = request.app.state.cache

    # Validate CSRF token from header (DELETE requests typically don't have body)
    csrf_token = request.headers.get('X-CSRF-Token')
    if not validate_csrf(request, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    if name not in config_manager.firewalls:
        raise HTTPException(status_code=404, detail="Firewall not found")

    # Hot reload: remove collector first
    if collector_manager:
        try:
            collector_manager.remove_collector(name)
            LOG.info(f"Hot-removed collector for: {name}")
        except Exception as e:
            LOG.warning(f"Could not hot-remove collector for {name}: {e}")

    # Remove from database (including all metrics data)
    if database:
        try:
            database.unregister_firewall(name, delete_metrics=True)
            LOG.info(f"Removed firewall from database: {name}")
        except Exception as e:
            LOG.warning(f"Could not remove firewall from database {name}: {e}")

    # Clear dashboard cache to reflect changes immediately
    cache.clear()

    # Remove from config manager (saves to YAML)
    config_manager.remove_firewall(name)
    LOG.info(f"Admin {user} deleted firewall: {name}")

    return JSONResponse({"status": "ok", "message": f"Firewall '{name}' deleted"})


@router.post("/api/firewalls/{name}/toggle")
async def admin_api_toggle_firewall(request: Request, name: str):
    """API: Enable/disable firewall"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    config_manager = request.app.state.config_manager
    collector_manager = request.app.state.collector_manager

    # Validate CSRF token from header
    csrf_token = request.headers.get('X-CSRF-Token')
    if not validate_csrf(request, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    firewall = config_manager.get_firewall(name)
    if not firewall:
        raise HTTPException(status_code=404, detail="Firewall not found")

    # Toggle enabled state
    new_enabled = not firewall.enabled
    firewall.enabled = new_enabled
    config_manager.add_firewall(firewall)  # Save update
    LOG.info(f"Admin {user} {'enabled' if new_enabled else 'disabled'} firewall: {name}")

    # Hot reload: start or stop collector
    if collector_manager:
        try:
            if new_enabled:
                collector_manager.add_collector(name, firewall)
            else:
                collector_manager.remove_collector(name)
            LOG.info(f"Hot-{'started' if new_enabled else 'stopped'} collector for: {name}")
        except Exception as e:
            LOG.warning(f"Could not hot-toggle collector for {name}: {e}")

    return JSONResponse({
        "status": "ok",
        "enabled": new_enabled,
        "message": f"Firewall '{name}' {'enabled' if new_enabled else 'disabled'}"
    })


@router.get("/api/vendors")
async def admin_api_list_vendors(request: Request):
    """API: List supported vendor types"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    from ...config import SUPPORTED_VENDOR_TYPES
    from ...vendors import get_available_vendors

    vendors = get_available_vendors()
    return JSONResponse({
        "supported_types": SUPPORTED_VENDOR_TYPES,
        "vendor_names": vendors
    })


@router.post("/api/test-connection")
async def admin_api_test_connection(request: Request):
    """API: Test firewall connection and authentication"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    config_manager = request.app.state.config_manager

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Validate CSRF token
    csrf_token = data.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not validate_csrf(request, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    vendor_type = data.get('type', 'palo_alto')

    # Fortinet uses API token (password field), username is optional
    if vendor_type == 'fortinet':
        required = ['host', 'password', 'type']
    else:
        required = ['host', 'username', 'password', 'type']

    missing = [f for f in required if not data.get(f)]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required fields: {', '.join(missing)}")

    host = data['host']
    username = data.get('username', '')
    password = data['password']
    verify_ssl = data.get('verify_ssl', True)
    vdom = data.get('vdom', 'root')

    # Test connection based on vendor type
    result = {
        "success": False,
        "message": "",
        "details": {}
    }

    if vendor_type == "palo_alto":
        result = await _test_panos_connection(config_manager, host, username, password, verify_ssl)
    elif vendor_type == "fortinet":
        result = await _test_fortinet_connection(config_manager, host, password, verify_ssl, vdom)
    elif vendor_type == "cisco_firepower":
        result = {
            "success": False,
            "message": "Cisco Firepower connection testing not yet implemented",
            "details": {}
        }
    else:
        result = {
            "success": False,
            "message": f"Unknown vendor type: {vendor_type}",
            "details": {}
        }

    LOG.info(f"Admin {user} tested connection to {host}: {'success' if result['success'] else 'failed'}")
    return JSONResponse(result)


@router.post("/api/discover-interfaces")
async def admin_api_discover_interfaces(request: Request):
    """API: Discover interfaces from a firewall"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    config_manager = request.app.state.config_manager

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Validate CSRF token
    csrf_token = data.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not validate_csrf(request, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    vendor_type = data.get('type', 'palo_alto')

    # Fortinet uses API token (password field), username is optional
    if vendor_type == 'fortinet':
        required = ['host', 'password', 'type']
    else:
        required = ['host', 'username', 'password', 'type']

    missing = [f for f in required if not data.get(f)]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required fields: {', '.join(missing)}")

    host = data['host']
    username = data.get('username', '')
    password = data['password']
    verify_ssl = data.get('verify_ssl', True)
    vdom = data.get('vdom', 'root')

    result = {
        "success": False,
        "message": "",
        "interfaces": []
    }

    if vendor_type == "palo_alto":
        result = await _discover_panos_interfaces(config_manager, host, username, password, verify_ssl)
    elif vendor_type == "fortinet":
        result = await _discover_fortinet_interfaces(config_manager, host, password, verify_ssl, vdom)
    elif vendor_type == "cisco_firepower":
        result = {
            "success": False,
            "message": "Cisco Firepower interface discovery not yet implemented",
            "interfaces": []
        }
    else:
        result = {
            "success": False,
            "message": f"Unknown vendor type: {vendor_type}",
            "interfaces": []
        }

    LOG.info(f"Admin {user} discovered interfaces from {host}: {len(result.get('interfaces', []))} found")
    return JSONResponse(result)


# ==================== Helper Functions ====================

def _get_ssl_verify(config_manager, verify_ssl: bool):
    """Get SSL verification setting, using custom CA bundle if available"""
    if not verify_ssl:
        return False

    from ...cert_manager import CertificateManager
    certs_dir = getattr(config_manager.global_config, 'certs_directory', './certs')
    cert_manager = CertificateManager(certs_dir)
    ca_bundle = cert_manager.get_ca_bundle_path()
    if ca_bundle:
        return ca_bundle  # Use custom CA bundle
    return True


async def _test_panos_connection(config_manager, host: str, username: str, password: str, verify_ssl: bool) -> dict:
    """Test PAN-OS firewall connection and return hardware info"""
    result = {
        "success": False,
        "message": "",
        "details": {}
    }

    ssl_verify = _get_ssl_verify(config_manager, verify_ssl)

    try:
        # Step 1: Get API key
        keygen_url = f"{host}/api/?type=keygen&user={username}&password={password}"
        response = requests.get(keygen_url, verify=ssl_verify, timeout=10)

        if response.status_code != 200:
            result["message"] = f"HTTP {response.status_code}: Failed to connect to firewall"
            return result

        # Parse response for API key
        root = ET.fromstring(response.text)

        status = root.get('status')
        if status != 'success':
            # Check for error message
            msg_elem = root.find('.//msg')
            error_msg = msg_elem.text if msg_elem is not None else "Authentication failed"
            result["message"] = f"Authentication failed: {error_msg}"
            return result

        key_elem = root.find('.//key')
        if key_elem is None:
            result["message"] = "Failed to retrieve API key"
            return result

        api_key = key_elem.text

        # Step 2: Get system info to verify full connectivity
        sysinfo_url = f"{host}/api/?type=op&cmd=<show><system><info></info></system></show>&key={api_key}"
        response = requests.get(sysinfo_url, verify=ssl_verify, timeout=10)

        if response.status_code != 200:
            result["message"] = f"Connected but failed to get system info (HTTP {response.status_code})"
            result["success"] = True  # Auth worked at least
            return result

        root = ET.fromstring(response.text)
        if root.get('status') != 'success':
            result["message"] = "Connected and authenticated, but failed to retrieve system info"
            result["success"] = True  # Auth worked
            return result

        # Extract system details
        sys_info = root.find('.//system')
        if sys_info is not None:
            result["details"] = {
                "hostname": sys_info.findtext('hostname', 'Unknown'),
                "model": sys_info.findtext('model', 'Unknown'),
                "serial": sys_info.findtext('serial', 'Unknown'),
                "sw_version": sys_info.findtext('sw-version', 'Unknown'),
                "uptime": sys_info.findtext('uptime', 'Unknown')
            }

        result["success"] = True
        result["message"] = "Connection successful"
        return result

    except SSLError as e:
        result["message"] = f"SSL/TLS error: {str(e)}. Try disabling SSL verification for self-signed certificates."
        return result
    except ConnectionError as e:
        result["message"] = f"Connection failed: Unable to reach {host}. Check the URL and network connectivity."
        return result
    except Timeout:
        result["message"] = f"Connection timed out: {host} did not respond within 10 seconds"
        return result
    except ET.ParseError as e:
        result["message"] = f"Invalid response from firewall: {str(e)}"
        return result
    except RequestException as e:
        result["message"] = f"Request failed: {str(e)}"
        return result
    except Exception as e:
        result["message"] = f"Unexpected error: {str(e)}"
        return result


async def _discover_panos_interfaces(config_manager, host: str, username: str, password: str, verify_ssl: bool) -> dict:
    """Discover interfaces from a PAN-OS firewall"""
    from ...interface_monitor import discover_interfaces_panos11

    result = {
        "success": False,
        "message": "",
        "interfaces": []
    }

    ssl_verify = _get_ssl_verify(config_manager, verify_ssl)

    try:
        # Step 1: Get API key
        keygen_url = f"{host}/api/?type=keygen&user={username}&password={password}"
        response = requests.get(keygen_url, verify=ssl_verify, timeout=10)

        if response.status_code != 200:
            result["message"] = f"HTTP {response.status_code}: Failed to connect to firewall"
            return result

        root = ET.fromstring(response.text)

        status = root.get('status')
        if status != 'success':
            msg_elem = root.find('.//msg')
            error_msg = msg_elem.text if msg_elem is not None else "Authentication failed"
            result["message"] = f"Authentication failed: {error_msg}"
            return result

        key_elem = root.find('.//key')
        if key_elem is None:
            result["message"] = "Failed to retrieve API key"
            return result

        api_key = key_elem.text

        # Step 2: Get interface list
        interface_url = f"{host}/api/?type=op&cmd=<show><interface>all</interface></show>&key={api_key}"
        response = requests.get(interface_url, verify=ssl_verify, timeout=15)

        if response.status_code != 200:
            result["message"] = f"Failed to get interface list (HTTP {response.status_code})"
            return result

        # Parse interface names
        interface_names = discover_interfaces_panos11(response.text)

        if not interface_names:
            result["success"] = True
            result["message"] = "Connected but no interfaces found"
            return result

        # Generate display names and create interface list
        from ...config import EnhancedFirewallConfig
        temp_config = EnhancedFirewallConfig(name="temp", host=host, username=username, password=password)

        interfaces = []
        for iface_name in sorted(interface_names):
            display_name = temp_config._generate_display_name(iface_name)
            interfaces.append({
                "name": iface_name,
                "display_name": display_name,
                "enabled": True,
                "description": ""
            })

        result["success"] = True
        result["message"] = f"Found {len(interfaces)} interfaces"
        result["interfaces"] = interfaces
        return result

    except SSLError as e:
        result["message"] = f"SSL/TLS error: {str(e)}. Try disabling SSL verification."
        return result
    except ConnectionError as e:
        result["message"] = f"Connection failed: Unable to reach {host}"
        return result
    except Timeout:
        result["message"] = f"Connection timed out: {host} did not respond"
        return result
    except Exception as e:
        result["message"] = f"Unexpected error: {str(e)}"
        return result


async def _test_fortinet_connection(config_manager, host: str, api_token: str, verify_ssl: bool, vdom: str = "root") -> dict:
    """Test FortiGate firewall connection using API token authentication"""
    from ...vendors.fortinet import FortinetClient

    result = {
        "success": False,
        "message": "",
        "details": {}
    }

    ssl_verify = _get_ssl_verify(config_manager, verify_ssl)

    try:
        # Create FortinetClient and test connection
        client = FortinetClient(host=host, verify_ssl=ssl_verify if ssl_verify is True else False)
        client.set_vdom(vdom)

        # Authenticate with API token
        if not client.authenticate(username="", password=api_token):
            result["message"] = "Authentication failed: Invalid API token or unable to connect"
            return result

        # Get hardware info from the client
        hw_info = client.get_hardware_info()

        if hw_info:
            result["details"] = {
                "hostname": hw_info.hostname,
                "model": hw_info.model,
                "serial": hw_info.serial,
                "sw_version": hw_info.sw_version,
            }

        result["success"] = True
        result["message"] = "Connection successful"

        client.close()
        return result

    except SSLError as e:
        result["message"] = f"SSL/TLS error: {str(e)}. Try disabling SSL verification for self-signed certificates."
        return result
    except ConnectionError as e:
        result["message"] = f"Connection failed: Unable to reach {host}. Check the URL and network connectivity."
        return result
    except Timeout:
        result["message"] = f"Connection timed out: {host} did not respond within 10 seconds"
        return result
    except RequestException as e:
        result["message"] = f"Request failed: {str(e)}"
        return result
    except Exception as e:
        result["message"] = f"Unexpected error: {str(e)}"
        return result


async def _discover_fortinet_interfaces(config_manager, host: str, api_token: str, verify_ssl: bool, vdom: str = "root") -> dict:
    """Discover interfaces from a FortiGate firewall"""
    from ...vendors.fortinet import FortinetClient

    result = {
        "success": False,
        "message": "",
        "interfaces": []
    }

    ssl_verify = _get_ssl_verify(config_manager, verify_ssl)

    try:
        # Create FortinetClient
        client = FortinetClient(host=host, verify_ssl=ssl_verify if ssl_verify is True else False)
        client.set_vdom(vdom)

        # Authenticate with API token
        if not client.authenticate(username="", password=api_token):
            result["message"] = "Authentication failed: Invalid API token"
            return result

        # Discover interfaces
        interface_names = client.discover_interfaces()

        if not interface_names:
            result["success"] = True
            result["message"] = "Connected but no interfaces found"
            client.close()
            return result

        # Generate display names and create interface list
        from ...config import EnhancedFirewallConfig
        temp_config = EnhancedFirewallConfig(
            name="temp",
            host=host,
            username="",
            password=api_token,
            type="fortinet"
        )

        interfaces = []
        for iface_name in sorted(interface_names):
            display_name = temp_config._generate_display_name(iface_name)
            interfaces.append({
                "name": iface_name,
                "display_name": display_name,
                "enabled": True,
                "description": ""
            })

        result["success"] = True
        result["message"] = f"Found {len(interfaces)} interfaces"
        result["interfaces"] = interfaces

        client.close()
        return result

    except SSLError as e:
        result["message"] = f"SSL/TLS error: {str(e)}. Try disabling SSL verification."
        return result
    except ConnectionError as e:
        result["message"] = f"Connection failed: Unable to reach {host}"
        return result
    except Timeout:
        result["message"] = f"Connection timed out: {host} did not respond"
        return result
    except Exception as e:
        result["message"] = f"Unexpected error: {str(e)}"
        return result
