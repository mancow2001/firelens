"""
Resource discovery for FireLens package data (templates, static files)

This module provides functions to locate templates and static assets
whether FireLens is installed via pip or running from source.
"""

from pathlib import Path
from typing import Optional


def get_package_path() -> Path:
    """Get the path to the installed firelens package"""
    return Path(__file__).parent


def get_templates_path() -> Path:
    """
    Get the path to Jinja2 templates directory.

    Returns:
        Path to templates directory

    Raises:
        FileNotFoundError: If templates directory cannot be found
    """
    # Check inside package (pip installed)
    pkg_templates = get_package_path() / "templates"
    if pkg_templates.exists():
        return pkg_templates

    # Fallback for development - check project root
    dev_templates = Path(__file__).parent.parent.parent.parent / "templates"
    if dev_templates.exists():
        return dev_templates

    raise FileNotFoundError(
        "Templates directory not found. "
        "Ensure package is installed correctly with: pip install firelens-monitor"
    )


def get_static_path() -> Path:
    """
    Get the path to static assets directory.

    Returns:
        Path to static directory

    Raises:
        FileNotFoundError: If static directory cannot be found
    """
    # Check inside package (pip installed)
    pkg_static = get_package_path() / "static"
    if pkg_static.exists():
        return pkg_static

    # Fallback for development - check project root
    dev_static = Path(__file__).parent.parent.parent.parent / "static"
    if dev_static.exists():
        return dev_static

    raise FileNotFoundError(
        "Static directory not found. "
        "Ensure package is installed correctly with: pip install firelens-monitor"
    )


def get_default_config_paths() -> list[Path]:
    """
    Get the default configuration file search paths.

    Returns:
        List of paths to search for config files, in priority order
    """
    return [
        Path("config.yaml"),
        Path("/etc/firelens/config.yaml"),
        Path("/etc/FireLens/config.yaml"),  # Backward compat with installation.sh
        Path.home() / ".config" / "firelens" / "config.yaml",
    ]


def find_config_file(specified: Optional[str] = None) -> Path:
    """
    Find configuration file from specified path or search defaults.

    Args:
        specified: Explicit config path (if provided, used directly)

    Returns:
        Path to configuration file
    """
    if specified:
        return Path(specified)

    for path in get_default_config_paths():
        if path.exists():
            return path

    # Return default path even if it doesn't exist
    # (caller will handle the error)
    return Path("config.yaml")


def get_data_directory() -> Path:
    """
    Get the default data directory for metrics database.

    Returns:
        Path to data directory
    """
    # System install location
    system_data = Path("/var/lib/firelens/data")
    if system_data.exists():
        return system_data

    # Backward compat with installation.sh
    legacy_data = Path("/var/lib/FireLens/data")
    if legacy_data.exists():
        return legacy_data

    # Development/local location
    local_data = Path("data")
    return local_data


def get_log_directory() -> Path:
    """
    Get the default log directory.

    Returns:
        Path to log directory
    """
    # System install location
    system_log = Path("/var/log/firelens")
    if system_log.exists():
        return system_log

    # Backward compat
    legacy_log = Path("/var/log/FireLens")
    if legacy_log.exists():
        return legacy_log

    # Development/local location
    return Path("logs")
