#!/usr/bin/env python3
"""
Check Python version compatibility for FireLens Monitor
Ensures Python 3.9+ is installed
"""
import sys

def check_python_version():
    """Check if Python version is compatible"""

    # Get version info
    version = sys.version_info
    version_string = f"{version.major}.{version.minor}.{version.micro}"

    print(f"Current Python Version: {version_string}")
    print(f"Version Info: {sys.version}")

    # Check minimum version (3.9)
    if version.major < 3:
        print("\n❌ ERROR: Python 3 is required")
        print("   Please install Python 3.9 or higher")
        return False

    if version.major == 3 and version.minor < 9:
        print(f"\n⚠️  WARNING: Python {version_string} detected")
        print("   Minimum recommended version: Python 3.9")
        print("   Some dependencies may not work correctly")
        print("   Please consider upgrading to Python 3.9+")

        # Still might work with 3.7-3.8
        if version.minor >= 7:
            print("\n✓ Python 3.7+ detected - may work but not fully tested")
            return True
        else:
            print("\n❌ ERROR: Python 3.7+ is required (dataclasses)")
            return False

    # Python 3.9+
    print(f"\n✅ Python {version_string} is compatible")
    print("   All features supported")
    return True


def check_required_modules():
    """Check if critical modules can be imported"""

    required_modules = [
        ('typing', 'Type hints'),
        ('dataclasses', 'Data classes'),
        ('collections', 'Collections (deque)'),
        ('queue', 'Queue'),
        ('threading', 'Threading'),
        ('sqlite3', 'SQLite database'),
        ('datetime', 'Date/time handling'),
    ]

    print("\nChecking required standard library modules:")
    all_ok = True

    for module_name, description in required_modules:
        try:
            __import__(module_name)
            print(f"  ✓ {module_name:20s} - {description}")
        except ImportError as e:
            print(f"  ✗ {module_name:20s} - MISSING: {e}")
            all_ok = False

    return all_ok


def check_dependencies():
    """Check if optional dependencies are installed"""

    dependencies = [
        ('requests', 'HTTP requests'),
        ('yaml', 'YAML config (PyYAML)'),
        ('pandas', 'Data analysis'),
        ('fastapi', 'Web framework'),
        ('uvicorn', 'ASGI server'),
        ('jinja2', 'Template engine'),
        ('psutil', 'System monitoring'),
        ('pytest', 'Testing framework'),
    ]

    print("\nChecking optional dependencies:")
    installed = []
    missing = []

    for module_name, description in dependencies:
        try:
            __import__(module_name)
            print(f"  ✓ {module_name:20s} - {description}")
            installed.append(module_name)
        except ImportError:
            print(f"  ✗ {module_name:20s} - NOT INSTALLED: {description}")
            missing.append(module_name)

    if missing:
        print(f"\n⚠️  {len(missing)} dependencies not installed")
        print("   Install with: pip install -r requirements.txt")
    else:
        print(f"\n✅ All {len(installed)} dependencies installed")

    return len(missing) == 0


if __name__ == '__main__':
    print("=" * 60)
    print("FireLens Monitor - Python Compatibility Check")
    print("=" * 60)

    # Check Python version
    version_ok = check_python_version()

    # Check standard library
    modules_ok = check_required_modules()

    # Check dependencies
    deps_ok = check_dependencies()

    print("\n" + "=" * 60)
    print("Summary:")
    print("=" * 60)

    if version_ok and modules_ok:
        print("✅ Python version and standard library: OK")
        if deps_ok:
            print("✅ All dependencies: INSTALLED")
            print("\n✅ System is ready to run FireLens Monitor")
            sys.exit(0)
        else:
            print("⚠️  Some dependencies: MISSING")
            print("\n⚠️  Run: pip install -r requirements.txt")
            sys.exit(1)
    else:
        print("❌ Python version or modules: INCOMPATIBLE")
        print("\n❌ Please upgrade Python to 3.9 or higher")
        sys.exit(1)
