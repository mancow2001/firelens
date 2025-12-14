#!/usr/bin/env python3
"""
FireLens Monitor - Command Line Interface

Entry points for the firelens and firelens-ctl commands.
"""
import argparse
import subprocess
import sys
from pathlib import Path

from . import __version__
from .resources import find_config_file


def main():
    """
    Main entry point for 'firelens' command.

    This is the primary CLI for starting the FireLens Monitor application.
    """
    parser = argparse.ArgumentParser(
        prog="firelens",
        description="FireLens Monitor - Multi-vendor Firewall Monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  firelens                            Start monitoring with default config
  firelens --config /etc/firelens/config.yaml
  firelens create-config              Create example configuration file
  firelens --port 9090                Override web dashboard port
  firelens --version                  Show version information
        """
    )

    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Configuration file path (searches defaults if not specified)"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        help="Override web dashboard port"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Override log level"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # create-config command
    config_parser = subparsers.add_parser(
        "create-config",
        help="Create example configuration file"
    )
    config_parser.add_argument(
        "--output", "-o",
        default="config.yaml",
        help="Output file path (default: config.yaml)"
    )
    config_parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Overwrite existing configuration file"
    )

    # version command (alternative to --version)
    subparsers.add_parser("version", help="Show version information")

    args = parser.parse_args()

    if args.command == "version":
        print(f"FireLens Monitor {__version__}")
        return 0

    if args.command == "create-config":
        return _create_config_command(args)

    # Find and validate config file
    config_path = find_config_file(args.config)
    if not config_path.exists():
        print(f"Configuration file not found: {config_path}")
        print(f"Create one with: firelens create-config --output {config_path}")
        return 1

    try:
        # Import here to avoid circular imports and speed up --help
        from .app import FireLensApp

        app = FireLensApp(str(config_path))

        if args.port:
            app.config_manager.global_config.web_port = args.port

        if args.log_level:
            app.config_manager.global_config.log_level = args.log_level
            app._setup_logging()

        app.start()

    except KeyboardInterrupt:
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


def _create_config_command(args):
    """Handle the create-config subcommand."""
    output_path = Path(args.output)

    if output_path.exists() and not args.force:
        print(f"Configuration file {args.output} already exists.")
        print("Use --force to overwrite.")
        return 1

    try:
        from .config import create_example_config

        example_content = create_example_config()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(example_content)
        print(f"Created example configuration file: {args.output}")
        print("Edit this file to configure your firewalls and start monitoring.")
        return 0
    except Exception as e:
        print(f"Failed to create configuration: {e}", file=sys.stderr)
        return 1


def control():
    """
    Entry point for 'firelens-ctl' service control command.

    Provides convenient wrappers around systemctl for managing
    the FireLens service.
    """
    parser = argparse.ArgumentParser(
        prog="firelens-ctl",
        description="FireLens Monitor Service Control",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  firelens-ctl status     Show service status
  firelens-ctl start      Start the service
  firelens-ctl stop       Stop the service
  firelens-ctl restart    Restart the service
  firelens-ctl logs       Follow service logs
  firelens-ctl config     Show current configuration
        """
    )

    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"firelens-ctl {__version__}"
    )

    parser.add_argument(
        "action",
        choices=["start", "stop", "restart", "status", "logs", "config", "enable", "disable"],
        help="Service action to perform"
    )

    parser.add_argument(
        "--service-name", "-n",
        default="firelens",
        help="Service name (default: firelens)"
    )

    args = parser.parse_args()

    service_name = args.service_name

    # Map actions to commands
    commands = {
        "start": ["systemctl", "start", service_name],
        "stop": ["systemctl", "stop", service_name],
        "restart": ["systemctl", "restart", service_name],
        "status": ["systemctl", "status", service_name, "--no-pager", "-l"],
        "logs": ["journalctl", "-u", service_name, "-f"],
        "enable": ["systemctl", "enable", service_name],
        "disable": ["systemctl", "disable", service_name],
    }

    if args.action == "config":
        # Show configuration file
        config_paths = [
            "/etc/firelens/config.yaml",
            "/etc/FireLens/config.yaml",  # Legacy
        ]
        for path in config_paths:
            if Path(path).exists():
                try:
                    subprocess.run(["cat", path], check=False)
                    return 0
                except FileNotFoundError:
                    with open(path) as f:
                        print(f.read())
                    return 0
        print("No configuration file found in standard locations.")
        return 1

    cmd = commands.get(args.action)
    if cmd:
        try:
            result = subprocess.run(cmd, check=False)
            return result.returncode
        except FileNotFoundError:
            print(f"Error: systemd not available.")
            print("Run FireLens manually with: firelens --config /path/to/config.yaml")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
