  ---
  # Contributing to FireLens

  Thank you for your interest in contributing to FireLens! This document provides guidelines and instructions for contributing.

  ## Code of Conduct

  By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

  ## How to Contribute

  ### Reporting Bugs

  Before submitting a bug report:
  1. Check the [existing issues](https://github.com/mancow2001/FireLens/issues) to avoid duplicates
  2. Include as much detail as possible:
     - FireLens version (`firelens --version`)
     - Python version (`python --version`)
     - Operating system
     - Steps to reproduce
     - Expected vs actual behavior
     - Relevant logs (sanitize any sensitive data)

  ### Suggesting Features

  Feature requests are welcome! Please:
  1. Check existing issues for similar suggestions
  2. Clearly describe the use case and expected behavior
  3. Explain why this feature would benefit other users

  ### Pull Requests

  1. **Fork the repository** and create your branch from `main`
  2. **Set up your development environment:**
     ```bash
     git clone https://github.com/YOUR_USERNAME/FireLens.git
     cd FireLens
     python3 -m venv venv
     source venv/bin/activate  # On Windows: venv\Scripts\activate
     pip install -e ".[dev]"
  3. Make your changes following the coding standards below
  4. Run tests to ensure nothing is broken:
  ./run_tests.sh
  # Or: pytest tests/ -v
  5. Format your code:
  black src/ tests/
  ruff check src/ --fix
  6. Commit your changes with a clear, descriptive message
  7. Push to your fork and submit a pull request

  Development Setup

  Prerequisites

  - Python 3.9 or higher
  - For SAML support: libxmlsec1-dev (Ubuntu/Debian) or xmlsec1-openssl-devel (RHEL/Fedora)

  Running Tests

  # Run all tests
  ./run_tests.sh

  # Run with coverage
  ./run_tests.sh coverage

  # Run specific test suites
  ./run_tests.sh database
  ./run_tests.sh memory
  ./run_tests.sh web
  ./run_tests.sh collectors
  ./run_tests.sh vendors

  # Quick run without coverage
  ./run_tests.sh quick

  Project Structure

  src/firelens/           # Main package
  ├── vendors/            # Multi-vendor firewall adapters
  ├── web_dashboard/      # FastAPI web interface
  │   └── routes/         # API route modules
  ├── templates/          # Jinja2 HTML templates
  └── static/             # CSS, JS, images

  tests/                  # Unit tests (218 tests)

  Coding Standards

  Python Style

  - Follow https://pep8.org/ conventions
  - Use https://github.com/psf/black for formatting
  - Use https://github.com/astral-sh/ruff for linting
  - Maximum line length: 88 characters (Black default)
  - Use type hints where practical

  Code Quality

  - Write docstrings for public functions and classes
  - Keep functions focused and under 50 lines where possible
  - Route modules should stay under 800 lines
  - Add unit tests for new functionality
  - Maintain test coverage for critical paths

  Commit Messages

  - Use clear, descriptive commit messages
  - Start with a verb in present tense (e.g., "Add", "Fix", "Update")
  - Reference issue numbers where applicable (e.g., "Fix #123")

  Security

  - Never commit credentials, API keys, or secrets
  - Sanitize user input to prevent injection attacks
  - Follow OWASP security guidelines
  - Use parameterized queries for database operations

  Adding Vendor Support

  To add support for a new firewall vendor:

  1. Create a new adapter in src/firelens/vendors/:
  # src/firelens/vendors/your_vendor.py
  from .base import BaseFirewallClient, FirewallMetrics

  class YourVendorClient(BaseFirewallClient):
      # Implement required methods
      pass
  2. Register the vendor in src/firelens/vendors/__init__.py
  3. Add vendor-specific form fields in templates if needed
  4. Write tests in tests/test_vendors.py
  5. Update documentation in README.md

  Testing Guidelines

  - Write tests for all new functionality
  - Use pytest fixtures for common setup
  - Mock external API calls
  - Test both success and failure cases
  - Aim for meaningful coverage, not just high numbers

  Documentation

  - Update README.md for user-facing changes
  - Add inline comments for complex logic
  - Include docstrings with parameter descriptions
  - Update configuration examples if adding new options

  Questions?

  If you have questions about contributing, feel free to:
  - Open a https://github.com/mancow2001/FireLens/discussions
  - Ask in an issue

  License

  By contributing to FireLens, you agree that your contributions will be licensed under the LICENSE.
  ```
