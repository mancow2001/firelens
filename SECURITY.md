  ---
  # Security Policy

  ## Supported Versions

  We release security patches for the following versions:

  | Version | Supported          |
  | ------- | ------------------ |
  | 1.0.x   | :white_check_mark: |
  | < 1.0   | :x:                |

  ## Reporting a Vulnerability

  **Please do not report security vulnerabilities through public GitHub issues.**

  If you discover a security vulnerability in FireLens, please report it privately by emailing the maintainers directly. Include the following information:

  - Description of the vulnerability
  - Steps to reproduce
  - Potential impact
  - Any suggested fixes (optional)

  You should receive an initial response within 48 hours acknowledging receipt. We will work with you to understand the issue and develop a fix.

  ## Security Features

  FireLens includes several built-in security features:

  ### Authentication & Session Management
  - **Bcrypt password hashing** (12 rounds) for stored credentials
  - **Secure session management** with absolute timeout (8 hours)
  - **SAML/SSO support** for enterprise identity providers
  - **Rate limiting** on login endpoints (5 requests/minute)

  ### Transport Security
  - **Native SSL/TLS support** enabled by default (port 8443)
  - **Auto-generated self-signed certificates** on first startup
  - **HTTP to HTTPS redirect** (port 8080 → 8443)
  - **Minimum TLS 1.2** enforced
  - **Custom certificate upload** via admin UI

  ### Application Security
  - **CSRF protection** on all state-changing operations
  - **Security headers**: X-Frame-Options, Content-Security-Policy, X-Content-Type-Options
  - **XXE protection** via defusedxml library
  - **Input validation** on all user-supplied data

  ### Credential Management
  - **Random secure password** generated during installation
  - **Password complexity requirements** enforced on change
  - **API credentials** stored in protected configuration files
  - **No credentials in logs** - sensitive data is sanitized

  ## Security Best Practices

  When deploying FireLens, we recommend:

  ### Network Security
  ```yaml
  # config.yaml
  firewalls:
    example_fw:
      verify_ssl: true  # Enable SSL verification in production

  - Deploy behind a reverse proxy (nginx, Traefik) for additional TLS termination
  - Restrict network access to the management interface
  - Use firewall rules to limit access to FireLens ports (8443, 8080)
  - Place FireLens on a management network separate from production traffic

  Firewall API Permissions

  Create dedicated monitoring accounts with minimal read-only permissions:

  Palo Alto Networks:
  - show system resources (read-only)
  - show running resource-monitor (read-only)
  - show session info (read-only)

  Fortinet FortiGate:
  - Use API tokens with read-only access
  - Limit token scope to monitoring endpoints

  Cisco Firepower:
  - Create dedicated API user with read-only role
  - For FMC, limit access to specific managed devices

  Configuration Security

  # Protect configuration file
  chmod 600 /etc/firelens/config.yaml
  chown firelens:firelens /etc/firelens/config.yaml

  - Store config.yaml with restrictive permissions (600)
  - Use environment variables for sensitive values when possible
  - Regularly rotate API credentials and tokens
  - Back up configuration securely

  SSL/TLS Configuration

  # config.yaml
  global:
    web_ssl:
      enabled: true
      min_tls_version: "TLSv1.2"
      redirect_http_to_https: true

  - Replace auto-generated certificates with CA-signed certificates in production
  - Monitor certificate expiration via the admin UI
  - Use strong cipher suites

  Docker Deployments

  # docker-compose.yml security additions
  services:
    firelens:
      read_only: true
      security_opt:
        - no-new-privileges:true
      tmpfs:
        - /tmp

  - Run container as non-root user
  - Use read-only filesystem where possible
  - Limit container capabilities
  - Scan images for vulnerabilities

  Known Security Considerations

  Self-Signed Certificates

  The auto-generated self-signed certificate is intended for initial setup and testing. For production:
  - Upload a CA-signed certificate via Admin → SSL/TLS Certificates
  - Or use a reverse proxy with proper TLS termination

  Database Security

  SQLite database contains firewall metrics but no credentials:
  - Database path is configurable (database_path in config.yaml)
  - Ensure database file has restrictive permissions
  - Consider encryption at rest for sensitive environments

  Log Files

  FireLens sanitizes sensitive data from logs, but review log configurations:
  - Set appropriate log levels in production (INFO or WARNING)
  - Restrict access to log files
  - Implement log rotation

  Vulnerability Disclosure Timeline

  1. Day 0: Vulnerability reported
  2. Day 1-2: Initial acknowledgment
  3. Day 3-14: Investigation and fix development
  4. Day 15-30: Testing and validation
  5. Day 30+: Coordinated public disclosure with fix release

  We aim to release security patches within 30 days of confirmed vulnerabilities. Critical issues may receive expedited patches.

  Security Updates

  Security updates are announced through:
  - GitHub Releases (tagged with security)
  - GitHub Security Advisories

  Subscribe to releases to receive notifications:
  1. Go to the https://github.com/mancow2001/FireLens
  2. Click "Watch" → "Custom" → Select "Releases"

  Acknowledgments

  We thank the security researchers who have responsibly disclosed vulnerabilities to help improve FireLens security.
  ```
