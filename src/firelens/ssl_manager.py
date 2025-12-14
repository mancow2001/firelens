#!/usr/bin/env python3
"""
FireLens Monitor - SSL/TLS Certificate Management Module
Handles certificate generation, validation, and management for the web dashboard.
"""
import logging
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_OK = True
except ImportError:
    CRYPTOGRAPHY_OK = False

LOG = logging.getLogger("FireLens.ssl")


class SSLManager:
    """Manages SSL certificates for the FireLens web dashboard."""

    def __init__(self, certs_dir: str):
        """
        Initialize SSL Manager.

        Args:
            certs_dir: Directory for storing certificates
        """
        self.certs_dir = Path(certs_dir)
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.web_cert_path = self.certs_dir / "web_server.crt"
        self.web_key_path = self.certs_dir / "web_server.key"

    def generate_self_signed_cert(
        self,
        hostname: str = "localhost",
        valid_days: int = 365,
        organization: str = "FireLens",
        key_size: int = 4096
    ) -> Tuple[str, str]:
        """
        Generate a self-signed certificate and private key.

        Args:
            hostname: Primary hostname for the certificate
            valid_days: Certificate validity period in days
            organization: Organization name for the certificate
            key_size: RSA key size in bits

        Returns:
            Tuple of (cert_path, key_path)

        Raises:
            RuntimeError: If cryptography library is not available
        """
        if not CRYPTOGRAPHY_OK:
            raise RuntimeError("cryptography library not available - install with: pip install cryptography")

        LOG.info(f"Generating self-signed certificate for {hostname} (valid for {valid_days} days)")

        # Generate RSA private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        # Build certificate subject and issuer
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        # Build Subject Alternative Names
        san_entries = [
            x509.DNSName(hostname),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]

        # Add hostname variations
        if hostname != "localhost":
            san_entries.append(x509.DNSName(f"*.{hostname}"))

        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=valid_days))
            .add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )

        # Write private key
        with open(self.web_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        self.web_key_path.chmod(0o600)  # Restrict key file permissions

        # Write certificate
        with open(self.web_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        self.web_cert_path.chmod(0o644)

        LOG.info(f"Self-signed certificate generated: {self.web_cert_path}")
        return str(self.web_cert_path), str(self.web_key_path)

    def has_valid_certificate(self) -> bool:
        """Check if a valid web server certificate exists."""
        if not self.web_cert_path.exists() or not self.web_key_path.exists():
            return False

        try:
            cert_info = self.get_certificate_info()
            if not cert_info:
                return False

            # Check if certificate has expired
            not_after = cert_info.get('not_after')
            if not_after and isinstance(not_after, datetime):
                if datetime.utcnow() > not_after:
                    LOG.warning("Web server certificate has expired")
                    return False

            return True
        except Exception as e:
            LOG.warning(f"Error validating certificate: {e}")
            return False

    def get_certificate_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the current web server certificate.

        Returns:
            Dictionary with certificate details, or None if not available
        """
        if not CRYPTOGRAPHY_OK:
            return None

        if not self.web_cert_path.exists():
            return None

        try:
            with open(self.web_cert_path, "rb") as f:
                cert_pem = f.read()

            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

            # Extract subject information
            subject_parts = {}
            for attr in cert.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    subject_parts['cn'] = attr.value
                elif attr.oid == NameOID.ORGANIZATION_NAME:
                    subject_parts['o'] = attr.value
                elif attr.oid == NameOID.COUNTRY_NAME:
                    subject_parts['c'] = attr.value

            # Extract issuer information
            issuer_parts = {}
            for attr in cert.issuer:
                if attr.oid == NameOID.COMMON_NAME:
                    issuer_parts['cn'] = attr.value
                elif attr.oid == NameOID.ORGANIZATION_NAME:
                    issuer_parts['o'] = attr.value

            # Check if self-signed
            is_self_signed = cert.subject == cert.issuer

            # Get Subject Alternative Names
            san_list = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    san_list.append(str(name.value))
            except x509.ExtensionNotFound:
                pass

            # Calculate fingerprint
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            fingerprint_formatted = ':'.join(fingerprint[i:i+2].upper() for i in range(0, len(fingerprint), 2))

            # Days until expiry
            days_until_expiry = (cert.not_valid_after_utc.replace(tzinfo=None) - datetime.utcnow()).days

            return {
                'subject': subject_parts,
                'issuer': issuer_parts,
                'common_name': subject_parts.get('cn', ''),
                'organization': subject_parts.get('o', ''),
                'not_before': cert.not_valid_before_utc.replace(tzinfo=None),
                'not_after': cert.not_valid_after_utc.replace(tzinfo=None),
                'serial_number': str(cert.serial_number),
                'fingerprint_sha256': fingerprint_formatted,
                'is_self_signed': is_self_signed,
                'san': san_list,
                'days_until_expiry': days_until_expiry,
                'expiring_soon': days_until_expiry <= 30,
                'expired': days_until_expiry < 0
            }
        except Exception as e:
            LOG.error(f"Error reading certificate info: {e}")
            return None

    def install_certificate(self, cert_pem: str, key_pem: str) -> Tuple[bool, str]:
        """
        Install a new certificate and private key.

        Args:
            cert_pem: Certificate in PEM format
            key_pem: Private key in PEM format

        Returns:
            Tuple of (success, message)
        """
        if not CRYPTOGRAPHY_OK:
            return False, "cryptography library not available"

        # Validate the cert/key pair
        is_valid, error = self.validate_cert_key_pair(cert_pem, key_pem)
        if not is_valid:
            return False, f"Invalid certificate/key pair: {error}"

        try:
            # Backup existing cert if present
            if self.web_cert_path.exists():
                backup_path = self.web_cert_path.with_suffix('.crt.bak')
                self.web_cert_path.rename(backup_path)
                LOG.info(f"Backed up existing certificate to {backup_path}")

            if self.web_key_path.exists():
                backup_path = self.web_key_path.with_suffix('.key.bak')
                self.web_key_path.rename(backup_path)

            # Write new certificate
            with open(self.web_cert_path, "w") as f:
                f.write(cert_pem)
            self.web_cert_path.chmod(0o644)

            # Write new private key
            with open(self.web_key_path, "w") as f:
                f.write(key_pem)
            self.web_key_path.chmod(0o600)

            LOG.info("New SSL certificate installed successfully")
            return True, "Certificate installed successfully"

        except Exception as e:
            LOG.error(f"Error installing certificate: {e}")
            return False, f"Installation failed: {str(e)}"

    def validate_cert_key_pair(self, cert_pem: str, key_pem: str) -> Tuple[bool, str]:
        """
        Validate that a certificate and private key match.

        Args:
            cert_pem: Certificate in PEM format
            key_pem: Private key in PEM format

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not CRYPTOGRAPHY_OK:
            return False, "cryptography library not available"

        try:
            # Load certificate
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode() if isinstance(cert_pem, str) else cert_pem,
                default_backend()
            )

            # Load private key
            key = serialization.load_pem_private_key(
                key_pem.encode() if isinstance(key_pem, str) else key_pem,
                password=None,
                backend=default_backend()
            )

            # Verify public key matches
            cert_public_key = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_public_key = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            if cert_public_key != key_public_key:
                return False, "Certificate and private key do not match"

            # Check certificate validity
            now = datetime.utcnow()
            if now < cert.not_valid_before_utc.replace(tzinfo=None):
                return False, "Certificate is not yet valid"
            if now > cert.not_valid_after_utc.replace(tzinfo=None):
                return False, "Certificate has expired"

            return True, ""

        except ValueError as e:
            return False, f"Invalid PEM format: {str(e)}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def validate_cert_chain(
        self,
        cert_pem: str,
        ca_bundle_path: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Validate certificate against a CA bundle.

        Args:
            cert_pem: Certificate to validate
            ca_bundle_path: Path to CA bundle file

        Returns:
            Tuple of (is_valid, message)
        """
        if not CRYPTOGRAPHY_OK:
            return False, "cryptography library not available"

        if not ca_bundle_path or not Path(ca_bundle_path).exists():
            return True, "No CA bundle provided - skipping chain validation"

        try:
            # Load the certificate
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode() if isinstance(cert_pem, str) else cert_pem,
                default_backend()
            )

            # For self-signed certs, chain validation doesn't apply
            if cert.subject == cert.issuer:
                return True, "Self-signed certificate - chain validation not applicable"

            # Load CA bundle
            ca_certs = []
            with open(ca_bundle_path, "rb") as f:
                ca_data = f.read()

            # Parse multiple certificates from bundle
            pem_start = b"-----BEGIN CERTIFICATE-----"
            pem_end = b"-----END CERTIFICATE-----"

            start_idx = 0
            while True:
                start = ca_data.find(pem_start, start_idx)
                if start == -1:
                    break
                end = ca_data.find(pem_end, start)
                if end == -1:
                    break
                cert_pem_bytes = ca_data[start:end + len(pem_end)]
                try:
                    ca_cert = x509.load_pem_x509_certificate(cert_pem_bytes, default_backend())
                    ca_certs.append(ca_cert)
                except Exception:
                    pass
                start_idx = end + len(pem_end)

            if not ca_certs:
                return False, "No valid CA certificates found in bundle"

            # Check if any CA cert is the issuer
            cert_issuer = cert.issuer
            for ca_cert in ca_certs:
                if ca_cert.subject == cert_issuer:
                    # Verify signature
                    try:
                        ca_cert.public_key().verify(
                            cert.signature,
                            cert.tbs_certificate_bytes,
                            cert.signature_algorithm_parameters
                        )
                        return True, "Certificate chain validated successfully"
                    except Exception:
                        continue

            return False, "Certificate issuer not found in CA bundle"

        except Exception as e:
            return False, f"Chain validation error: {str(e)}"

    def delete_certificate(self) -> Tuple[bool, str]:
        """
        Delete the current certificate and key (to revert to auto-generated).

        Returns:
            Tuple of (success, message)
        """
        try:
            deleted = []
            if self.web_cert_path.exists():
                self.web_cert_path.unlink()
                deleted.append("certificate")
            if self.web_key_path.exists():
                self.web_key_path.unlink()
                deleted.append("private key")

            if deleted:
                LOG.info(f"Deleted SSL {', '.join(deleted)}")
                return True, f"Deleted {', '.join(deleted)}. New self-signed certificate will be generated on restart."
            else:
                return False, "No certificate files found to delete"

        except Exception as e:
            LOG.error(f"Error deleting certificate: {e}")
            return False, f"Error: {str(e)}"
