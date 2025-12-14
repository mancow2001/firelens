"""
Certificate Manager for FireLens Monitor

Handles CA certificate upload, validation, storage, and bundle generation
for SSL/TLS verification when connecting to firewall APIs.
"""

import logging
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID

LOG = logging.getLogger("firelens.cert_manager")

# Constants
MAX_FILE_SIZE = 1024 * 1024  # 1MB
ALLOWED_EXTENSIONS = {'.pem', '.crt', '.der', '.cer'}
CA_BUNDLE_FILENAME = "ca-bundle.pem"
PEM_CERT_HEADER = b"-----BEGIN CERTIFICATE-----"
PEM_CERT_FOOTER = b"-----END CERTIFICATE-----"


@dataclass
class CertificateInfo:
    """Information about a parsed X.509 certificate"""
    id: str  # SHA256 fingerprint prefix (first 16 chars)
    subject: str
    issuer: str
    not_before: str  # ISO format datetime string
    not_after: str   # ISO format datetime string
    fingerprint_sha256: str
    fingerprint_sha1: str
    serial_number: str
    filename: str
    file_path: str
    is_expired: bool = False
    days_until_expiry: int = 0
    is_ca: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass
class AddCertificateResult:
    """Result of adding certificate(s)"""
    success: bool
    certs_added: int = 0
    certificates: List[CertificateInfo] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.certificates is None:
            self.certificates = []


class CertificateManager:
    """Manages CA certificates for SSL/TLS verification"""

    def __init__(self, certs_dir: str = "./certs"):
        """
        Initialize the certificate manager.

        Args:
            certs_dir: Directory to store certificates (created if doesn't exist)
        """
        self.certs_dir = Path(certs_dir)
        self._ensure_certs_directory()

    def _ensure_certs_directory(self) -> None:
        """Create the certificates directory if it doesn't exist"""
        if not self.certs_dir.exists():
            self.certs_dir.mkdir(parents=True, mode=0o755)
            LOG.info(f"Created certificates directory: {self.certs_dir}")

    def _is_der_format(self, data: bytes) -> bool:
        """
        Detect if certificate data is in DER (binary) format.

        DER certificates start with a SEQUENCE tag (0x30) followed by length encoding.
        PEM certificates start with "-----BEGIN".
        """
        if data.startswith(b"-----BEGIN"):
            return False
        # DER format starts with ASN.1 SEQUENCE tag
        return len(data) > 2 and data[0] == 0x30

    def _convert_der_to_pem(self, der_bytes: bytes) -> bytes:
        """
        Convert DER-encoded certificate to PEM format.

        Args:
            der_bytes: DER-encoded certificate data

        Returns:
            PEM-encoded certificate data

        Raises:
            ValueError: If the data is not a valid DER certificate
        """
        try:
            cert = x509.load_der_x509_certificate(der_bytes, default_backend())
            return cert.public_bytes(serialization.Encoding.PEM)
        except Exception as e:
            raise ValueError(f"Invalid DER certificate: {e}")

    def _extract_certs_from_bundle(self, pem_data: bytes) -> List[bytes]:
        """
        Extract individual certificates from a PEM bundle.

        Args:
            pem_data: PEM data potentially containing multiple certificates

        Returns:
            List of individual PEM-encoded certificates
        """
        certs = []
        # Split on BEGIN CERTIFICATE markers
        pattern = re.compile(
            rb'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)',
            re.DOTALL
        )
        matches = pattern.findall(pem_data)
        for match in matches:
            certs.append(match)
        return certs

    def _parse_certificate(self, pem_bytes: bytes) -> Tuple[x509.Certificate, CertificateInfo]:
        """
        Parse a PEM-encoded certificate and extract information.

        Args:
            pem_bytes: PEM-encoded certificate data

        Returns:
            Tuple of (x509.Certificate object, CertificateInfo)

        Raises:
            ValueError: If the data is not a valid certificate
        """
        try:
            cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
        except Exception as e:
            raise ValueError(f"Invalid PEM certificate: {e}")

        # Calculate fingerprints
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()

        # Format fingerprints with colons for readability
        fingerprint_sha256_formatted = ':'.join(
            fingerprint_sha256[i:i+2] for i in range(0, len(fingerprint_sha256), 2)
        )
        fingerprint_sha1_formatted = ':'.join(
            fingerprint_sha1[i:i+2] for i in range(0, len(fingerprint_sha1), 2)
        )

        # Extract subject and issuer
        subject = self._format_name(cert.subject)
        issuer = self._format_name(cert.issuer)

        # Check if this is a CA certificate
        is_ca = False
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            pass

        # Calculate expiry information
        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc
        is_expired = now > not_after
        days_until_expiry = max(0, (not_after - now).days) if not is_expired else 0

        # Create certificate ID from fingerprint prefix
        cert_id = fingerprint_sha256.replace(':', '')[:16].lower()

        info = CertificateInfo(
            id=cert_id,
            subject=subject,
            issuer=issuer,
            not_before=cert.not_valid_before_utc.isoformat(),
            not_after=not_after.isoformat(),
            fingerprint_sha256=fingerprint_sha256_formatted,
            fingerprint_sha1=fingerprint_sha1_formatted,
            serial_number=format(cert.serial_number, 'X'),
            filename="",  # Set later when saved
            file_path="",  # Set later when saved
            is_expired=is_expired,
            days_until_expiry=days_until_expiry,
            is_ca=is_ca
        )

        return cert, info

    def _format_name(self, name: x509.Name) -> str:
        """Format an X.509 name as a readable string"""
        parts = []
        for attr in name:
            oid_name = attr.oid._name
            if oid_name == 'commonName':
                parts.insert(0, f"CN={attr.value}")
            elif oid_name == 'organizationName':
                parts.append(f"O={attr.value}")
            elif oid_name == 'organizationalUnitName':
                parts.append(f"OU={attr.value}")
            elif oid_name == 'countryName':
                parts.append(f"C={attr.value}")
        return ", ".join(parts) if parts else str(name)

    def _sanitize_filename(self, name: str) -> str:
        """Create a safe filename from a certificate subject"""
        # Extract CN if present
        cn_match = re.search(r'CN=([^,]+)', name)
        if cn_match:
            name = cn_match.group(1)
        # Remove/replace unsafe characters
        safe = re.sub(r'[^\w\-.]', '_', name)
        # Limit length
        return safe[:50] if len(safe) > 50 else safe

    def _generate_cert_filename(self, info: CertificateInfo) -> str:
        """Generate a unique filename for a certificate"""
        safe_name = self._sanitize_filename(info.subject)
        return f"{info.id}_{safe_name}.pem"

    def add_certificate(self, data: bytes, original_filename: str) -> AddCertificateResult:
        """
        Add one or more certificates from uploaded data.

        Args:
            data: Certificate file contents (PEM or DER format)
            original_filename: Original filename for extension detection

        Returns:
            AddCertificateResult with success status and certificate info
        """
        # Validate file size
        if len(data) > MAX_FILE_SIZE:
            return AddCertificateResult(
                success=False,
                error=f"File too large. Maximum size is {MAX_FILE_SIZE // 1024}KB"
            )

        # Validate file extension
        ext = Path(original_filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return AddCertificateResult(
                success=False,
                error=f"Invalid file type '{ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
            )

        # Convert DER to PEM if necessary
        if self._is_der_format(data):
            try:
                data = self._convert_der_to_pem(data)
                LOG.info(f"Converted DER certificate to PEM format")
            except ValueError as e:
                return AddCertificateResult(success=False, error=str(e))

        # Extract individual certificates (handles bundles)
        cert_data_list = self._extract_certs_from_bundle(data)
        if not cert_data_list:
            return AddCertificateResult(
                success=False,
                error="No valid certificates found in file"
            )

        added_certs = []
        errors = []

        for cert_data in cert_data_list:
            try:
                cert, info = self._parse_certificate(cert_data)

                # Generate filename and save
                filename = self._generate_cert_filename(info)
                file_path = self.certs_dir / filename

                # Check if certificate already exists (by fingerprint)
                existing = self._find_cert_by_fingerprint(info.fingerprint_sha256)
                if existing:
                    LOG.info(f"Certificate already exists: {info.subject}")
                    errors.append(f"Certificate '{info.subject}' already exists")
                    continue

                # Write certificate file
                file_path.write_bytes(cert_data)
                os.chmod(file_path, 0o644)

                info.filename = filename
                info.file_path = str(file_path)
                added_certs.append(info)
                LOG.info(f"Added certificate: {info.subject} ({info.id})")

            except ValueError as e:
                errors.append(str(e))
                LOG.warning(f"Failed to parse certificate: {e}")

        # Regenerate CA bundle if any certs were added
        if added_certs:
            self.regenerate_ca_bundle()

        if not added_certs and errors:
            return AddCertificateResult(
                success=False,
                error="; ".join(errors)
            )

        return AddCertificateResult(
            success=True,
            certs_added=len(added_certs),
            certificates=added_certs,
            error="; ".join(errors) if errors else None
        )

    def _find_cert_by_fingerprint(self, fingerprint: str) -> Optional[Path]:
        """Find a certificate file by its fingerprint"""
        # Normalize fingerprint (remove colons, lowercase)
        normalized = fingerprint.replace(':', '').lower()[:16]

        for cert_file in self.certs_dir.glob("*.pem"):
            if cert_file.name == CA_BUNDLE_FILENAME:
                continue
            if cert_file.name.startswith(normalized):
                return cert_file
        return None

    def delete_certificate(self, cert_id: str) -> Tuple[bool, str]:
        """
        Delete a certificate by its ID.

        Args:
            cert_id: Certificate ID (fingerprint prefix)

        Returns:
            Tuple of (success, message)
        """
        # Find the certificate file
        cert_file = None
        for f in self.certs_dir.glob("*.pem"):
            if f.name == CA_BUNDLE_FILENAME:
                continue
            if f.name.startswith(cert_id):
                cert_file = f
                break

        if not cert_file:
            return False, f"Certificate not found: {cert_id}"

        try:
            cert_file.unlink()
            LOG.info(f"Deleted certificate: {cert_file.name}")

            # Regenerate CA bundle
            self.regenerate_ca_bundle()

            return True, f"Certificate deleted successfully"
        except Exception as e:
            LOG.error(f"Failed to delete certificate {cert_id}: {e}")
            return False, f"Failed to delete certificate: {e}"

    def list_certificates(self) -> List[CertificateInfo]:
        """
        List all uploaded certificates.

        Returns:
            List of CertificateInfo for all certificates
        """
        certificates = []

        for cert_file in sorted(self.certs_dir.glob("*.pem")):
            if cert_file.name == CA_BUNDLE_FILENAME:
                continue

            try:
                cert_data = cert_file.read_bytes()
                _, info = self._parse_certificate(cert_data)
                info.filename = cert_file.name
                info.file_path = str(cert_file)
                certificates.append(info)
            except Exception as e:
                LOG.warning(f"Failed to parse certificate {cert_file.name}: {e}")

        return certificates

    def get_certificate(self, cert_id: str) -> Optional[CertificateInfo]:
        """
        Get information about a specific certificate.

        Args:
            cert_id: Certificate ID (fingerprint prefix)

        Returns:
            CertificateInfo or None if not found
        """
        for cert_file in self.certs_dir.glob("*.pem"):
            if cert_file.name == CA_BUNDLE_FILENAME:
                continue
            if cert_file.name.startswith(cert_id):
                try:
                    cert_data = cert_file.read_bytes()
                    _, info = self._parse_certificate(cert_data)
                    info.filename = cert_file.name
                    info.file_path = str(cert_file)
                    return info
                except Exception as e:
                    LOG.warning(f"Failed to parse certificate {cert_file.name}: {e}")
        return None

    def get_certificate_pem(self, cert_id: str) -> Optional[bytes]:
        """
        Get the PEM data for a specific certificate.

        Args:
            cert_id: Certificate ID (fingerprint prefix)

        Returns:
            PEM-encoded certificate data or None if not found
        """
        for cert_file in self.certs_dir.glob("*.pem"):
            if cert_file.name == CA_BUNDLE_FILENAME:
                continue
            if cert_file.name.startswith(cert_id):
                return cert_file.read_bytes()
        return None

    def regenerate_ca_bundle(self) -> Optional[str]:
        """
        Regenerate the combined CA bundle from all certificates.

        Returns:
            Path to the CA bundle, or None if no certificates
        """
        bundle_path = self.certs_dir / CA_BUNDLE_FILENAME

        # Collect all certificate PEM data
        cert_pems = []
        for cert_file in sorted(self.certs_dir.glob("*.pem")):
            if cert_file.name == CA_BUNDLE_FILENAME:
                continue
            cert_pems.append(cert_file.read_bytes())

        if not cert_pems:
            # Remove bundle if no certificates
            if bundle_path.exists():
                bundle_path.unlink()
                LOG.info("Removed empty CA bundle")
            return None

        # Write combined bundle
        bundle_data = b"\n".join(cert_pems)
        bundle_path.write_bytes(bundle_data)
        os.chmod(bundle_path, 0o644)

        LOG.info(f"Regenerated CA bundle with {len(cert_pems)} certificate(s)")
        return str(bundle_path)

    def get_ca_bundle_path(self) -> Optional[str]:
        """
        Get the path to the CA bundle if it exists and has certificates.

        Returns:
            Path to CA bundle, or None if no custom certificates uploaded
        """
        bundle_path = self.certs_dir / CA_BUNDLE_FILENAME
        if bundle_path.exists() and bundle_path.stat().st_size > 0:
            return str(bundle_path)
        return None

    def get_certificate_count(self) -> int:
        """Get the number of uploaded certificates"""
        count = 0
        for cert_file in self.certs_dir.glob("*.pem"):
            if cert_file.name != CA_BUNDLE_FILENAME:
                count += 1
        return count

    def get_certificate_stats(self) -> dict:
        """
        Get statistics about uploaded certificates.

        Returns:
            Dictionary with total, valid, expiring_soon, and expired counts
        """
        certs = self.list_certificates()
        total = len(certs)
        expired = sum(1 for c in certs if c.is_expired)
        expiring_soon = sum(1 for c in certs if not c.is_expired and c.days_until_expiry <= 30)
        valid = total - expired - expiring_soon

        return {
            "total": total,
            "valid": valid,
            "expiring_soon": expiring_soon,
            "expired": expired,
            "ca_bundle_path": self.get_ca_bundle_path()
        }
