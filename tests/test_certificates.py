"""
Unit tests for certificate management functionality.

Tests cover:
- Certificate parsing (PEM and DER formats)
- Bundle extraction
- Certificate validation
- CA bundle generation
- File operations
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from firelens.cert_manager import CertificateManager, CertificateInfo, AddCertificateResult


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_certs_dir():
    """Create a temporary directory for certificates"""
    temp_dir = tempfile.mkdtemp(prefix="firelens_test_certs_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def cert_manager(temp_certs_dir):
    """Create a certificate manager with temporary directory"""
    return CertificateManager(temp_certs_dir)


def generate_test_certificate(
    common_name: str = "Test CA", days_valid: int = 365, is_ca: bool = True, expired: bool = False
) -> bytes:
    """Generate a test X.509 certificate in PEM format"""
    # Generate key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # Set validity period
    if expired:
        not_before = datetime.now(timezone.utc) - timedelta(days=days_valid + 1)
        not_after = datetime.now(timezone.utc) - timedelta(days=1)
    else:
        not_before = datetime.now(timezone.utc)
        not_after = datetime.now(timezone.utc) + timedelta(days=days_valid)

    # Build certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )

    cert = builder.sign(key, hashes.SHA256(), default_backend())

    return cert.public_bytes(serialization.Encoding.PEM)


def generate_test_certificate_der(common_name: str = "Test CA DER") -> bytes:
    """Generate a test X.509 certificate in DER format"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )

    cert = builder.sign(key, hashes.SHA256(), default_backend())

    return cert.public_bytes(serialization.Encoding.DER)


# =============================================================================
# Test: Certificate Manager Initialization
# =============================================================================


class TestCertificateManagerInit:
    """Tests for CertificateManager initialization"""

    def test_creates_certs_directory(self, temp_certs_dir):
        """Test that certs directory is created if it doesn't exist"""
        new_dir = Path(temp_certs_dir) / "new_certs"
        assert not new_dir.exists()

        manager = CertificateManager(str(new_dir))
        assert new_dir.exists()
        assert new_dir.is_dir()

    def test_uses_existing_directory(self, temp_certs_dir):
        """Test that existing directory is used"""
        manager = CertificateManager(temp_certs_dir)
        assert Path(temp_certs_dir).exists()


# =============================================================================
# Test: Certificate Format Detection
# =============================================================================


class TestFormatDetection:
    """Tests for certificate format detection"""

    def test_detect_pem_format(self, cert_manager):
        """Test PEM format detection"""
        pem_cert = generate_test_certificate()
        assert not cert_manager._is_der_format(pem_cert)

    def test_detect_der_format(self, cert_manager):
        """Test DER format detection"""
        der_cert = generate_test_certificate_der()
        assert cert_manager._is_der_format(der_cert)

    def test_detect_pem_with_headers(self, cert_manager):
        """Test PEM detection with various headers"""
        pem_data = b"-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
        assert not cert_manager._is_der_format(pem_data)


# =============================================================================
# Test: DER to PEM Conversion
# =============================================================================


class TestDerToPemConversion:
    """Tests for DER to PEM format conversion"""

    def test_convert_valid_der(self, cert_manager):
        """Test successful DER to PEM conversion"""
        der_cert = generate_test_certificate_der("DER Test")
        pem_cert = cert_manager._convert_der_to_pem(der_cert)

        assert pem_cert.startswith(b"-----BEGIN CERTIFICATE-----")
        assert pem_cert.endswith(b"-----END CERTIFICATE-----\n")

    def test_convert_invalid_der(self, cert_manager):
        """Test conversion fails for invalid DER data"""
        with pytest.raises(ValueError, match="Invalid DER certificate"):
            cert_manager._convert_der_to_pem(b"not a certificate")


# =============================================================================
# Test: Bundle Extraction
# =============================================================================


class TestBundleExtraction:
    """Tests for extracting certificates from bundles"""

    def test_extract_single_cert(self, cert_manager):
        """Test extracting a single certificate"""
        pem_cert = generate_test_certificate("Single")
        certs = cert_manager._extract_certs_from_bundle(pem_cert)

        assert len(certs) == 1
        assert b"-----BEGIN CERTIFICATE-----" in certs[0]

    def test_extract_multiple_certs(self, cert_manager):
        """Test extracting multiple certificates from a bundle"""
        cert1 = generate_test_certificate("Cert 1")
        cert2 = generate_test_certificate("Cert 2")
        cert3 = generate_test_certificate("Cert 3")

        bundle = cert1 + b"\n" + cert2 + b"\n" + cert3
        certs = cert_manager._extract_certs_from_bundle(bundle)

        assert len(certs) == 3

    def test_extract_empty_data(self, cert_manager):
        """Test extracting from empty data"""
        certs = cert_manager._extract_certs_from_bundle(b"")
        assert len(certs) == 0

    def test_extract_no_certs(self, cert_manager):
        """Test extracting from data with no certificates"""
        certs = cert_manager._extract_certs_from_bundle(b"random data without certs")
        assert len(certs) == 0


# =============================================================================
# Test: Certificate Parsing
# =============================================================================


class TestCertificateParsing:
    """Tests for certificate parsing and info extraction"""

    def test_parse_valid_certificate(self, cert_manager):
        """Test parsing a valid certificate"""
        pem_cert = generate_test_certificate("Parse Test CA", is_ca=True)
        cert, info = cert_manager._parse_certificate(pem_cert)

        assert cert is not None
        assert info.id is not None
        assert len(info.id) == 16  # Fingerprint prefix
        assert "CN=Parse Test CA" in info.subject
        assert info.is_ca is True
        assert info.is_expired is False
        assert info.days_until_expiry > 0

    def test_parse_non_ca_certificate(self, cert_manager):
        """Test parsing a non-CA certificate"""
        pem_cert = generate_test_certificate("Non-CA Cert", is_ca=False)
        cert, info = cert_manager._parse_certificate(pem_cert)

        assert info.is_ca is False

    def test_parse_expired_certificate(self, cert_manager):
        """Test parsing an expired certificate"""
        pem_cert = generate_test_certificate("Expired CA", expired=True)
        cert, info = cert_manager._parse_certificate(pem_cert)

        assert info.is_expired is True
        assert info.days_until_expiry == 0

    def test_parse_invalid_certificate(self, cert_manager):
        """Test parsing fails for invalid data"""
        with pytest.raises(ValueError, match="Invalid PEM certificate"):
            cert_manager._parse_certificate(b"not a certificate")

    def test_fingerprint_format(self, cert_manager):
        """Test fingerprint formatting"""
        pem_cert = generate_test_certificate()
        cert, info = cert_manager._parse_certificate(pem_cert)

        # SHA256 fingerprint should be 64 hex chars with colons
        assert ":" in info.fingerprint_sha256
        hex_only = info.fingerprint_sha256.replace(":", "")
        assert len(hex_only) == 64

        # SHA1 fingerprint should be 40 hex chars with colons
        hex_only_sha1 = info.fingerprint_sha1.replace(":", "")
        assert len(hex_only_sha1) == 40


# =============================================================================
# Test: Add Certificate
# =============================================================================


class TestAddCertificate:
    """Tests for adding certificates"""

    def test_add_valid_pem_certificate(self, cert_manager):
        """Test adding a valid PEM certificate"""
        pem_cert = generate_test_certificate("Add Test CA")
        result = cert_manager.add_certificate(pem_cert, "test.pem")

        assert result.success is True
        assert result.certs_added == 1
        assert len(result.certificates) == 1
        assert result.error is None

    def test_add_valid_der_certificate(self, cert_manager):
        """Test adding a valid DER certificate (auto-converted)"""
        der_cert = generate_test_certificate_der("DER Add Test")
        result = cert_manager.add_certificate(der_cert, "test.der")

        assert result.success is True
        assert result.certs_added == 1

    def test_add_bundle(self, cert_manager):
        """Test adding a certificate bundle"""
        cert1 = generate_test_certificate("Bundle Cert 1")
        cert2 = generate_test_certificate("Bundle Cert 2")
        bundle = cert1 + b"\n" + cert2

        result = cert_manager.add_certificate(bundle, "bundle.pem")

        assert result.success is True
        assert result.certs_added == 2
        assert len(result.certificates) == 2

    def test_add_duplicate_certificate(self, cert_manager):
        """Test adding the same certificate twice"""
        pem_cert = generate_test_certificate("Duplicate Test")

        result1 = cert_manager.add_certificate(pem_cert, "cert1.pem")
        assert result1.success is True
        assert result1.certs_added == 1

        result2 = cert_manager.add_certificate(pem_cert, "cert2.pem")
        assert result2.success is False or result2.certs_added == 0
        assert "already exists" in (result2.error or "")

    def test_add_file_too_large(self, cert_manager):
        """Test rejection of oversized files"""
        large_data = b"x" * (1024 * 1024 + 1)  # > 1MB
        result = cert_manager.add_certificate(large_data, "large.pem")

        assert result.success is False
        assert "too large" in result.error.lower()

    def test_add_invalid_extension(self, cert_manager):
        """Test rejection of invalid file extensions"""
        pem_cert = generate_test_certificate()
        result = cert_manager.add_certificate(pem_cert, "cert.txt")

        assert result.success is False
        assert "invalid file type" in result.error.lower()

    def test_add_invalid_certificate(self, cert_manager):
        """Test rejection of invalid certificate data"""
        result = cert_manager.add_certificate(b"not a certificate", "invalid.pem")

        assert result.success is False
        assert "no valid certificates" in result.error.lower()


# =============================================================================
# Test: Delete Certificate
# =============================================================================


class TestDeleteCertificate:
    """Tests for deleting certificates"""

    def test_delete_existing_certificate(self, cert_manager):
        """Test deleting an existing certificate"""
        pem_cert = generate_test_certificate("Delete Test")
        result = cert_manager.add_certificate(pem_cert, "delete.pem")
        cert_id = result.certificates[0].id

        success, message = cert_manager.delete_certificate(cert_id)
        assert success is True
        assert "deleted" in message.lower()

        # Verify it's gone
        assert cert_manager.get_certificate(cert_id) is None

    def test_delete_nonexistent_certificate(self, cert_manager):
        """Test deleting a non-existent certificate"""
        success, message = cert_manager.delete_certificate("nonexistent")

        assert success is False
        assert "not found" in message.lower()


# =============================================================================
# Test: List Certificates
# =============================================================================


class TestListCertificates:
    """Tests for listing certificates"""

    def test_list_empty(self, cert_manager):
        """Test listing when no certificates exist"""
        certs = cert_manager.list_certificates()
        assert len(certs) == 0

    def test_list_multiple(self, cert_manager):
        """Test listing multiple certificates"""
        cert_manager.add_certificate(generate_test_certificate("List 1"), "c1.pem")
        cert_manager.add_certificate(generate_test_certificate("List 2"), "c2.pem")
        cert_manager.add_certificate(generate_test_certificate("List 3"), "c3.pem")

        certs = cert_manager.list_certificates()
        assert len(certs) == 3

    def test_list_excludes_ca_bundle(self, cert_manager):
        """Test that CA bundle is not included in list"""
        cert_manager.add_certificate(generate_test_certificate(), "test.pem")

        # CA bundle should be created but not listed
        certs = cert_manager.list_certificates()
        filenames = [c.filename for c in certs]

        assert "ca-bundle.pem" not in filenames


# =============================================================================
# Test: Get Certificate
# =============================================================================


class TestGetCertificate:
    """Tests for getting individual certificate info"""

    def test_get_existing(self, cert_manager):
        """Test getting an existing certificate"""
        result = cert_manager.add_certificate(generate_test_certificate("Get Test"), "test.pem")
        cert_id = result.certificates[0].id

        info = cert_manager.get_certificate(cert_id)
        assert info is not None
        assert "CN=Get Test" in info.subject

    def test_get_nonexistent(self, cert_manager):
        """Test getting a non-existent certificate"""
        info = cert_manager.get_certificate("nonexistent")
        assert info is None


# =============================================================================
# Test: CA Bundle Generation
# =============================================================================


class TestCABundleGeneration:
    """Tests for CA bundle generation"""

    def test_bundle_created_on_add(self, cert_manager, temp_certs_dir):
        """Test that CA bundle is created when cert is added"""
        cert_manager.add_certificate(generate_test_certificate(), "test.pem")

        bundle_path = Path(temp_certs_dir) / "ca-bundle.pem"
        assert bundle_path.exists()

    def test_bundle_contains_all_certs(self, cert_manager, temp_certs_dir):
        """Test that bundle contains all certificates"""
        cert_manager.add_certificate(generate_test_certificate("Bundle A"), "a.pem")
        cert_manager.add_certificate(generate_test_certificate("Bundle B"), "b.pem")

        bundle_path = Path(temp_certs_dir) / "ca-bundle.pem"
        bundle_content = bundle_path.read_text()

        # Should contain 2 certificates
        assert bundle_content.count("-----BEGIN CERTIFICATE-----") == 2

    def test_bundle_removed_when_empty(self, cert_manager, temp_certs_dir):
        """Test that bundle is removed when all certs are deleted"""
        result = cert_manager.add_certificate(generate_test_certificate(), "test.pem")
        cert_id = result.certificates[0].id

        bundle_path = Path(temp_certs_dir) / "ca-bundle.pem"
        assert bundle_path.exists()

        cert_manager.delete_certificate(cert_id)
        assert not bundle_path.exists()

    def test_get_ca_bundle_path(self, cert_manager):
        """Test getting CA bundle path"""
        # No certs - should return None
        assert cert_manager.get_ca_bundle_path() is None

        # Add cert - should return path
        cert_manager.add_certificate(generate_test_certificate(), "test.pem")
        path = cert_manager.get_ca_bundle_path()
        assert path is not None
        assert "ca-bundle.pem" in path


# =============================================================================
# Test: Certificate Statistics
# =============================================================================


class TestCertificateStatistics:
    """Tests for certificate statistics"""

    def test_stats_empty(self, cert_manager):
        """Test stats with no certificates"""
        stats = cert_manager.get_certificate_stats()
        assert stats["total"] == 0
        assert stats["valid"] == 0
        assert stats["expiring_soon"] == 0
        assert stats["expired"] == 0
        assert stats["ca_bundle_path"] is None

    def test_stats_with_certs(self, cert_manager):
        """Test stats with various certificates"""
        # Add a valid cert
        cert_manager.add_certificate(
            generate_test_certificate("Valid", days_valid=365), "valid.pem"
        )
        # Add an expiring cert (within 30 days)
        cert_manager.add_certificate(
            generate_test_certificate("Expiring", days_valid=15), "expiring.pem"
        )
        # Add an expired cert
        cert_manager.add_certificate(
            generate_test_certificate("Expired", expired=True), "expired.pem"
        )

        stats = cert_manager.get_certificate_stats()
        assert stats["total"] == 3
        assert stats["valid"] == 1
        assert stats["expiring_soon"] == 1
        assert stats["expired"] == 1
        assert stats["ca_bundle_path"] is not None


# =============================================================================
# Test: Certificate Count
# =============================================================================


class TestCertificateCount:
    """Tests for certificate counting"""

    def test_count_empty(self, cert_manager):
        """Test count with no certificates"""
        assert cert_manager.get_certificate_count() == 0

    def test_count_multiple(self, cert_manager):
        """Test count with multiple certificates"""
        cert_manager.add_certificate(generate_test_certificate("C1"), "c1.pem")
        cert_manager.add_certificate(generate_test_certificate("C2"), "c2.pem")

        assert cert_manager.get_certificate_count() == 2


# =============================================================================
# Test: CertificateInfo Serialization
# =============================================================================


class TestCertificateInfoSerialization:
    """Tests for CertificateInfo serialization"""

    def test_to_dict(self, cert_manager):
        """Test CertificateInfo.to_dict()"""
        result = cert_manager.add_certificate(generate_test_certificate(), "test.pem")
        info = result.certificates[0]

        d = info.to_dict()
        assert isinstance(d, dict)
        assert "id" in d
        assert "subject" in d
        assert "fingerprint_sha256" in d
        assert "is_expired" in d


# =============================================================================
# Test: AddCertificateResult
# =============================================================================


class TestAddCertificateResult:
    """Tests for AddCertificateResult dataclass"""

    def test_success_result(self):
        """Test successful result"""
        result = AddCertificateResult(success=True, certs_added=1)
        assert result.success is True
        assert result.certs_added == 1
        assert result.certificates == []
        assert result.error is None

    def test_failure_result(self):
        """Test failure result"""
        result = AddCertificateResult(success=False, error="Test error")
        assert result.success is False
        assert result.error == "Test error"
