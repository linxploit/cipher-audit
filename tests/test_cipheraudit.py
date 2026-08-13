"""
Unit tests for CipherAudit.

Most tests exercise pure logic (target parsing, risk analysis) with no
network access required. A few integration tests hit badssl.com over a
real TLS connection to validate the certificate-parsing fix end-to-end;
these are skipped automatically if the network is unavailable.

Run with:
    python3 -m unittest discover -s tests
"""

import os
import socket
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cipheraudit as ca  # noqa: E402


def network_available(host="badssl.com", port=443, timeout=3) -> bool:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


NETWORK_UP = network_available()


class TestParseTarget(unittest.TestCase):

    def test_plain_host(self):
        self.assertEqual(ca.parse_target("example.com"), ("example.com", 443))

    def test_host_with_port(self):
        self.assertEqual(ca.parse_target("example.com:8443"), ("example.com", 8443))

    def test_strips_scheme_and_path(self):
        self.assertEqual(ca.parse_target("https://example.com/path"), ("example.com", 443))

    def test_invalid_port_falls_back_to_443(self):
        self.assertEqual(ca.parse_target("example.com:notaport"), ("example.com", 443))


class TestRiskAnalysis(unittest.TestCase):

    def test_expired_cert_is_critical(self):
        cert = ca.CertificateInfo(days_remaining=-5)
        findings = ca.analyze_findings(cert, {}, {})
        self.assertTrue(any(f.severity == "CRITICAL" and "EXPIRED" in f.issue for f in findings))

    def test_expiring_soon_is_high(self):
        cert = ca.CertificateInfo(days_remaining=15)
        findings = ca.analyze_findings(cert, {}, {})
        self.assertTrue(any(f.severity == "HIGH" for f in findings))

    def test_weak_rsa_key_flagged(self):
        cert = ca.CertificateInfo(key_type="RSA", key_size=1024)
        findings = ca.analyze_findings(cert, {}, {})
        self.assertTrue(any("1024" in f.issue for f in findings))

    def test_strong_rsa_key_not_flagged(self):
        cert = ca.CertificateInfo(key_type="RSA", key_size=2048)
        findings = ca.analyze_findings(cert, {}, {})
        self.assertFalse(any("RSA key size" in f.issue for f in findings))

    def test_weak_signature_algorithm_flagged(self):
        cert = ca.CertificateInfo(signature_algorithm="sha1")
        findings = ca.analyze_findings(cert, {}, {})
        self.assertTrue(any("weak signature" in f.issue.lower() for f in findings))

    def test_self_signed_flagged_medium(self):
        cert = ca.CertificateInfo(self_signed_heuristic=True)
        findings = ca.analyze_findings(cert, {}, {})
        self.assertTrue(any(f.severity == "MEDIUM" and "self-signed" in f.issue.lower() for f in findings))

    def test_untrusted_cert_flagged_high(self):
        cert = ca.CertificateInfo(trust_validated=False, trust_error="hostname mismatch")
        findings = ca.analyze_findings(cert, {}, {})
        self.assertTrue(any(f.severity == "HIGH" and "trust validation" in f.issue for f in findings))

    def test_sslv3_supported_is_critical(self):
        protocols = {"SSLv3": ca.ProtocolResult(True, "negotiated")}
        findings = ca.analyze_findings(None, protocols, {})
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))

    def test_tlsv10_supported_is_high(self):
        protocols = {"TLSv1.0": ca.ProtocolResult(True, "negotiated")}
        findings = ca.analyze_findings(None, protocols, {})
        self.assertTrue(any(f.severity == "HIGH" and "TLSv1.0" in f.issue for f in findings))

    def test_missing_hsts_flagged(self):
        findings = ca.analyze_findings(None, {}, {"Strict-Transport-Security": None})
        self.assertTrue(any("HSTS" in f.issue for f in findings))

    def test_present_hsts_not_flagged(self):
        findings = ca.analyze_findings(None, {}, {"Strict-Transport-Security": "max-age=31536000"})
        self.assertFalse(any("HSTS" in f.issue for f in findings))

    def test_healthy_cert_and_protocols_minimal_findings(self):
        cert = ca.CertificateInfo(
            days_remaining=200, key_type="RSA", key_size=2048,
            signature_algorithm="sha256", trust_validated=True,
        )
        protocols = {
            "TLSv1.2": ca.ProtocolResult(True, "ok"),
            "TLSv1.3": ca.ProtocolResult(True, "ok"),
        }
        headers = {h: "present" for h in ca.SECURITY_HEADER_NAMES}
        findings = ca.analyze_findings(cert, protocols, headers)
        self.assertEqual(len([f for f in findings if f.severity in ("CRITICAL", "HIGH")]), 0)


class TestScanResultAggregation(unittest.TestCase):

    def test_worst_severity_picks_most_severe(self):
        result = ca.ScanResult(host="x", port=443)
        result.findings = [ca.Finding("LOW", "a"), ca.Finding("CRITICAL", "b")]
        self.assertEqual(result.worst_severity, "CRITICAL")

    def test_error_reported_as_error(self):
        result = ca.ScanResult(host="x", port=443, error="failed")
        self.assertEqual(result.worst_severity, "ERROR")

    def test_no_findings_is_info(self):
        result = ca.ScanResult(host="x", port=443)
        self.assertEqual(result.worst_severity, "INFO")


@unittest.skipUnless(NETWORK_UP, "network access to badssl.com not available in this environment")
class TestLiveCertificateParsing(unittest.TestCase):
    """Validates the fix for the original script's core bug: getpeercert()
    returns an empty dict when verify_mode is CERT_NONE, so certificate
    details must come from parsing the raw DER bytes instead."""

    def test_certificate_fields_are_populated(self):
        der = ca.fetch_certificate_der("badssl.com", 443, timeout=8)
        cert = ca.parse_certificate(der)
        self.assertIsNone(cert.error)
        self.assertIsNotNone(cert.subject)
        self.assertIsNotNone(cert.not_after)
        self.assertIsNotNone(cert.fingerprint_sha256)
        self.assertEqual(len(cert.fingerprint_sha256), 64)  # hex-encoded SHA-256


if __name__ == "__main__":
    unittest.main()
