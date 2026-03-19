#!/usr/bin/env python3
"""SSL/TLS security analyzer.

Checks certificate expiry, TLS version, cipher strength, and risk level.
Uses stdlib only (ssl, socket, datetime).

Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import ssl
from datetime import datetime, timezone

logger = logging.getLogger("ssl_analyzer")


def get_certificate(hostname: str, port: int = 443, timeout: int = 10) -> dict | None:
    """Get SSL certificate and connection details.

    Returns dict with certificate, tls_version, cipher_suite, or None on failure.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_dict = ssock.getpeercert()
                tls_version = ssock.version()
                cipher = ssock.cipher()

                not_before = datetime.strptime(
                    cert_dict["notBefore"], "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)

                not_after = datetime.strptime(
                    cert_dict["notAfter"], "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)

                has_expired = datetime.now(timezone.utc) > not_after

                subject = dict(x[0] for x in cert_dict.get("subject", []))
                issuer = dict(x[0] for x in cert_dict.get("issuer", []))

                sans = [
                    entry[1]
                    for entry in cert_dict.get("subjectAltName", [])
                    if entry[0] == "DNS"
                ]

                return {
                    "certificate": {
                        "subject": subject,
                        "issuer": issuer,
                        "serial_number": cert_dict.get("serialNumber", ""),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "version": cert_dict.get("version", 0),
                        "has_expired": has_expired,
                        "subject_alt_names": sans,
                    },
                    "tls_version": tls_version,
                    "cipher_suite": {
                        "name": cipher[0] if cipher else None,
                        "protocol": cipher[1] if cipher else None,
                        "bits": cipher[2] if cipher else None,
                    },
                }

    except ssl.SSLError as e:
        logger.warning(f"SSL error for {hostname}: {e}")
    except socket.timeout:
        logger.warning(f"Connection timeout for {hostname}")
    except Exception as e:
        logger.error(f"Certificate retrieval error for {hostname}: {e}")
    return None


def analyze_certificate_security(cert_info: dict) -> list[dict]:
    """Analyze certificate for security issues."""
    issues = []
    cert = cert_info["certificate"]

    not_after = datetime.fromisoformat(cert["not_after"])
    days_until_expiry = (not_after - datetime.now(timezone.utc)).days

    if cert["has_expired"]:
        issues.append({
            "type": "EXPIRED_CERTIFICATE",
            "severity": "CRITICAL",
            "message": f"Certificate expired on {cert['not_after']}",
        })
    elif days_until_expiry < 30:
        issues.append({
            "type": "EXPIRING_SOON",
            "severity": "HIGH",
            "message": f"Certificate expires in {days_until_expiry} days",
        })
    elif days_until_expiry < 90:
        issues.append({
            "type": "EXPIRING_SOON",
            "severity": "MEDIUM",
            "message": f"Certificate expires in {days_until_expiry} days",
        })

    tls_version = cert_info.get("tls_version", "")
    if tls_version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
        issues.append({
            "type": "OUTDATED_TLS",
            "severity": "HIGH",
            "message": f"Outdated TLS version: {tls_version}",
        })

    cipher = cert_info.get("cipher_suite", {})
    if cipher.get("bits", 256) < 128:
        issues.append({
            "type": "WEAK_CIPHER",
            "severity": "CRITICAL",
            "message": f"Weak cipher strength: {cipher.get('bits')} bits",
        })

    sans = cert.get("subject_alt_names", [])
    if any("*" in san for san in sans):
        issues.append({
            "type": "WILDCARD_CERT",
            "severity": "LOW",
            "message": "Wildcard certificate detected (increases attack surface)",
        })

    return issues


def calculate_risk_level(issues: list[dict]) -> str:
    """Calculate overall risk level from security issues."""
    if not issues:
        return "LOW"
    severities = [issue["severity"] for issue in issues]
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    return "LOW"


def analyze_ssl(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    """Comprehensive SSL/TLS analysis for a hostname."""
    result = {
        "hostname": hostname,
        "port": port,
        "certificate": None,
        "tls_version": None,
        "cipher_suite": None,
        "security_issues": [],
        "risk_level": "LOW",
    }

    try:
        cert_info = get_certificate(hostname, port, timeout)

        if cert_info:
            result["certificate"] = cert_info["certificate"]
            result["tls_version"] = cert_info["tls_version"]
            result["cipher_suite"] = cert_info["cipher_suite"]

            security_issues = analyze_certificate_security(cert_info)
            result["security_issues"] = security_issues
            result["risk_level"] = calculate_risk_level(security_issues)
        else:
            result["security_issues"].append({
                "type": "CONNECTION_FAILED",
                "severity": "HIGH",
                "message": "Could not establish SSL/TLS connection",
            })
            result["risk_level"] = "HIGH"

    except Exception as e:
        logger.error(f"SSL analysis error for {hostname}: {e}")
        result["error"] = str(e)
        result["security_issues"].append({
            "type": "ANALYSIS_ERROR",
            "severity": "MEDIUM",
            "message": str(e),
        })

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze SSL/TLS certificate security")
    parser.add_argument("--domain", required=True, help="Domain to analyze")
    parser.add_argument("--port", type=int, default=443, help="Port (default: 443)")
    args = parser.parse_args()

    print(json.dumps(analyze_ssl(args.domain, args.port), indent=2))
