"""
Tool A: Vulnerability & Security Header / Port Scanner.
Audits web targets for critical HTTP security headers, server banner disclosures,
cookie security flags, and common exposed ports.
"""

import socket
import ssl
import urllib.parse
import requests
from typing import Dict, Any, List

COMMON_PORTS = {
    80: ("HTTP", "Standard Web Traffic"),
    443: ("HTTPS", "Encrypted Web Traffic"),
    8080: ("HTTP-Alt", "Web Proxy / Alternate Web Server"),
    8443: ("HTTPS-Alt", "Secure Alternate Web Server"),
    21: ("FTP", "File Transfer Protocol (Cleartext)"),
    22: ("SSH", "Secure Shell Remote Access"),
    3306: ("MySQL", "Database Port (Should NOT be public)")
}

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Enforces secure HTTPS connections and prevents SSL stripping attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' in web server config."
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Mitigates Cross-Site Scripting (XSS) and data injection vulnerabilities.",
        "remediation": "Define a strict CSP header e.g. \"Content-Security-Policy: default-src 'self'; script-src 'self'\"."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Protects against Clickjacking attacks by forbidding framing.",
        "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME-sniffing attacks causing browsers to interpret non-scripts as scripts.",
        "remediation": "Set 'X-Content-Type-Options: nosniff'."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer information is sent with requests.",
        "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin'."
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Restricts browser features like camera, microphone, geolocation.",
        "remediation": "Configure 'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
    }
}

def scan_target(target: str) -> Dict[str, Any]:
    """Execute complete security header, cookie, and port audit on a target endpoint."""
    cleaned_target = target.strip()
    if not cleaned_target:
        return {"error": "Target input cannot be empty."}

    # Normalize URL
    if not cleaned_target.startswith(("http://", "https://")):
        url = f"https://{cleaned_target}"
    else:
        url = cleaned_target

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or cleaned_target
    
    result = {
        "target": target,
        "url": url,
        "hostname": hostname,
        "is_https": url.startswith("https://"),
        "headers_found": {},
        "headers_missing": {},
        "server_banner": None,
        "x_powered_by": None,
        "cookie_flags": [],
        "open_ports": [],
        "issues": [],
        "security_score": 100,
        "status_code": None
    }

    # 1. HTTP Request & Header Inspection
    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "CyberSOC-Vulnerability-Scanner/2.0"})
        response = session.get(url, timeout=6, allow_redirects=True, verify=False)
        result["status_code"] = response.status_code
        resp_headers = response.headers

        # Check recommended headers
        for header, meta in RECOMMENDED_HEADERS.items():
            if header in resp_headers:
                result["headers_found"][header] = resp_headers[header]
            else:
                result["headers_missing"][header] = meta
                penalty = 15 if meta["severity"] == "HIGH" else (10 if meta["severity"] == "MEDIUM" else 5)
                result["security_score"] -= penalty
                result["issues"].append({
                    "type": "Missing Header",
                    "item": header,
                    "severity": meta["severity"],
                    "description": meta["description"],
                    "remediation": meta["remediation"]
                })

        # Server banner disclosure check
        if "Server" in resp_headers:
            result["server_banner"] = resp_headers["Server"]
            result["security_score"] -= 5
            result["issues"].append({
                "type": "Information Disclosure",
                "item": "Server Header Exposed",
                "severity": "LOW",
                "description": f"Server revealed version/architecture: '{resp_headers['Server']}'.",
                "remediation": "Mask or disable the 'Server' header tokens in your web server configuration."
            })

        if "X-Powered-By" in resp_headers:
            result["x_powered_by"] = resp_headers["X-Powered-By"]
            result["security_score"] -= 8
            result["issues"].append({
                "type": "Information Disclosure",
                "item": "X-Powered-By Header Exposed",
                "severity": "MEDIUM",
                "description": f"Backend technology disclosed: '{resp_headers['X-Powered-By']}'.",
                "remediation": "Remove the X-Powered-By response header in backend framework configs."
            })

        # Cookie security flags check
        if response.cookies:
            for cookie in response.cookies:
                is_secure = cookie.secure
                is_httponly = cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly')
                flags = {
                    "name": cookie.name,
                    "secure": is_secure,
                    "httponly": is_httponly,
                }
                result["cookie_flags"].append(flags)
                if not is_secure and result["is_https"]:
                    result["security_score"] -= 5
                    result["issues"].append({
                        "type": "Insecure Cookie",
                        "item": f"Cookie '{cookie.name}' missing 'Secure' flag",
                        "severity": "MEDIUM",
                        "description": "Cookie can be intercepted over unencrypted HTTP channels.",
                        "remediation": "Add 'Secure' attribute to all session cookies."
                    })
                if not is_httponly:
                    result["security_score"] -= 5
                    result["issues"].append({
                        "type": "Insecure Cookie",
                        "item": f"Cookie '{cookie.name}' missing 'HttpOnly' flag",
                        "severity": "MEDIUM",
                        "description": "Cookie is accessible via client-side JavaScript, increasing XSS session theft risk.",
                        "remediation": "Add 'HttpOnly' attribute to session cookies."
                    })

    except requests.exceptions.RequestException as e:
        result["connection_error"] = str(e)
        result["issues"].append({
            "type": "Connection Failure",
            "item": "HTTP Endpoint Unreachable",
            "severity": "HIGH",
            "description": f"Could not establish HTTP connection to {url}: {e}",
            "remediation": "Check whether the target domain/IP is active, online, and accessible."
        })
        result["security_score"] -= 30

    # 2. Fast Non-blocking Port Probe
    try:
        ip = socket.gethostbyname(hostname)
        result["resolved_ip"] = ip
        for port, (service, desc) in COMMON_PORTS.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.35)
            status = s.connect_ex((ip, port))
            s.close()
            if status == 0:
                result["open_ports"].append({
                    "port": port,
                    "service": service,
                    "description": desc
                })
                # Check for sensitive exposed ports
                if port == 3306:
                    result["security_score"] -= 20
                    result["issues"].append({
                        "type": "Critical Port Exposure",
                        "item": "MySQL Database Port 3306 Open Publicly",
                        "severity": "CRITICAL",
                        "description": "Direct database port is accessible from the public internet.",
                        "remediation": "Bind MySQL to 127.0.0.1 or configure firewall rules/VPC security groups."
                    })
                elif port == 21:
                    result["security_score"] -= 10
                    result["issues"].append({
                        "type": "Exposed Legacy Protocol",
                        "item": "Cleartext FTP Port 21 Open",
                        "severity": "HIGH",
                        "description": "FTP sends credentials and data in cleartext.",
                        "remediation": "Migrate to SFTP (over SSH) and close port 21."
                    })
    except Exception as e:
        result["dns_error"] = str(e)

    # Clamp score between 0 and 100
    result["security_score"] = max(0, min(100, result["security_score"]))
    
    # Severity rating
    score = result["security_score"]
    if score >= 85:
        result["rating"] = "SECURE / EXCELLENT"
        result["badge_color"] = "#00f5a0"
    elif score >= 65:
        result["rating"] = "MODERATE / NEEDS ATTENTION"
        result["badge_color"] = "#ffb703"
    elif score >= 45:
        result["rating"] = "ELEVATED VULNERABILITY"
        result["badge_color"] = "#fb8500"
    else:
        result["rating"] = "CRITICAL RISK / SEVERELY EXPOSED"
        result["badge_color"] = "#ff0055"

    return result
