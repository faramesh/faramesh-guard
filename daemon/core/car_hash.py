"""
CAR Canonicalization and Hashing.

Implements deterministic CAR identity:
1. Canonical JSON serialization (sorted keys, no whitespace)
2. SHA256 hashing
3. Identity fields only (tool, operation, target_kind, target)

This ensures same action always produces same car_hash.
"""

import hashlib
import json
import os
import sys
import urllib.parse
from typing import Dict, Any


def canonicalize_path(path: str) -> str:
    """
    Normalize filesystem paths to canonical form.

    Rules:
    1. Resolve symlinks
    2. Absolute path
    3. Expand ~ and env vars
    4. Normalize separators (/ only)
    5. Remove trailing slash
    6. Case normalization (macOS/Windows)
    """
    # Expand user home and environment variables
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)

    # Convert to absolute path
    path = os.path.abspath(path)

    # Resolve symlinks
    try:
        path = os.path.realpath(path)
    except (OSError, ValueError):
        # Path may not exist yet
        pass

    # Normalize separators
    path = path.replace("\\", "/")

    # Remove trailing slash
    path = path.rstrip("/")

    # Case normalization (macOS/Windows are case-insensitive)
    if sys.platform in ["darwin", "win32"]:
        path = path.lower()

    return path


def canonicalize_url(url: str) -> str:
    """
    Normalize URLs to canonical form.

    Rules:
    1. Scheme lowercase
    2. Domain lowercase + punycode decode
    3. Remove default ports
    4. Path normalization
    5. Sort query params
    6. Remove fragment
    """
    parsed = urllib.parse.urlparse(url)

    # Scheme lowercase
    scheme = parsed.scheme.lower()

    # Domain lowercase + punycode
    domain = parsed.netloc.lower()
    if domain.startswith("xn--"):
        try:
            domain = domain.encode("ascii").decode("idna")
        except Exception:
            pass  # Keep original if decode fails

    # Remove default ports
    if ":" in domain:
        host, port = domain.rsplit(":", 1)
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            domain = host

    # Path normalization
    path = parsed.path or "/"
    path = urllib.parse.quote(urllib.parse.unquote(path))

    # Sort query params
    if parsed.query:
        params = sorted(parsed.query.split("&"))
        query = "&".join(params)
    else:
        query = ""

    # Reconstruct URL (without fragment)
    canonical = f"{scheme}://{domain}{path}"
    if query:
        canonical += f"?{query}"

    return canonical


def canonicalize_email(email: str) -> str:
    """
    Normalize email addresses to canonical form.

    Rules:
    1. Lowercase
    2. Gmail: ignore dots and +aliases
    3. Punycode domain decode
    """
    email = email.lower()

    if "@" not in email:
        return email

    local, domain = email.split("@", 1)

    # Gmail normalization
    if domain == "gmail.com":
        # Remove +alias
        if "+" in local:
            local = local.split("+")[0]
        # Remove dots
        local = local.replace(".", "")

    # Punycode domain
    if domain.startswith("xn--"):
        try:
            domain = domain.encode("ascii").decode("idna")
        except Exception:
            pass

    return f"{local}@{domain}"


def canonicalize_car(car: Dict[str, Any]) -> Dict[str, Any]:
    """
    Canonicalize CAR to deterministic form for hashing.

    Only identity fields are included:
    - tool (lowercase)
    - operation (lowercase)
    - target_kind
    - target (normalized)
    """
    canonical = {
        "tool": car.get("tool", "").lower(),
        "operation": car.get("operation", "").lower(),
        "target_kind": car.get("target_kind", "generic"),
        "target": car.get("target", ""),
    }

    # Normalize target based on target_kind
    target = canonical["target"]
    target_kind = canonical["target_kind"]

    if target_kind == "path":
        canonical["target"] = canonicalize_path(target)
    elif target_kind == "url":
        canonical["target"] = canonicalize_url(target)
    elif target_kind == "email":
        canonical["target"] = canonicalize_email(target)
    # For "generic", "money", etc. - keep as-is

    return canonical


def compute_car_hash(car: Dict[str, Any]) -> str:
    """
    Compute deterministic SHA256 hash of CAR.

    This hash is the action's identity for:
    - Permit binding (prevents replay attacks)
    - Audit trail
    - Duplicate detection

    Args:
        car: Action record

    Returns:
        Hex-encoded SHA256 hash (64 characters)
    """
    canonical = canonicalize_car(car)

    # Canonical JSON (sorted keys, no whitespace)
    canonical_json = json.dumps(canonical, sort_keys=True, separators=(",", ":"))

    # SHA256 hash
    hash_bytes = hashlib.sha256(canonical_json.encode("utf-8")).digest()

    return hash_bytes.hex()
