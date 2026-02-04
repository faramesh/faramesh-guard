"""
Faramesh Guard - Production Configuration

Central configuration for all Guard cloud services.
Replace placeholder values with your production credentials.

Environment Variables Required:
  GUARD_INGEST_URL        - Cloudflare Worker URL for telemetry/heartbeats
  GUARD_ENROLL_URL        - Cloudflare Worker URL for device enrollment
  GUARD_SUPPORT_URL       - Cloudflare Worker URL for support bundle uploads
  GUARD_ARTIFACT_BASE_URL - GitHub Releases or R2 URL for binary artifacts
  GUARD_TUF_METADATA_URL  - TUF metadata repository URL
  GUARD_AUTH_TOKEN        - API authentication token (keep secret!)
  GUARD_INSTANCE_ID       - Unique instance identifier (auto-generated if not set)
"""

import os
import hashlib
import platform
import uuid
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
import logging

logger = logging.getLogger("guard.config")

# =============================================================================
# PRODUCTION ENDPOINTS - Replace with your real URLs
# =============================================================================

# Control Plane (Pull - TUF signed files)
ARTIFACT_BASE_URL = os.getenv(
    "GUARD_ARTIFACT_BASE_URL",
    "https://github.com/faramesh/guard/releases/download"  # GitHub Releases
    # OR: "https://artifacts.faramesh.dev/guard"  # R2 bucket with custom domain
)

TUF_METADATA_URL = os.getenv(
    "GUARD_TUF_METADATA_URL",
    "https://updates.faramesh.dev/guard/v1"  # TUF repository
)

# Data Plane (Push - Cloudflare Workers)
INGEST_URL = os.getenv(
    "GUARD_INGEST_URL",
    "https://guard-ingest.faramesh.workers.dev"  # LIVE: Telemetry + heartbeats
)

ENROLL_URL = os.getenv(
    "GUARD_ENROLL_URL",
    "https://guard-enroll.faramesh.workers.dev"  # LIVE: Device enrollment
)

SUPPORT_URL = os.getenv(
    "GUARD_SUPPORT_URL",
    "https://guard-support.faramesh.workers.dev"  # LIVE: Support bundle uploads
)

HEARTBEAT_URL = os.getenv(
    "GUARD_HEARTBEAT_URL",
    f"{INGEST_URL}/heartbeat"  # Heartbeat endpoint (part of ingest)
)

# Authentication
AUTH_TOKEN = os.getenv("GUARD_AUTH_TOKEN", "")  # Keep this secret!

# Instance identification
def _generate_instance_id() -> str:
    """Generate stable machine-specific instance ID."""
    components = [
        platform.node(),
        platform.machine(),
        str(uuid.getnode()),  # MAC address
    ]
    return hashlib.sha256(":".join(components).encode()).hexdigest()[:24]

INSTANCE_ID = os.getenv("GUARD_INSTANCE_ID", _generate_instance_id())


@dataclass
class CloudConfig:
    """Production cloud service configuration."""

    # Control plane (pull)
    artifact_base_url: str = ARTIFACT_BASE_URL
    tuf_metadata_url: str = TUF_METADATA_URL

    # Data plane (push)
    ingest_url: str = INGEST_URL
    enroll_url: str = ENROLL_URL
    support_url: str = SUPPORT_URL
    heartbeat_url: str = HEARTBEAT_URL

    # Auth
    auth_token: str = AUTH_TOKEN
    instance_id: str = INSTANCE_ID

    # Intervals
    heartbeat_interval_seconds: int = 60
    telemetry_flush_interval_seconds: int = 300
    update_check_interval_seconds: int = 3600

    # Feature flags
    telemetry_enabled: bool = True
    heartbeat_enabled: bool = True
    auto_update_enabled: bool = True
    transparency_log_enabled: bool = True

    @classmethod
    def from_env(cls) -> "CloudConfig":
        """Load configuration from environment variables."""
        return cls(
            artifact_base_url=os.getenv("GUARD_ARTIFACT_BASE_URL", ARTIFACT_BASE_URL),
            tuf_metadata_url=os.getenv("GUARD_TUF_METADATA_URL", TUF_METADATA_URL),
            ingest_url=os.getenv("GUARD_INGEST_URL", INGEST_URL),
            enroll_url=os.getenv("GUARD_ENROLL_URL", ENROLL_URL),
            support_url=os.getenv("GUARD_SUPPORT_URL", SUPPORT_URL),
            heartbeat_url=os.getenv("GUARD_HEARTBEAT_URL", HEARTBEAT_URL),
            auth_token=os.getenv("GUARD_AUTH_TOKEN", AUTH_TOKEN),
            instance_id=os.getenv("GUARD_INSTANCE_ID", INSTANCE_ID),
            heartbeat_interval_seconds=int(os.getenv("GUARD_HEARTBEAT_INTERVAL", "60")),
            telemetry_flush_interval_seconds=int(os.getenv("GUARD_TELEMETRY_INTERVAL", "300")),
            update_check_interval_seconds=int(os.getenv("GUARD_UPDATE_INTERVAL", "3600")),
            telemetry_enabled=os.getenv("GUARD_TELEMETRY_ENABLED", "true").lower() == "true",
            heartbeat_enabled=os.getenv("GUARD_HEARTBEAT_ENABLED", "true").lower() == "true",
            auto_update_enabled=os.getenv("GUARD_AUTO_UPDATE", "true").lower() == "true",
            transparency_log_enabled=os.getenv("GUARD_TRANSPARENCY_LOG", "true").lower() == "true",
        )

    def get_headers(self) -> dict:
        """Get authentication headers for API requests."""
        return {
            "Authorization": f"Bearer {self.auth_token}",
            "X-Guard-Instance": self.instance_id,
            "X-Guard-Version": get_version(),
            "X-Guard-Platform": f"{platform.system()}/{platform.machine()}",
        }

    def is_configured(self) -> bool:
        """Check if production endpoints are configured."""
        return bool(self.auth_token) and not self.ingest_url.startswith("https://guard-")


def get_version() -> str:
    """Get Guard version from VERSION file or fallback."""
    version_file = Path(__file__).parent.parent / "VERSION"
    if version_file.exists():
        return version_file.read_text().strip()
    return "0.0.0-dev"


def get_config() -> CloudConfig:
    """Get the global cloud configuration."""
    return CloudConfig.from_env()


# =============================================================================
# WHAT YOU NEED TO PROVIDE
# =============================================================================
"""
To launch Guard to production, you need to set up and provide:

1. CLOUDFLARE WORKERS (Data Plane - Push)
   ─────────────────────────────────────

   a) guard-ingest Worker
      - URL: https://guard-ingest.<your-domain>.workers.dev (or custom domain)
      - Receives: Heartbeats, telemetry, interception proofs
      - Stores: R2 bucket for raw data
      - Example: See cloud/workers/guard-ingest/

   b) guard-enroll Worker
      - URL: https://guard-enroll.<your-domain>.workers.dev
      - Receives: New device enrollments
      - Stores: D1 database for device registry

   c) guard-support Worker
      - URL: https://guard-support.<your-domain>.workers.dev
      - Receives: Support bundles (gzipped diagnostics)
      - Stores: R2 bucket for support files

2. R2 BUCKETS
   ───────────

   a) guard-telemetry-bucket
      - Stores heartbeats, telemetry, interception proofs

   b) guard-support-bucket
      - Stores support bundles from users

   c) guard-artifacts-bucket (optional)
      - Alternative to GitHub Releases for binary distribution

3. TUF REPOSITORY (Control Plane - Pull)
   ─────────────────────────────────────

   a) GitHub Releases (recommended)
      - Signed binaries
      - TUF metadata in releases

   b) OR Custom TUF Server
      - Host at: https://updates.<your-domain>.ai/guard/v1
      - Contains: root.json, targets.json, snapshot.json, timestamp.json

4. SIGNING KEYS (Keep Secure!)
   ────────────────────────────

   a) TUF root key (offline, air-gapped)
   b) TUF targets key (for signing releases)
   c) Code signing certificate (for macOS/Windows)

5. ENVIRONMENT VARIABLES TO SET
   ─────────────────────────────

   GUARD_INGEST_URL=https://guard-ingest.yourcompany.workers.dev
   GUARD_ENROLL_URL=https://guard-enroll.yourcompany.workers.dev
   GUARD_SUPPORT_URL=https://guard-support.yourcompany.workers.dev
   GUARD_ARTIFACT_BASE_URL=https://github.com/yourorg/guard/releases/download
   GUARD_TUF_METADATA_URL=https://updates.yourcompany.ai/guard/v1
   GUARD_AUTH_TOKEN=<your-secret-api-token>

"""
