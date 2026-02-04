"""
Rust Core Client for Faramesh Guard.

This module provides Python bindings to the Rust security kernel.
The Rust core handles all security-critical hot path operations:
- CAR hash canonicalization
- Permit HMAC verification
- Fast decision cache
- Replay detection

Communication is via Unix socket IPC using JSON-RPC 2.0.
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Default socket path
DEFAULT_SOCKET_PATH = "/var/run/faramesh-guard/core.sock"


class Decision(str, Enum):
    """Decision from the security kernel."""

    ALLOW = "allow"
    DENY = "deny"
    PENDING = "pending"


@dataclass
class CachedDecision:
    """Cached decision from Rust core."""

    decision: Decision
    confidence: float
    expires_at: int
    car_hash: str


@dataclass
class GateCheckResult:
    """Result from the gate check operation."""

    decision: Decision
    confidence: float
    car_hash: str
    source: str  # "cache", "permit", "none"


@dataclass
class VerificationResult:
    """Result of permit verification."""

    valid: bool
    permit_id: str
    car_hash: str
    decision: Decision
    confidence: float
    remaining_ttl: int


@dataclass
class CacheStats:
    """Cache statistics from Rust core."""

    entries: int
    max_entries: int
    hits: int
    misses: int
    hit_rate: float
    evictions: int


@dataclass
class ReplayStats:
    """Replay detection statistics."""

    entries: int
    max_entries: int
    window_seconds: int
    total_checks: int
    replays_detected: int


class RustCoreError(Exception):
    """Error from the Rust security kernel."""

    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"RustCore error {code}: {message}")


class RustCoreClient:
    """
    Async client for the Rust security kernel.

    This client connects to the Rust core via Unix socket and
    provides Python-friendly wrappers for all operations.
    """

    def __init__(self, socket_path: Optional[str] = None):
        self.socket_path = socket_path or os.environ.get(
            "GUARD_SOCKET_PATH", DEFAULT_SOCKET_PATH
        )
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._request_id = 0
        self._lock = asyncio.Lock()
        self._connected = False

    async def connect(self) -> None:
        """Connect to the Rust core."""
        if self._connected:
            return

        try:
            self._reader, self._writer = await asyncio.open_unix_connection(
                self.socket_path
            )
            self._connected = True
            logger.info(f"Connected to Rust core at {self.socket_path}")
        except Exception as e:
            logger.error(f"Failed to connect to Rust core: {e}")
            raise

    async def disconnect(self) -> None:
        """Disconnect from the Rust core."""
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
        self._reader = None
        self._writer = None
        self._connected = False

    async def _call(self, method: str, params: Any = None) -> Any:
        """Make a JSON-RPC call to the Rust core."""
        if not self._connected:
            await self.connect()

        async with self._lock:
            self._request_id += 1
            request = {
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": method,
                "params": params or {},
            }

            # Send request
            request_json = json.dumps(request) + "\n"
            self._writer.write(request_json.encode())
            await self._writer.drain()

            # Read response
            response_line = await self._reader.readline()
            if not response_line:
                raise RustCoreError(-32000, "Connection closed")

            response = json.loads(response_line.decode())

            # Check for error
            if "error" in response and response["error"]:
                err = response["error"]
                raise RustCoreError(
                    err.get("code", -32000),
                    err.get("message", "Unknown error"),
                    err.get("data"),
                )

            return response.get("result")

    # ========== CAR Hashing ==========

    async def hash_car(self, car_data: Dict[str, Any]) -> str:
        """
        Hash a CAR (Canonical Action Request).

        Args:
            car_data: The CAR data to hash

        Returns:
            SHA-256 hash prefixed with "sha256:"
        """
        result = await self._call("hash_car", car_data)
        return result["hash"]

    # ========== Cache Operations ==========

    async def cache_get(self, car_hash: str) -> Optional[CachedDecision]:
        """
        Get a cached decision.

        Args:
            car_hash: The CAR hash to look up

        Returns:
            CachedDecision if found, None otherwise
        """
        result = await self._call("cache_get", {"car_hash": car_hash})
        if result is None:
            return None
        return CachedDecision(
            decision=Decision(result["decision"]),
            confidence=result["confidence"],
            expires_at=result["expires_at"],
            car_hash=result["car_hash"],
        )

    async def cache_put(
        self,
        car_hash: str,
        decision: Decision,
        confidence: float = 1.0,
        ttl: Optional[int] = None,
    ) -> None:
        """
        Put a decision in the cache.

        Args:
            car_hash: The CAR hash
            decision: The decision to cache
            confidence: Confidence score (0.0 - 1.0)
            ttl: Time-to-live in seconds (optional)
        """
        params = {
            "car_hash": car_hash,
            "decision": decision.value,
            "confidence": confidence,
        }
        if ttl is not None:
            params["ttl"] = ttl
        await self._call("cache_put", params)

    async def cache_invalidate(self, car_hash: str) -> bool:
        """
        Invalidate a cached decision.

        Args:
            car_hash: The CAR hash to invalidate

        Returns:
            True if entry was removed, False if not found
        """
        result = await self._call("cache_invalidate", {"car_hash": car_hash})
        return result["removed"]

    async def cache_stats(self) -> CacheStats:
        """Get cache statistics."""
        result = await self._call("cache_stats")
        return CacheStats(**result)

    # ========== Permit Operations ==========

    async def verify_permit(self, permit: Dict[str, Any]) -> VerificationResult:
        """
        Verify a permit signature and check for replay.

        Args:
            permit: The permit to verify

        Returns:
            VerificationResult

        Raises:
            RustCoreError: If verification fails or replay detected
        """
        result = await self._call("verify_permit", permit)
        return VerificationResult(
            valid=result["valid"],
            permit_id=result["permit_id"],
            car_hash=result["car_hash"],
            decision=Decision(result["decision"]),
            confidence=result["confidence"],
            remaining_ttl=result["remaining_ttl"],
        )

    async def create_permit(
        self,
        car_hash: str,
        decision: Decision,
        confidence: float = 1.0,
        issued_by: str = "guard",
        ttl: int = 300,
    ) -> Dict[str, Any]:
        """
        Create a signed permit.

        Args:
            car_hash: The CAR hash to authorize
            decision: The decision (allow/deny)
            confidence: Confidence score
            issued_by: Who/what issued the permit
            ttl: Time-to-live in seconds

        Returns:
            The signed permit as a dict
        """
        return await self._call(
            "create_permit",
            {
                "car_hash": car_hash,
                "decision": decision.value,
                "confidence": confidence,
                "issued_by": issued_by,
                "ttl": ttl,
            },
        )

    # ========== Replay Detection ==========

    async def check_replay(self, nonce: str) -> bool:
        """
        Check if a nonce has been seen (is a replay).

        Args:
            nonce: The nonce to check

        Returns:
            True if this is a replay, False if new
        """
        result = await self._call("check_replay", {"nonce": nonce})
        return result["replay"]

    async def replay_stats(self) -> ReplayStats:
        """Get replay detection statistics."""
        result = await self._call("replay_stats")
        return ReplayStats(**result)

    # ========== Gate Check (Composite) ==========

    async def gate_check(
        self,
        car: Dict[str, Any],
        permit: Optional[Dict[str, Any]] = None,
    ) -> GateCheckResult:
        """
        Perform a full gate check - the main security chokepoint.

        This is the primary method for checking if an action is allowed.
        It performs:
        1. CAR hash computation
        2. Cache lookup (fast path)
        3. Permit verification if provided
        4. Replay detection

        Args:
            car: The CAR (action request) to check
            permit: Optional permit to verify

        Returns:
            GateCheckResult with decision and source
        """
        params = {"car": car}
        if permit:
            params["permit"] = permit

        result = await self._call("gate_check", params)
        return GateCheckResult(
            decision=Decision(result["decision"]),
            confidence=result["confidence"],
            car_hash=result["car_hash"],
            source=result["source"],
        )

    # ========== Health ==========

    async def ping(self) -> str:
        """Ping the Rust core."""
        return await self._call("ping")

    async def version(self) -> str:
        """Get Rust core version."""
        return await self._call("version")


# ========== Singleton ==========

_rust_core_client: Optional[RustCoreClient] = None


def get_rust_core_client() -> RustCoreClient:
    """Get the singleton Rust core client."""
    global _rust_core_client
    if _rust_core_client is None:
        _rust_core_client = RustCoreClient()
    return _rust_core_client


async def reset_rust_core_client() -> RustCoreClient:
    """Reset and return a new Rust core client."""
    global _rust_core_client
    if _rust_core_client is not None:
        await _rust_core_client.disconnect()
    _rust_core_client = RustCoreClient()
    return _rust_core_client


# ========== Fallback Mode ==========


class FallbackRustCoreClient:
    """
    Fallback implementation when Rust core is unavailable.

    This provides the same interface but uses pure Python implementations.
    Use this during development or when Rust core is not deployed.
    """

    def __init__(self):
        self._cache: Dict[str, CachedDecision] = {}
        self._seen_nonces: set = set()
        self._connected = True
        logger.warning(
            "Using Python fallback for Rust core (not recommended for production)"
        )

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    async def hash_car(self, car_data: Dict[str, Any]) -> str:
        """Pure Python CAR hashing fallback."""
        import hashlib

        # Sort keys for determinism
        canonical = json.dumps(car_data, sort_keys=True, separators=(",", ":"))
        hash_bytes = hashlib.sha256(canonical.encode()).hexdigest()
        return f"sha256:{hash_bytes}"

    async def cache_get(self, car_hash: str) -> Optional[CachedDecision]:
        return self._cache.get(car_hash)

    async def cache_put(
        self,
        car_hash: str,
        decision: Decision,
        confidence: float = 1.0,
        ttl: Optional[int] = None,
    ) -> None:
        import time

        ttl = ttl or 300
        self._cache[car_hash] = CachedDecision(
            decision=decision,
            confidence=confidence,
            expires_at=int(time.time()) + ttl,
            car_hash=car_hash,
        )

    async def cache_invalidate(self, car_hash: str) -> bool:
        if car_hash in self._cache:
            del self._cache[car_hash]
            return True
        return False

    async def cache_stats(self) -> CacheStats:
        return CacheStats(
            entries=len(self._cache),
            max_entries=10000,
            hits=0,
            misses=0,
            hit_rate=0.0,
            evictions=0,
        )

    async def check_replay(self, nonce: str) -> bool:
        if nonce in self._seen_nonces:
            return True
        self._seen_nonces.add(nonce)
        return False

    async def replay_stats(self) -> ReplayStats:
        return ReplayStats(
            entries=len(self._seen_nonces),
            max_entries=100000,
            window_seconds=300,
            total_checks=0,
            replays_detected=0,
        )

    async def gate_check(
        self,
        car: Dict[str, Any],
        permit: Optional[Dict[str, Any]] = None,
    ) -> GateCheckResult:
        car_hash = await self.hash_car(car)

        # Check cache
        cached = await self.cache_get(car_hash)
        if cached:
            return GateCheckResult(
                decision=cached.decision,
                confidence=cached.confidence,
                car_hash=car_hash,
                source="cache",
            )

        # No permit verification in fallback - just return pending
        return GateCheckResult(
            decision=Decision.PENDING,
            confidence=0.0,
            car_hash=car_hash,
            source="none",
        )

    async def ping(self) -> str:
        return "pong (fallback)"

    async def version(self) -> str:
        return "fallback-0.0.0"


def get_rust_core_client_with_fallback() -> RustCoreClient:
    """
    Get Rust core client, falling back to Python implementation.

    Use this during development or when Rust core may not be available.
    """
    socket_path = os.environ.get("GUARD_SOCKET_PATH", DEFAULT_SOCKET_PATH)

    if Path(socket_path).exists():
        return get_rust_core_client()
    else:
        logger.warning(f"Rust core socket not found at {socket_path}, using fallback")
        return FallbackRustCoreClient()  # type: ignore
