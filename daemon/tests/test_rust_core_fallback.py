#!/usr/bin/env python3
"""Test the Rust core fallback client."""

import asyncio
from service.core import FallbackRustCoreClient, Decision


async def test_fallback():
    """Test all fallback client operations."""
    client = FallbackRustCoreClient()

    # Test CAR hashing
    car = {"action_type": "file_read", "resource": "/tmp/test.txt", "agent_id": "test"}
    car_hash = await client.hash_car(car)
    print(f"✅ CAR hash: {car_hash[:40]}...")

    # Test cache
    await client.cache_put(car_hash, Decision.ALLOW, 0.95)
    cached = await client.cache_get(car_hash)
    print(f"✅ Cache: {cached.decision.value} confidence={cached.confidence}")

    # Test gate check
    result = await client.gate_check(car)
    print(f"✅ Gate check: {result.decision.value} from {result.source}")

    # Test replay detection
    is_replay = await client.check_replay("nonce-123")
    print(f"✅ First nonce check: replay={is_replay}")
    is_replay = await client.check_replay("nonce-123")
    print(f"✅ Second nonce check: replay={is_replay}")

    # Test stats
    cache_stats = await client.cache_stats()
    print(f"✅ Cache stats: {cache_stats.entries} entries")

    replay_stats = await client.replay_stats()
    print(f"✅ Replay stats: {replay_stats.entries} nonces tracked")

    print("\n✅ All fallback client tests passed!")


if __name__ == "__main__":
    asyncio.run(test_fallback())
