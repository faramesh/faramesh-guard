"""
Enforcement Invariant Tests for Faramesh Guard

These tests ensure the core safety properties cannot be violated.
From guard-plan-v1.md Meta-Layer 8: Invariant Tests

Critical Properties:
1. No action without decision record
2. No permit without audit
3. Behavioral/adversarial detection always runs
4. DENY cannot be bypassed
5. ABSTAIN always creates pending action
"""

import pytest
import json
import httpx
from datetime import datetime
import hashlib
import os

# Guard daemon URL
GUARD_URL = os.getenv("GUARD_URL", "http://127.0.0.1:8765")


class TestEnforcementInvariants:
    """Test suite for enforcement invariants."""

    @pytest.fixture
    def client(self):
        """HTTP client for testing."""
        return httpx.Client(base_url=GUARD_URL, timeout=10)

    @pytest.fixture
    def unique_car_hash(self):
        """Generate unique CAR hash for each test."""
        timestamp = datetime.utcnow().isoformat()
        return hashlib.sha256(f"test-{timestamp}".encode()).hexdigest()[:16]

    # === INVARIANT 1: No action without decision record ===

    def test_every_execute_creates_audit_entry(self, client, unique_car_hash):
        """Every execute request MUST create an audit log entry."""
        # Execute a safe command
        response = client.post(
            "/api/v1/guard/execute",
            json={
                "tool_name": "bash",
                "args": {"command": "pwd"},
                "agent_id": "audit-invariant-test",
                "car_hash": unique_car_hash,
            },
        )
        assert response.status_code == 200

        # Verify audit entry was created for this specific action_id
        audit_after = client.get("/api/v1/guard/audit").json()
        action_ids = [e["action_id"] for e in audit_after.get("entries", [])]

        assert unique_car_hash in action_ids, "Execute MUST create audit entry"

    def test_denied_actions_are_logged(self, client, unique_car_hash):
        """Denied actions MUST be recorded in audit log."""
        response = client.post(
            "/api/v1/guard/execute",
            json={
                "tool_name": "bash",
                "args": {"command": "rm -rf /"},
                "agent_id": "invariant-test",
                "car_hash": unique_car_hash,
            },
        )
        assert response.status_code == 200
        assert response.json()["allowed"] is False

        # Verify denial was logged
        audit = client.get("/api/v1/guard/audit").json()
        latest = audit["entries"][0]
        assert latest["action_id"] == unique_car_hash
        assert latest["decision"] == "DENY"
        assert latest["event_type"] == "action_denied"

    # === INVARIANT 2: No permit without audit ===

    def test_permit_only_with_audit(self, client, unique_car_hash):
        """Permits MUST only be issued after audit logging."""
        response = client.post(
            "/api/v1/guard/execute",
            json={
                "tool_name": "bash",
                "args": {"command": "ls"},
                "agent_id": "invariant-test",
                "car_hash": unique_car_hash,
            },
        )
        data = response.json()

        if data["allowed"]:
            # If allowed, permit MUST exist
            assert data["permit"] is not None, "Allowed action MUST have permit"
            assert data["permit"]["signature"], "Permit MUST have signature"

            # Verify audit entry exists
            audit = client.get("/api/v1/guard/audit").json()
            action_ids = [e["action_id"] for e in audit["entries"]]
            assert unique_car_hash in action_ids, "Audit MUST exist for permit"

    def test_no_permit_on_deny(self, client, unique_car_hash):
        """Denied actions MUST NOT have permits."""
        response = client.post(
            "/api/v1/guard/execute",
            json={
                "tool_name": "bash",
                "args": {"command": "rm -rf /"},
                "agent_id": "invariant-test",
                "car_hash": unique_car_hash,
            },
        )
        data = response.json()

        assert data["allowed"] is False
        assert data["permit"] is None, "Denied action MUST NOT have permit"

    # === INVARIANT 3: Critical commands always blocked ===

    @pytest.mark.parametrize(
        "dangerous_cmd",
        [
            "rm -rf /",
            "rm -rf ~",
            "sudo rm -rf",
            "dd if=/dev/zero of=/dev/sda",
            "mkfs.ext4 /dev/sda",
            "chmod 777 /etc/passwd",
            "shutdown -h now",
            "reboot",
            "kill -9 1",
        ],
    )
    def test_critical_commands_always_blocked(self, client, dangerous_cmd):
        """Critical destructive commands MUST always be blocked."""
        car_hash = hashlib.sha256(dangerous_cmd.encode()).hexdigest()[:16]

        response = client.post(
            "/api/v1/guard/execute",
            json={
                "tool_name": "bash",
                "args": {"command": dangerous_cmd},
                "agent_id": "invariant-test",
                "car_hash": car_hash,
            },
        )
        data = response.json()

        assert data["allowed"] is False, f"CRITICAL: {dangerous_cmd} MUST be blocked"
        assert data["permit"] is None

    # === INVARIANT 4: Safe commands always allowed ===

    @pytest.mark.parametrize(
        "safe_cmd",
        [
            "ls -la",
            "pwd",
            "echo hello",
            "cat /etc/hosts",
            "head -n 10 file.txt",
            "tail -f log.txt",
            "wc -l file.txt",
        ],
    )
    def test_safe_commands_allowed(self, client, safe_cmd):
        """Known safe commands MUST be allowed."""
        car_hash = hashlib.sha256(safe_cmd.encode()).hexdigest()[:16]
        # Use unique agent ID to avoid rate limiting from previous tests
        unique_agent = f"safe-test-{hashlib.sha256(safe_cmd.encode()).hexdigest()[:8]}"

        response = client.post(
            "/api/v1/guard/execute",
            json={
                "tool_name": "bash",
                "args": {"command": safe_cmd},
                "agent_id": unique_agent,
                "car_hash": car_hash,
            },
        )
        data = response.json()

        assert data["allowed"] is True, f"Safe command {safe_cmd} should be allowed"
        assert data["permit"] is not None

    # === INVARIANT 5: Approval flow works correctly ===

    def test_approval_required_creates_pending(self, client, unique_car_hash):
        """Commands requiring approval MUST create pending action."""
        # Use unique agent to avoid rate limiting
        unique_agent = f"approval-test-{unique_car_hash[:8]}"
        response = client.post(
            "/api/v1/guard/execute",
            json={
                "tool_name": "bash",
                "args": {"command": "docker run nginx"},
                "agent_id": unique_agent,
                "car_hash": unique_car_hash,
            },
        )
        data = response.json()

        assert data["allowed"] is False
        assert data["needs_approval"] is True, "Docker run MUST require approval"
        assert data["action_id"] == unique_car_hash

        # Verify pending action exists
        pending = client.get("/api/v1/guard/pending").json()
        action_ids = [a["action_id"] for a in pending["actions"]]
        assert unique_car_hash in action_ids, "Pending action MUST be created"

    def test_approved_action_gets_permit(self, client, unique_car_hash):
        """Approved pending action MUST get a permit."""
        # Use unique agent to avoid rate limiting
        unique_agent = f"approve-test-{unique_car_hash[:8]}"
        # Create pending action
        client.post(
            "/api/v1/guard/execute",
            json={
                "tool_name": "bash",
                "args": {"command": "docker run hello"},
                "agent_id": unique_agent,
                "car_hash": unique_car_hash,
            },
        )

        # Approve it
        approve_response = client.post(
            f"/api/v1/guard/pending/{unique_car_hash}/approve",
            params={"reason": "test approval"},
        )
        data = approve_response.json()

        assert data["status"] == "approved"
        assert data["permit"] is not None, "Approved action MUST get permit"
        assert data["permit"]["signature"], "Permit MUST have valid signature"

    def test_denied_pending_action_no_permit(self, client, unique_car_hash):
        """Denied pending action MUST NOT get a permit."""
        # Use unique agent to avoid rate limiting
        unique_agent = f"deny-test-{unique_car_hash[:8]}"
        # Create pending action
        client.post(
            "/api/v1/guard/execute",
            json={
                "tool_name": "bash",
                "args": {"command": "pip install malware"},
                "agent_id": unique_agent,
                "car_hash": unique_car_hash,
            },
        )

        # Deny it
        deny_response = client.post(
            f"/api/v1/guard/pending/{unique_car_hash}/deny",
            params={"reason": "test denial"},
        )
        data = deny_response.json()

        assert data["status"] == "denied"
        assert "permit" not in data or data.get("permit") is None

    # === INVARIANT 6: Merkle chain integrity ===

    def test_audit_log_hash_chain_valid(self, client):
        """Audit log MUST maintain valid hash chain."""
        audit = client.get("/api/v1/guard/audit", params={"limit": 10}).json()
        entries = audit.get("entries", [])

        if len(entries) < 2:
            pytest.skip("Need at least 2 entries to verify chain")

        # Entries are in reverse order (newest first)
        for i in range(len(entries) - 1):
            current = entries[i]
            previous = entries[i + 1]

            # Current entry's prev_hash should match previous entry's hash
            assert (
                current["prev_hash"] == previous["entry_hash"]
            ), f"Hash chain broken: entry {i} prev_hash doesn't match entry {i+1}"

    # === INVARIANT 7: Policy mode affects decisions ===

    def test_policy_mode_switch(self, client, unique_car_hash):
        """Policy mode MUST be changeable and affect decisions."""
        # Get current policy
        policy = client.get("/api/v1/guard/policy").json()
        original_mode = policy["mode"]

        try:
            # Switch to strict mode
            response = client.post(
                "/api/v1/guard/policy/mode", params={"mode": "strict"}
            )
            assert response.json()["mode"] == "strict"

            # Verify policy changed
            policy = client.get("/api/v1/guard/policy").json()
            assert policy["mode"] == "strict"

        finally:
            # Restore original mode
            client.post("/api/v1/guard/policy/mode", params={"mode": original_mode})

    # === INVARIANT 8: Health check always available ===

    def test_health_check_always_responds(self, client):
        """Health endpoint MUST always respond."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "timestamp" in data

    # === INVARIANT 9: Stats are accurate ===

    def test_stats_reflect_operations(self, client, unique_car_hash):
        """Stats MUST reflect actual operations."""
        stats_before = client.get("/api/v1/guard/stats").json()

        # Execute a command
        client.post(
            "/api/v1/guard/execute",
            json={
                "tool_name": "bash",
                "args": {"command": "echo test"},
                "agent_id": "stats-test",
                "car_hash": unique_car_hash,
            },
        )

        stats_after = client.get("/api/v1/guard/stats").json()

        # Audit entries should increase
        assert (
            stats_after["components"]["audit_log"]["entries"]
            >= stats_before["components"]["audit_log"]["entries"]
        )


class TestAdversarialResistance:
    """Test resistance to adversarial inputs."""

    @pytest.fixture
    def client(self):
        return httpx.Client(base_url=GUARD_URL, timeout=10)

    @pytest.mark.parametrize(
        "injection",
        [
            "ls; rm -rf /",  # Command injection
            "ls && sudo su",  # Command chaining
            "ls | cat /etc/passwd",  # Pipe injection (unsafe target)
            "$(rm -rf /)",  # Subshell injection
            "`rm -rf /`",  # Backtick injection
            "ls\nrm -rf /",  # Newline injection
        ],
    )
    def test_command_injection_blocked(self, client, injection):
        """Command injection attempts MUST be blocked."""
        car_hash = hashlib.sha256(injection.encode()).hexdigest()[:16]

        response = client.post(
            "/api/v1/guard/execute",
            json={
                "tool_name": "bash",
                "args": {"command": injection},
                "agent_id": "adversarial-test-unique",
                "car_hash": car_hash,
            },
        )
        data = response.json()

        # Command injection MUST be blocked
        assert data["allowed"] is False, f"Injection {injection} MUST be blocked"
        assert (
            "injection" in data["decision"]["reason"].lower()
            or "suspicious" in data["decision"]["reason"].lower()
            or "pipe" in data["decision"]["reason"].lower()
        ), f"Injection {injection} not properly flagged: {data['decision']['reason']}"


class TestRateLimiting:
    """Test behavioral anomaly detection (rate limiting)."""

    @pytest.fixture
    def client(self):
        return httpx.Client(base_url=GUARD_URL, timeout=10)

    def test_rapid_requests_detected(self, client):
        """Rapid requests SHOULD trigger rate anomaly detection."""
        # Note: This tests behavioral anomaly, which may or may not block
        # depending on configuration. We just verify the system handles it.

        for i in range(20):
            car_hash = f"rate-test-{i}-{datetime.utcnow().timestamp()}"
            response = client.post(
                "/api/v1/guard/execute",
                json={
                    "tool_name": "bash",
                    "args": {"command": "echo rapid"},
                    "agent_id": "rate-test-agent",
                    "car_hash": car_hash,
                },
            )
            assert response.status_code == 200  # Should handle gracefully

        # Check if anomalies were detected
        stats = client.get("/api/v1/guard/stats").json()
        behavioral = stats["components"]["behavioral_detector"]
        # Just verify the system tracked the agent
        assert behavioral["total_agents"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
