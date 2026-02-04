#!/usr/bin/env python3
"""
Faramesh Guard CLI

Command-line interface for managing the Guard daemon.
"""

import argparse
import json
import sys
from typing import Optional

try:
    import httpx
except ImportError:
    print("Error: httpx not installed. Run: pip install httpx")
    sys.exit(1)


GUARD_URL = "http://127.0.0.1:8765"


def get_client():
    """Get HTTP client."""
    return httpx.Client(base_url=GUARD_URL, timeout=10)


def cmd_status(args):
    """Show Guard daemon status."""
    try:
        client = get_client()
        health = client.get("/health").json()
        stats = client.get("/api/v1/guard/stats").json()

        print("🛡️  Faramesh Guard Status")
        print("=" * 40)
        print(f"Status: {health['status']}")
        print(f"Version: {health['version']}")
        print()

        policy = stats["components"]["policy"]
        print(f"Policy: {policy['name']}")
        print(f"Mode: {policy['mode']}")
        print(
            f"Rules: {policy['allow_patterns']} allow, {policy['require_approval']} approval, {policy['deny_patterns']} deny"
        )
        print()

        behavioral = stats["components"]["behavioral_detector"]
        print(f"Agents tracked: {behavioral['total_agents']}")
        print(f"Anomalies detected: {behavioral['total_anomalies']}")
        print()

        fusion = stats["components"]["signal_fusion"]
        total = sum(fusion["decisions_by_outcome"].values())
        print(f"Decisions: {total} total")
        for outcome, count in fusion["decisions_by_outcome"].items():
            if count > 0:
                print(f"  - {outcome}: {count}")
        print()

        audit = stats["components"]["audit_log"]
        print(f"Audit entries: {audit['entries']}")
        print(f"WebSocket clients: {stats['websocket_clients']}")

    except httpx.ConnectError:
        print("❌ Guard daemon not running")
        print(
            "Start with: cd faramesh-guard/daemon && ./venv/bin/uvicorn main:app --host 127.0.0.1 --port 8765"
        )
        sys.exit(1)


def cmd_policy(args):
    """Show or change policy."""
    client = get_client()

    if args.mode:
        # Set mode
        response = client.post("/api/v1/guard/policy/mode", params={"mode": args.mode})
        if response.status_code == 200:
            print(f"✅ Policy mode changed to: {args.mode}")
        else:
            print(f"❌ Error: {response.json().get('detail', response.text)}")
            sys.exit(1)
    else:
        # Show policy
        policy = client.get("/api/v1/guard/policy").json()

        print(f"📋 Policy: {policy['name']}")
        print(f"   Mode: {policy['mode']}")
        print(f"   Version: {policy['version']}")
        print()

        if args.verbose:
            print("Allow Patterns:")
            for p in policy["allow_patterns"][:5]:
                print(f"  - {p.get('tool', 'any')}: {p.get('reason', '')}")
            if len(policy["allow_patterns"]) > 5:
                print(f"  ... and {len(policy['allow_patterns']) - 5} more")
            print()

            print("Require Approval:")
            for p in policy["require_approval"][:5]:
                print(f"  - {p.get('tool', 'any')}: {p.get('reason', '')}")
            print()

            print("Deny Patterns:")
            for p in policy["deny_patterns"]:
                print(f"  - {p.get('tool', 'any')}: {p.get('reason', '')}")


def cmd_pending(args):
    """List or manage pending actions."""
    client = get_client()

    if args.action_id:
        if args.approve:
            response = client.post(
                f"/api/v1/guard/pending/{args.action_id}/approve",
                params={"reason": args.reason or "approved via CLI"},
            )
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Approved: {args.action_id}")
                if data.get("permit"):
                    print(f"   Permit: {data['permit']['signature'][:16]}...")
            else:
                print(f"❌ Error: {response.text}")
                sys.exit(1)

        elif args.deny:
            response = client.post(
                f"/api/v1/guard/pending/{args.action_id}/deny",
                params={"reason": args.reason or "denied via CLI"},
            )
            if response.status_code == 200:
                print(f"✅ Denied: {args.action_id}")
            else:
                print(f"❌ Error: {response.text}")
                sys.exit(1)

        else:
            # Show specific action
            response = client.get(f"/api/v1/guard/pending/{args.action_id}")
            if response.status_code == 200:
                action = response.json()
                print(f"Action: {action['action_id']}")
                print(f"Tool: {action['tool_name']}")
                print(f"Agent: {action['agent_id']}")
                print(f"Status: {action['status']}")
                print(f"Reason: {action['reason']}")
                print(f"Risk: {action['risk_level']}")
                print(f"Created: {action['created_at']}")
                print(f"Expires: {action['expires_at']}")
                if args.verbose:
                    print(f"Args: {json.dumps(action['args'], indent=2)}")
            else:
                print(f"❌ Action not found: {args.action_id}")
                sys.exit(1)
    else:
        # List pending
        pending = client.get("/api/v1/guard/pending").json()
        actions = pending["actions"]

        if not actions:
            print("📭 No pending actions")
            return

        print(f"📬 {len(actions)} Pending Actions")
        print("=" * 60)
        for action in actions:
            print(f"\n🔶 {action['action_id'][:16]}...")
            print(f"   Tool: {action['tool_name']}")
            print(f"   Agent: {action['agent_id']}")
            print(f"   Reason: {action['reason']}")
            print(f"   Risk: {action['risk_level']}")
            print(f"   Expires: {action['expires_at']}")


def cmd_audit(args):
    """Show audit log."""
    client = get_client()
    response = client.get("/api/v1/guard/audit", params={"limit": args.limit})
    data = response.json()

    print(f"📜 Audit Log ({data['count']} entries)")
    print("=" * 60)

    for entry in data["entries"]:
        decision_icon = (
            "✅"
            if entry["decision"] == "ALLOW"
            else "❌" if entry["decision"] == "DENY" else "🔶"
        )
        print(f"\n{decision_icon} {entry['timestamp']}")
        print(f"   Action: {entry['action_id'][:16]}...")
        print(f"   Event: {entry['event_type']}")
        print(f"   Decision: {entry['decision']}")
        print(f"   Risk: {entry['risk_score']:.2f}")

        if args.verbose:
            meta = entry.get("metadata", {})
            print(f"   Tool: {meta.get('tool', 'unknown')}")
            print(f"   Agent: {meta.get('agent_id', 'unknown')}")
            print(f"   Reason: {meta.get('reason', '')}")
            print(f"   Hash: {entry['entry_hash'][:16]}...")


def cmd_test(args):
    """Test a command against the policy."""
    client = get_client()

    response = client.post(
        "/api/v1/guard/execute",
        json={
            "tool_name": "bash",
            "args": {"command": args.command},
            "agent_id": "cli-test",
            "car_hash": f"test-{args.command[:20]}",
        },
    )
    data = response.json()

    if data["allowed"]:
        print(f"✅ ALLOWED: {args.command}")
        print(f"   Reason: {data['decision']['reason']}")
        print(f"   Risk: {data['decision']['risk_level']}")
        if data.get("permit"):
            print(f"   Permit: {data['permit']['signature'][:32]}...")
    elif data.get("needs_approval"):
        print(f"🔶 NEEDS APPROVAL: {args.command}")
        print(f"   Reason: {data['decision']['reason']}")
        print(f"   Risk: {data['decision']['risk_level']}")
        print(f"   Action ID: {data['action_id']}")
    else:
        print(f"❌ DENIED: {args.command}")
        print(f"   Reason: {data['decision']['reason']}")
        print(f"   Risk: {data['decision']['risk_level']}")


def cmd_health(args):
    """Show detailed health check."""
    try:
        client = get_client()
        health = client.get("/api/v1/guard/health").json()

        status_icons = {"healthy": "✅", "degraded": "⚠️", "unhealthy": "❌"}

        check_icons = {"ok": "✅", "warning": "⚠️", "error": "❌", "critical": "🔴"}

        print("🏥 Guard Health Check")
        print("=" * 50)
        print(
            f"Overall: {status_icons.get(health['overall_status'], '❓')} {health['overall_status'].upper()}"
        )
        print(f"Uptime: {health['uptime_seconds']:.0f} seconds")
        print()

        print("Checks:")
        for check in health.get("checks", []):
            icon = check_icons.get(check["status"], "❓")
            print(f"  {icon} {check['name']}: {check['message']}")
            if args.verbose and check.get("details"):
                for k, v in check["details"].items():
                    print(f"      {k}: {v}")

        if health.get("has_issues"):
            print()
            print("⚠️  Issues detected! Review checks above.")

    except httpx.ConnectError:
        print("❌ Guard daemon not running")
        sys.exit(1)


def cmd_integrity(args):
    """Check policy integrity."""
    try:
        client = get_client()
        result = client.get("/api/v1/guard/integrity").json()

        if result["passed"]:
            print("✅ Policy Integrity: VERIFIED")
            print(f"   Hash: {result['current_hash'][:32]}...")
        else:
            print("❌ Policy Integrity: FAILED")
            print(f"   Message: {result['message']}")
            if result.get("tampered_files"):
                print("   Tampered files:")
                for f in result["tampered_files"]:
                    print(f"     - {f}")
            print()
            print("⚠️  Policy files may have been modified!")
            print("   Review changes or restore from backup.")
            sys.exit(1)

    except httpx.ConnectError:
        print("❌ Guard daemon not running")
        sys.exit(1)


def cmd_watchdog(args):
    """Show watchdog status and alerts."""
    try:
        client = get_client()
        stats = client.get("/api/v1/guard/watchdog").json()

        print("🐕 Guard Watchdog")
        print("=" * 50)
        print(f"Running: {'✅ Yes' if stats['running'] else '❌ No'}")
        print(f"Check interval: {stats['check_interval_seconds']}s")
        print(f"Uptime: {stats['uptime_seconds']:.0f}s")
        print(f"Started: {stats['start_time']}")
        print()

        current = stats.get("current_status", {})
        if current:
            print(f"Current status: {current['overall_status'].upper()}")

        alerts = stats.get("recent_alerts", [])
        if alerts:
            print()
            print(f"Recent Alerts ({len(alerts)}):")
            for alert in alerts[-5:]:
                print(f"  ⚠️ {alert['timestamp']}: {alert['status']}")
                for issue in alert.get("issues", []):
                    print(f"     - {issue['name']}: {issue['message']}")
        else:
            print()
            print("No recent alerts ✅")

    except httpx.ConnectError:
        print("❌ Guard daemon not running")
        sys.exit(1)


def cmd_start(args):
    """Start the Guard daemon."""
    import subprocess
    import os

    daemon_dir = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(daemon_dir, "venv", "bin", "python")

    if not os.path.exists(venv_python):
        print("❌ Virtual environment not found")
        print(f"   Expected: {venv_python}")
        print(
            "   Run: python3 -m venv venv && ./venv/bin/pip install -r requirements.txt"
        )
        sys.exit(1)

    # Check if already running
    try:
        client = get_client()
        health = client.get("/health").json()
        print("✅ Guard daemon is already running")
        print(f"   Status: {health['status']}")
        return
    except Exception:
        pass

    print("🚀 Starting Guard daemon...")

    # Start in background
    cmd = [
        venv_python,
        "-m",
        "uvicorn",
        "main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8765",
    ]
    process = subprocess.Popen(
        cmd,
        cwd=daemon_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    # Wait for startup
    import time

    for _ in range(10):
        time.sleep(0.5)
        try:
            client = get_client()
            health = client.get("/health").json()
            print("✅ Guard daemon started")
            print(f"   PID: {process.pid}")
            print(f"   URL: {GUARD_URL}")
            return
        except Exception:
            pass

    print("⚠️ Daemon may still be starting...")
    print(f"   Check: curl {GUARD_URL}/health")


def cmd_stop(args):
    """Stop the Guard daemon."""
    import subprocess

    try:
        # Try graceful first
        result = subprocess.run(
            ["pkill", "-f", "uvicorn main:app.*8765"], capture_output=True
        )
        if result.returncode == 0:
            print("✅ Guard daemon stopped")
        else:
            # Check if it was running
            try:
                client = get_client()
                client.get("/health")
                print("❌ Failed to stop daemon")
                sys.exit(1)
            except Exception:
                print("✅ Guard daemon is not running")
    except Exception as e:
        print(f"❌ Error stopping daemon: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Faramesh Guard CLI - Manage AI agent safety",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  guard status               Show daemon status
  guard health               Detailed health check
  guard start                Start the daemon
  guard stop                 Stop the daemon
  guard policy               Show current policy
  guard policy --mode strict Change to strict mode
  guard pending              List pending approvals
  guard pending abc123 --approve  Approve an action
  guard audit                Show recent audit log
  guard test "ls -la"        Test a command against policy
  guard integrity            Verify policy integrity
  guard watchdog             Show watchdog status
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # status
    status_parser = subparsers.add_parser("status", help="Show daemon status")
    status_parser.set_defaults(func=cmd_status)

    # health
    health_parser = subparsers.add_parser("health", help="Detailed health check")
    health_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show details"
    )
    health_parser.set_defaults(func=cmd_health)

    # start
    start_parser = subparsers.add_parser("start", help="Start the daemon")
    start_parser.set_defaults(func=cmd_start)

    # stop
    stop_parser = subparsers.add_parser("stop", help="Stop the daemon")
    stop_parser.set_defaults(func=cmd_stop)

    # policy
    policy_parser = subparsers.add_parser("policy", help="Show or change policy")
    policy_parser.add_argument(
        "--mode", choices=["safe", "strict", "permissive"], help="Set policy mode"
    )
    policy_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed policy"
    )
    policy_parser.set_defaults(func=cmd_policy)

    # pending
    pending_parser = subparsers.add_parser("pending", help="Manage pending actions")
    pending_parser.add_argument("action_id", nargs="?", help="Specific action ID")
    pending_parser.add_argument("--approve", action="store_true", help="Approve action")
    pending_parser.add_argument("--deny", action="store_true", help="Deny action")
    pending_parser.add_argument("--reason", help="Reason for approval/denial")
    pending_parser.add_argument("-v", "--verbose", action="store_true")
    pending_parser.set_defaults(func=cmd_pending)

    # audit
    audit_parser = subparsers.add_parser("audit", help="Show audit log")
    audit_parser.add_argument("--limit", type=int, default=10, help="Number of entries")
    audit_parser.add_argument("-v", "--verbose", action="store_true")
    audit_parser.set_defaults(func=cmd_audit)

    # test
    test_parser = subparsers.add_parser("test", help="Test a command")
    test_parser.add_argument("command", help="Command to test")
    test_parser.set_defaults(func=cmd_test)

    # integrity
    integrity_parser = subparsers.add_parser(
        "integrity", help="Verify policy integrity"
    )
    integrity_parser.set_defaults(func=cmd_integrity)

    # watchdog
    watchdog_parser = subparsers.add_parser("watchdog", help="Show watchdog status")
    watchdog_parser.set_defaults(func=cmd_watchdog)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
