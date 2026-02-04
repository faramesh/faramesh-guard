"""
Faramesh Guard - AI Agent Authority & Safety System

This is the comprehensive implementation following plan-farameshGuardV1Enhanced.prompt.md

Architecture:
- Daemon: Authorization decision engine
- Plugin: Hook into OpenClaw tool execution
- Enforcement: Cryptographic permit validation at execution boundary

Key Properties:
- Non-bypassable: Tool cannot execute without valid permit
- Fail-closed: Any error blocks execution
- Tamper-evident: Audit trail with hash chains
- Capability-based: Permits with caveats, not boolean allow/deny
"""

__version__ = "0.1.0"
