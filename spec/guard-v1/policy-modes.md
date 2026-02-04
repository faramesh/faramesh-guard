# Faramesh Guard v1: Policy Modes

> **Version**: 1.0.0
> **Status**: Production Ready

This document describes the policy modes available in Guard v1 and how they translate to enforcement rules.

---

## Overview

Policy modes control the balance between safety and usability. Each mode defines:
- **Allow patterns**: Commands that execute without approval
- **Require approval patterns**: Commands that need human approval
- **Deny patterns**: Commands that are always blocked

---

## Mode Definitions

### Safe Mode (Default)

**Philosophy**: Maximum protection with approval flow for most operations.

```yaml
mode: safe
description: "Maximum protection, approval for most operations"

allow_patterns:
  # Read-only commands
  - pattern: "^(ls|pwd|echo|cat|head|tail|wc|grep|find|which|whoami|date|uname)\\b"
    risk_level: low
  # Safe file reading
  - pattern: "^cat\\s+[^;|&><]+$"
    risk_level: low
  # Git read operations
  - pattern: "^git\\s+(status|log|diff|branch|remote)\\b"
    risk_level: low

require_approval:
  # Package management
  - pattern: "\\b(npm|pip|brew|apt)\\s+(install|uninstall)"
    risk_level: medium
  # Docker operations
  - pattern: "\\bdocker\\b"
    risk_level: medium
  # File modifications
  - pattern: "\\b(mv|cp|rm)\\b"
    risk_level: medium
  # Git write operations
  - pattern: "^git\\s+(push|commit|merge|rebase)"
    risk_level: medium

deny_patterns:
  # Destructive commands
  - pattern: "rm\\s+-rf\\s+/"
    risk_level: critical
  - pattern: "rm\\s+-rf\\s+~"
    risk_level: critical
  # Privilege escalation
  - pattern: "\\bsudo\\b.*\\brm\\b"
    risk_level: critical
  - pattern: "chmod\\s+777"
    risk_level: critical
  # System commands
  - pattern: "\\b(shutdown|reboot|halt)\\b"
    risk_level: critical
  - pattern: "\\bmkfs\\b"
    risk_level: critical
```

**Use Case**: First-time users, sensitive environments, shared machines.

---

### Balanced Mode

**Philosophy**: Trust common development operations, require approval for risky ones.

```yaml
mode: balanced
description: "Trust common operations, approve risky ones"

allow_patterns:
  # Everything in Safe mode, plus:
  - pattern: "^(ls|pwd|echo|cat|head|tail|wc|grep|find|which|whoami|date|uname)\\b"
    risk_level: low
  # Package reading
  - pattern: "^(npm|pip)\\s+(list|show|search)"
    risk_level: low
  # Git all operations
  - pattern: "^git\\s+"
    risk_level: low
  # File modifications in workspace
  - pattern: "\\b(mv|cp)\\s+\\./"
    risk_level: low

require_approval:
  # Package installation (reduced scope)
  - pattern: "\\b(npm|pip)\\s+(install|uninstall)\\s+-g"
    risk_level: medium
  # Docker build/run
  - pattern: "\\bdocker\\s+(build|run|push)"
    risk_level: medium
  # System-level rm
  - pattern: "\\brm\\s+-rf\\s+(?!\\./)/"
    risk_level: high

deny_patterns:
  # Same as Safe mode
  - pattern: "rm\\s+-rf\\s+/"
    risk_level: critical
  - pattern: "\\bsudo\\b.*\\brm\\b"
    risk_level: critical
  - pattern: "chmod\\s+777"
    risk_level: critical
  - pattern: "\\b(shutdown|reboot|halt)\\b"
    risk_level: critical
```

**Use Case**: Experienced developers, active development, trusted environments.

---

### Strict Mode

**Philosophy**: Everything requires approval except viewing.

```yaml
mode: strict
description: "Approval required for all non-trivial operations"

allow_patterns:
  # Only pure read operations
  - pattern: "^(ls|pwd|echo|cat|head|tail|wc)\\b"
    risk_level: low
  - pattern: "^git\\s+(status|log)\\b"
    risk_level: low

require_approval:
  # Everything else that's not denied
  - pattern: ".*"
    risk_level: medium

deny_patterns:
  # Same as Safe mode, but more aggressive
  - pattern: "rm\\s+-rf"
    risk_level: critical
  - pattern: "\\bsudo\\b"
    risk_level: critical
  - pattern: "\\b(chmod|chown)\\b"
    risk_level: critical
  - pattern: "\\b(shutdown|reboot|halt|mkfs|dd)\\b"
    risk_level: critical
  - pattern: "\\bkill\\s+-9"
    risk_level: high
```

**Use Case**: Production environments, compliance-required, high-security.

---

### Permissive Mode

**Philosophy**: Trust most operations, block only critical dangers.

```yaml
mode: permissive
description: "Allow most operations, block critical only"

allow_patterns:
  # Most commands allowed
  - pattern: ".*"
    risk_level: low

require_approval:
  # Only very dangerous operations
  - pattern: "rm\\s+-rf\\s+/"
    risk_level: critical
  - pattern: "\\bsudo\\b.*\\brm\\b"
    risk_level: critical

deny_patterns:
  # Only the worst
  - pattern: "rm\\s+-rf\\s+/\\s*$"
    risk_level: critical
  - pattern: "\\bmkfs\\b"
    risk_level: critical
  - pattern: "dd\\s+.*of=/dev/"
    risk_level: critical
```

**Use Case**: Personal projects, experimentation, trusted agents.

**Warning**: Not recommended for production or shared environments.

---

## Pattern Evaluation Order

Patterns are evaluated in this order:

1. **Deny patterns**: If any match, action is BLOCKED (no override possible)
2. **Injection detection**: Check for command injection attempts
3. **Allow patterns**: If any match, action is ALLOWED
4. **Require approval patterns**: If any match, action needs APPROVAL
5. **Default**: Unknown actions go to APPROVAL

```
┌─────────────────────────────────────────────────────────┐
│                  PATTERN EVALUATION                     │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. Check deny_patterns                                 │
│     └─► Match? → DENY (immediate)                       │
│                                                         │
│  2. Check injection patterns                            │
│     └─► Match? → DENY (immediate)                       │
│                                                         │
│  3. Check allow_patterns                                │
│     └─► Match? → ALLOW                                  │
│                                                         │
│  4. Check require_approval patterns                     │
│     └─► Match? → PENDING (need approval)                │
│                                                         │
│  5. Default behavior                                    │
│     └─► Unknown → PENDING (need approval)               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Mode Switching

### Via API

```bash
# Get current mode
curl http://127.0.0.1:8765/api/v1/guard/policy

# Switch to strict mode
curl -X POST "http://127.0.0.1:8765/api/v1/guard/policy/mode?mode=strict"
```

### Via Configuration

```yaml
# ~/.faramesh-guard/config.yaml
policy:
  mode: balanced
  custom_patterns:
    allow:
      - pattern: "^my-safe-script\\.sh$"
        risk_level: low
    deny:
      - pattern: "^dangerous-tool\\b"
        risk_level: critical
```

---

## Custom Patterns

Users can add custom patterns that layer on top of mode defaults:

```yaml
# ~/.faramesh-guard/custom_policy.yaml
custom_allow:
  - pattern: "^./my-build-script\\.sh$"
    description: "Project build script"
    risk_level: low

custom_require_approval:
  - pattern: "^./deploy\\.sh"
    description: "Deployment requires review"
    risk_level: high

custom_deny:
  - pattern: "\\bdrop\\s+database\\b"
    description: "Never allow database drops"
    risk_level: critical
```

---

## Policy Compilation

Internally, policies compile to evaluation functions:

```python
class CompiledPolicy:
    def evaluate(self, tool_name: str, args: dict) -> Tuple[Decision, str, str]:
        command = self._extract_command(tool_name, args)

        # 1. Check deny patterns
        for pattern in self.deny_patterns:
            if pattern.match(command):
                return Decision.DENY, pattern.reason, pattern.risk_level

        # 2. Check injection
        if self._has_injection(command):
            return Decision.DENY, "command_injection", "high"

        # 3. Check allow patterns
        for pattern in self.allow_patterns:
            if pattern.match(command):
                return Decision.ALLOW, pattern.reason, pattern.risk_level

        # 4. Check require_approval
        for pattern in self.require_approval_patterns:
            if pattern.match(command):
                return Decision.PENDING, pattern.reason, pattern.risk_level

        # 5. Default
        return Decision.PENDING, "unknown_command", "medium"
```

---

## Injection Detection

All modes include built-in injection detection:

| Pattern | Description |
|---------|-------------|
| `;` | Command chaining |
| `&&` | Conditional execution |
| `\|\|` | Conditional execution |
| `\|` + dangerous target | Pipe to dangerous command |
| `$()` | Command substitution |
| `` ` `` | Command substitution |
| `\n` | Newline injection |

**Safe pipe targets** (not blocked):
- `head`, `tail`, `wc`, `sort`, `uniq`, `grep`, `awk`, `sed`, `less`, `more`

**Dangerous pipe targets** (blocked):
- `cat`, `rm`, `dd`, `mv`, `cp`, `chmod`, `bash`, `sh`, `python`, `eval`

---

## Risk Levels

| Level | Description | Typical Response |
|-------|-------------|-----------------|
| `low` | Safe, read-only | Allow |
| `medium` | Potentially impactful | Require approval |
| `high` | Dangerous, reversible | Require approval with warning |
| `critical` | Catastrophic, irreversible | Deny |

---

## Best Practices

1. **Start with Safe mode**: Understand what your agents are doing
2. **Review approval requests**: Learn your agent's patterns
3. **Gradually relax**: Move to Balanced mode as trust builds
4. **Never use Permissive in production**: Too risky for real systems
5. **Add custom patterns**: Tailor to your specific workflows
6. **Regular audits**: Review audit logs for unexpected patterns

---

*Last Updated: 2024*
