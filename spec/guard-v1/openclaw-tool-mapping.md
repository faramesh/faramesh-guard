# Faramesh Guard v1: OpenClaw Tool Mapping

> **Version**: 1.0.0
> **Status**: Production Ready

This document defines how OpenClaw tools map to CAR (Canonical Action Representation) fields.

---

## Tool Categories

### 1. Execution Tools (`exec`)

Tools that execute system commands or processes.

| OpenClaw Tool | CAR.tool | CAR.operation | CAR.target_kind | Sensitivity Extracted |
|--------------|----------|---------------|-----------------|----------------------|
| `bash` | exec | execute | process | Secrets in args, destructive patterns, sudo |
| `shell` | exec | execute | process | Same as bash |
| `run_command` | exec | execute | process | Same as bash |
| `python` | exec | execute | process | Code analysis, imports |
| `node` | exec | execute | process | Code analysis, requires |

**Sensitivity Detection**:
- Secrets: `AWS_`, `API_KEY`, `SECRET`, `PASSWORD`, `TOKEN`
- Destructive: `rm -rf`, `dd if=`, `mkfs`, `format`
- Privilege: `sudo`, `su -`, `chmod 777`, `chown`

---

### 2. Filesystem Tools (`fs`)

Tools that read or write files.

| OpenClaw Tool | CAR.tool | CAR.operation | CAR.target_kind | Sensitivity Extracted |
|--------------|----------|---------------|-----------------|----------------------|
| `read_file` | fs | read | filesystem | PII in path, system paths |
| `write_file` | fs | write | filesystem | PII in content, home dir |
| `edit_file` | fs | modify | filesystem | Same as write |
| `delete_file` | fs | delete | filesystem | System paths, scope |
| `create_directory` | fs | create | filesystem | Path analysis |
| `list_directory` | fs | read | filesystem | Path analysis |

**Sensitivity Detection**:
- PII paths: `/home/`, `/Users/`, `/etc/passwd`, `~`
- System paths: `/etc/`, `/var/`, `/usr/`, `/bin/`
- Sensitive files: `.env`, `.ssh/`, `credentials`, `secrets`

---

### 3. Network Tools (`http`)

Tools that make HTTP requests.

| OpenClaw Tool | CAR.tool | CAR.operation | CAR.target_kind | Sensitivity Extracted |
|--------------|----------|---------------|-----------------|----------------------|
| `http_request` | http | fetch | network | External domain, data in body |
| `curl` | http | fetch | network | URL analysis, headers |
| `fetch` | http | fetch | network | Same as http_request |
| `download` | http | fetch | network | URL analysis |
| `upload` | http | send | network | Data exfil detection |

**Sensitivity Detection**:
- External: Non-localhost, non-internal domains
- Data exfil: POST with large body to external
- Credentials: Auth headers, API keys in URL

---

### 4. Communication Tools (`communication`)

Tools that send messages to people.

| OpenClaw Tool | CAR.tool | CAR.operation | CAR.target_kind | Sensitivity Extracted |
|--------------|----------|---------------|-----------------|----------------------|
| `email.send` | communication | send | person | Recipient domain, financial refs, CRM relationship |
| `slack.message` | communication | send | person | Channel, mentions |
| `discord.send` | communication | send | person | Channel, mentions |
| `sms.send` | communication | send | person | Phone number, content |

**Sensitivity Detection**:
- External recipient: Domain not in org
- Unknown recipient: Not in CRM/contacts
- Financial content: Money amounts, account numbers
- PII content: Names, addresses, SSN

---

### 5. API Tools (`api`)

Tools that call external APIs.

| OpenClaw Tool | CAR.tool | CAR.operation | CAR.target_kind | Sensitivity Extracted |
|--------------|----------|---------------|-----------------|----------------------|
| `stripe.refund` | api | modify | financial | Money amount, customer ID |
| `stripe.charge` | api | create | financial | Money amount, card info |
| `github.create_issue` | api | create | api | Repo, content |
| `aws.s3_upload` | api | create | api | Bucket, data size |
| `database.query` | api | read | api | SQL analysis |
| `database.execute` | api | modify | api | SQL analysis (DDL, DML) |

**Sensitivity Detection**:
- Financial: Money amounts, transaction IDs
- Database: DROP, DELETE, TRUNCATE statements
- Cloud: Region, bucket names, IAM

---

### 6. Browser Tools (`browser`)

Tools that interact with web browsers.

| OpenClaw Tool | CAR.tool | CAR.operation | CAR.target_kind | Sensitivity Extracted |
|--------------|----------|---------------|-----------------|----------------------|
| `browser.navigate` | browser | fetch | network | URL analysis |
| `browser.click` | browser | modify | network | Target element |
| `browser.fill_form` | browser | send | network | Form data analysis |
| `browser.screenshot` | browser | read | network | URL, visible content |

**Sensitivity Detection**:
- Login forms: Password fields
- Financial forms: Credit card, bank account
- PII forms: SSN, address, phone

---

## Risk Classification

### Technical Risk

Based on system impact:

| Level | Criteria |
|-------|----------|
| `low` | Read-only, scoped to workspace |
| `medium` | Write operations in workspace |
| `high` | System paths, sudo, network |
| `critical` | Destructive, irreversible, system-wide |

### Economic Risk

Based on financial impact:

| Level | Criteria |
|-------|----------|
| `low` | No financial impact |
| `medium` | < $100 or reversible |
| `high` | $100-$10,000 or customer impact |
| `critical` | > $10,000 or legal liability |

### Operational Risk

Based on business impact:

| Level | Criteria |
|-------|----------|
| `low` | No disruption |
| `medium` | Minor workflow impact |
| `high` | Service degradation |
| `critical` | Outage, data loss |

---

## Extraction Confidence

CAR extraction confidence based on tool clarity:

| Confidence | Description |
|------------|-------------|
| 0.95+ | Exact tool match, clear semantics |
| 0.80-0.94 | Tool recognized, some inference |
| 0.60-0.79 | Partial extraction, heuristics used |
| < 0.60 | Low confidence, manual review needed |

**Low confidence triggers**:
- Unknown tool name
- Ambiguous arguments
- Complex nested commands
- Dynamic code generation

---

## Example Mappings

### Example 1: File Read

**Tool Call**:
```json
{
  "tool": "read_file",
  "args": {"path": "/home/alice/documents/report.pdf"}
}
```

**CAR**:
```json
{
  "tool": "fs",
  "operation": "read",
  "target_kind": "filesystem",
  "target": "/home/alice/documents/report.pdf",
  "scope": "single",
  "sensitivity": {
    "contains_pii": false,
    "contains_home_dir": true
  },
  "risk_tags": ["system_path"],
  "technical_risk": "low",
  "economic_risk": "low",
  "operational_risk": "low",
  "extraction_confidence": 0.95
}
```

### Example 2: Shell Command

**Tool Call**:
```json
{
  "tool": "bash",
  "args": {"command": "rm -rf ./temp/*"}
}
```

**CAR**:
```json
{
  "tool": "exec",
  "operation": "execute",
  "target_kind": "process",
  "target": "rm -rf ./temp/*",
  "scope": "recursive",
  "sensitivity": {
    "contains_pii": false,
    "contains_secrets": false
  },
  "risk_tags": ["destructive", "irreversible"],
  "technical_risk": "medium",
  "economic_risk": "low",
  "operational_risk": "medium",
  "extraction_confidence": 0.95
}
```

### Example 3: External API

**Tool Call**:
```json
{
  "tool": "stripe.refund",
  "args": {
    "transaction_id": "ch_xyz123",
    "amount": 5000,
    "reason": "customer_request"
  }
}
```

**CAR**:
```json
{
  "tool": "api",
  "operation": "modify",
  "target_kind": "financial",
  "target": "stripe.refund",
  "destination": "stripe.com",
  "destination_external": true,
  "scope": "single",
  "sensitivity": {
    "contains_financial_ref": true,
    "money_amount": 50.00
  },
  "risk_tags": ["financial", "external_communication"],
  "technical_risk": "low",
  "economic_risk": "medium",
  "operational_risk": "low",
  "extraction_confidence": 0.95
}
```

---

## Adding New Tools

To add a new tool mapping:

1. **Identify category**: Which CAR.tool does it belong to?
2. **Map operation**: What operation type (read, write, execute, etc.)?
3. **Define target_kind**: What resource type is affected?
4. **Extract sensitivity**: What sensitive data might be involved?
5. **Classify risk**: Technical, economic, operational impact?
6. **Set confidence**: How reliable is the extraction?

---

*Last Updated: 2024*
