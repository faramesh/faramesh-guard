# Faramesh Guard v1: CAR Canonicalization Specification

> **Version**: 1.0.0
> **Status**: CRITICAL - Must be followed exactly for audit integrity

This document defines the deterministic canonicalization algorithm for CAR (Canonical Action Representation). Correct implementation is essential for:
- Audit log integrity (hash chain)
- Replay protection (same action = same hash)
- Permit validation (permit embeds car_hash)

---

## Canonical JSON Serialization

### Field Ordering

CARs MUST be serialized with keys in **lexicographic order** (Unicode codepoint order).

```json
{
  "agent_id": "...",
  "car_hash": "(computed after canonicalization)",
  "context": { /* sorted keys */ },
  "destination": "...",
  "destination_external": true,
  "economic_risk": "...",
  "extraction_confidence": 0.95,
  "operation": "...",
  "operational_risk": "...",
  "risk_tags": [/* sorted */],
  "scope": "...",
  "sensitivity": { /* sorted keys */ },
  "session_id": "...",
  "target": "...",
  "target_kind": "...",
  "technical_risk": "...",
  "timestamp": "...",
  "tool": "...",
  "workspace_id": "..."
}
```

### JSON Formatting

- No whitespace between tokens
- No trailing commas
- UTF-8 encoding
- No BOM (Byte Order Mark)

**Example (canonical form)**:
```
{"agent_id":"claude","destination":"user@example.com","operation":"send","target":"email","tool":"communication"}
```

---

## Normalization Rules

### Path Normalization

All filesystem paths MUST be normalized:

| Input | Canonical Form |
|-------|---------------|
| `/home/alice/./docs/../files/test.txt` | `/home/alice/files/test.txt` |
| `~/Documents/file.txt` | `/home/alice/Documents/file.txt` |
| `./temp/../data/file.txt` | `data/file.txt` |
| `/foo//bar///baz` | `/foo/bar/baz` |
| `C:\Users\Alice\file.txt` | `C:/Users/Alice/file.txt` |

**Rules**:
1. Resolve `.` and `..` components
2. Expand `~` to absolute home directory
3. Normalize path separators to `/`
4. Remove duplicate separators
5. Resolve symlinks if possible
6. Keep trailing slash for directories

### Domain Normalization

All domains MUST be normalized:

| Input | Canonical Form |
|-------|---------------|
| `Example.COM.` | `example.com` |
| `HTTPS://API.Example.COM:443/path` | `https://api.example.com/path` |
| `http://example.com:80/` | `http://example.com/` |
| `münchen.de` (IDN) | `xn--mnchen-3ya.de` (punycode) |

**Rules**:
1. Lowercase domain names
2. Strip trailing dots
3. Convert IDN to punycode
4. Remove default ports (80 for HTTP, 443 for HTTPS)
5. Lowercase scheme

### Email Normalization

All email addresses MUST be normalized:

| Input | Canonical Form |
|-------|---------------|
| `John@Client.COM ` | `john@client.com` |
| `  Alice.Smith@EXAMPLE.org  ` | `alice.smith@example.org` |

**Rules**:
1. Trim leading/trailing whitespace
2. Lowercase local part and domain
3. Validate format (reject invalid addresses)

### Command Normalization

Shell commands MUST be normalized:

| Input | Canonical Form |
|-------|---------------|
| `  rm   -rf   "file"  ` | `rm -rf "file"` |
| `ls -la` | `ls -la` |
| `echo 'hello  world'` | `echo 'hello  world'` |

**Rules**:
1. Trim leading/trailing whitespace
2. Collapse multiple spaces (outside quotes)
3. Preserve quoted strings exactly
4. Normalize newlines to space (for single-line representation)

### Timestamp Normalization

All timestamps MUST be in ISO 8601 UTC format:

| Input | Canonical Form |
|-------|---------------|
| `2026-02-03T12:30:45Z` | `2026-02-03T12:30:45.000Z` |
| `2026-02-03T12:30:45.1Z` | `2026-02-03T12:30:45.100Z` |
| `2026-02-03T07:30:45-05:00` | `2026-02-03T12:30:45.000Z` |

**Rules**:
1. Convert to UTC
2. Always include milliseconds (3 digits)
3. Use `Z` suffix (not `+00:00`)

### Array Normalization

Arrays MUST be sorted lexicographically:

| Input | Canonical Form |
|-------|---------------|
| `["destructive", "irreversible", "system_path"]` | `["destructive", "irreversible", "system_path"]` |
| `["z", "a", "m"]` | `["a", "m", "z"]` |

**Rules**:
1. Sort array elements lexicographically
2. Case-sensitive comparison
3. Deduplicate identical elements

---

## Hashing Procedure

### Step 1: Prepare CAR for Hashing

Remove the `car_hash` field (it's computed, not input):

```python
def prepare_for_hash(car: dict) -> dict:
    car_copy = car.copy()
    car_copy.pop('car_hash', None)
    return car_copy
```

### Step 2: Normalize All Fields

Apply normalization rules to each field:

```python
def normalize_car(car: dict) -> dict:
    normalized = {}
    for key in sorted(car.keys()):
        value = car[key]
        if key == 'target' and car.get('target_kind') == 'filesystem':
            value = normalize_path(value)
        elif key == 'destination' and car.get('target_kind') == 'person':
            value = normalize_email(value)
        elif key == 'destination' and car.get('target_kind') == 'network':
            value = normalize_domain(value)
        elif key == 'timestamp':
            value = normalize_timestamp(value)
        elif key == 'risk_tags' and isinstance(value, list):
            value = sorted(set(value))
        elif isinstance(value, dict):
            value = normalize_car(value)  # Recurse
        normalized[key] = value
    return normalized
```

### Step 3: Serialize to Canonical JSON

```python
import json

def canonical_json(car: dict) -> str:
    def sort_dict(obj):
        if isinstance(obj, dict):
            return {k: sort_dict(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            return sorted([sort_dict(x) for x in obj])
        return obj

    sorted_car = sort_dict(car)
    return json.dumps(sorted_car, separators=(',', ':'), ensure_ascii=False)
```

### Step 4: Compute SHA-256 Hash

```python
import hashlib

def compute_car_hash(car: dict) -> str:
    prepared = prepare_for_hash(car)
    normalized = normalize_car(prepared)
    canonical = canonical_json(normalized)
    hash_bytes = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    return f"sha256:{hash_bytes}"
```

---

## Identity vs Metadata Fields

### Identity Fields (Part of Hash)

These fields define the **action identity** - two CARs with the same identity are the same action:

- `tool`
- `operation`
- `target`
- `target_kind`
- `destination`
- `destination_external`
- `scope`
- `sensitivity` (all subfields)
- `risk_tags`

### Metadata Fields (NOT Part of Hash)

These fields are contextual and may vary for the same action:

- `agent_id` - Who is performing (context)
- `session_id` - When/where (context)
- `workspace_id` - Environment (context)
- `timestamp` - When (timing)
- `extraction_confidence` - Quality signal
- `context` - Ambient context

**Note**: The current implementation includes all fields in the hash for simplicity. Future versions may optimize to hash only identity fields.

---

## Test Vectors

### Vector 1: Simple Command

**Input**:
```json
{
  "tool": "exec",
  "operation": "execute",
  "target": "ls -la",
  "target_kind": "process"
}
```

**Canonical Form**:
```
{"operation":"execute","target":"ls -la","target_kind":"process","tool":"exec"}
```

**Expected Hash**:
```
sha256:a1b2c3... (compute with reference implementation)
```

### Vector 2: Path Normalization

**Input**:
```json
{
  "tool": "fs",
  "operation": "read",
  "target": "/home/alice/./docs/../files/test.txt",
  "target_kind": "filesystem"
}
```

**Canonical Form** (after path normalization):
```
{"operation":"read","target":"/home/alice/files/test.txt","target_kind":"filesystem","tool":"fs"}
```

### Vector 3: Email Normalization

**Input**:
```json
{
  "tool": "communication",
  "operation": "send",
  "target": "email",
  "target_kind": "person",
  "destination": "  John.Doe@EXAMPLE.COM  "
}
```

**Canonical Form**:
```
{"destination":"john.doe@example.com","operation":"send","target":"email","target_kind":"person","tool":"communication"}
```

---

## Implementation Notes

1. **Determinism is critical**: Same input MUST always produce same hash
2. **Test thoroughly**: Use property-based testing with random inputs
3. **Version the algorithm**: If canonicalization changes, hash prefix changes
4. **Handle edge cases**: Empty strings, null values, Unicode

---

## Changelog

| Version | Changes |
|---------|---------|
| 1.0.0 | Initial specification |

---

*Last Updated: 2024*
