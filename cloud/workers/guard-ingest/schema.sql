-- Faramesh Guard Fleet Database Schema
-- Run: wrangler d1 execute guard-fleet --file=schema.sql

-- Guard instances (one row per device)
CREATE TABLE IF NOT EXISTS instances (
    instance_id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    first_seen DATETIME DEFAULT (datetime('now')),
    last_heartbeat DATETIME NOT NULL,
    protection_enabled INTEGER DEFAULT 1,
    protection_mode TEXT DEFAULT 'standard',
    uptime_seconds INTEGER DEFAULT 0,
    total_requests INTEGER DEFAULT 0,
    approved INTEGER DEFAULT 0,
    denied INTEGER DEFAULT 0,
    pending INTEGER DEFAULT 0,
    policy_hash TEXT,
    ml_model_version TEXT,
    organization_id TEXT,
    tags TEXT -- JSON array of tags
);

-- Index for finding stale instances
CREATE INDEX IF NOT EXISTS idx_instances_last_heartbeat ON instances(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_instances_org ON instances(organization_id);

-- Interception proofs (cryptographic evidence Guard is in the path)
CREATE TABLE IF NOT EXISTS interception_proofs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    action_hash TEXT NOT NULL,
    decision TEXT NOT NULL,
    signature TEXT NOT NULL,
    policy_hash TEXT,
    received_at DATETIME DEFAULT (datetime('now')),
    verified INTEGER DEFAULT 0,
    FOREIGN KEY (instance_id) REFERENCES instances(instance_id)
);

CREATE INDEX IF NOT EXISTS idx_proofs_instance ON interception_proofs(instance_id);
CREATE INDEX IF NOT EXISTS idx_proofs_timestamp ON interception_proofs(timestamp);

-- Daily aggregated statistics
CREATE TABLE IF NOT EXISTS daily_stats (
    date TEXT NOT NULL,
    event_type TEXT NOT NULL,
    count INTEGER DEFAULT 0,
    PRIMARY KEY (date, event_type)
);

-- Pending commands to send to Guard instances
CREATE TABLE IF NOT EXISTS pending_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL, -- '*' for broadcast to all
    command_type TEXT NOT NULL, -- 'emergency_block', 'force_update', 'policy_sync', etc.
    command_data TEXT, -- JSON payload
    created_at DATETIME DEFAULT (datetime('now')),
    executed_at DATETIME,
    expires_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_commands_instance ON pending_commands(instance_id);
CREATE INDEX IF NOT EXISTS idx_commands_pending ON pending_commands(executed_at) WHERE executed_at IS NULL;

-- Emergency blocklist (global kill switch for malicious patterns)
CREATE TABLE IF NOT EXISTS emergency_blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL,
    pattern_type TEXT NOT NULL, -- 'agent_id', 'tool', 'resource', 'hash'
    reason TEXT,
    created_at DATETIME DEFAULT (datetime('now')),
    expires_at DATETIME,
    active INTEGER DEFAULT 1
);

-- Policy assignments (which policy version each org/instance should use)
CREATE TABLE IF NOT EXISTS policy_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT,
    instance_id TEXT,
    policy_version TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    assigned_at DATETIME DEFAULT (datetime('now')),
    UNIQUE(organization_id, instance_id)
);

-- Minimum version requirements (force upgrade outdated clients)
CREATE TABLE IF NOT EXISTS min_version_requirements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL, -- 'darwin', 'linux', 'windows', '*'
    min_version TEXT NOT NULL,
    reason TEXT,
    created_at DATETIME DEFAULT (datetime('now')),
    enforced INTEGER DEFAULT 0 -- 0 = warn, 1 = block
);

-- Model calibration data (for ML improvements)
CREATE TABLE IF NOT EXISTS model_calibration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_version TEXT NOT NULL,
    calibration_type TEXT NOT NULL, -- 'threshold', 'weight', 'feature'
    calibration_data TEXT NOT NULL, -- JSON
    deployed_at DATETIME DEFAULT (datetime('now')),
    active INTEGER DEFAULT 1
);

-- Views for analytics

CREATE VIEW IF NOT EXISTS fleet_summary AS
SELECT
    COUNT(*) as total_instances,
    COUNT(CASE WHEN last_heartbeat > datetime('now', '-5 minutes') THEN 1 END) as active_instances,
    COUNT(CASE WHEN last_heartbeat > datetime('now', '-1 hour') THEN 1 END) as recent_instances,
    COUNT(CASE WHEN protection_enabled = 1 THEN 1 END) as protected_instances,
    SUM(total_requests) as total_requests,
    SUM(approved) as total_approved,
    SUM(denied) as total_denied
FROM instances;

CREATE VIEW IF NOT EXISTS version_distribution AS
SELECT
    version,
    platform,
    COUNT(*) as instance_count,
    COUNT(CASE WHEN last_heartbeat > datetime('now', '-1 hour') THEN 1 END) as active_count
FROM instances
GROUP BY version, platform
ORDER BY instance_count DESC;
