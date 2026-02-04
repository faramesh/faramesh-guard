-- Guard Transparency Log Schema
-- Implements a Merkle tree / Certificate Transparency style log

-- Log entries (leaves of the Merkle tree)
CREATE TABLE IF NOT EXISTS log_entries (
    leaf_index INTEGER PRIMARY KEY,
    leaf_hash TEXT NOT NULL,
    entry_type TEXT NOT NULL DEFAULT 'v1',
    artifact_hash TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    version TEXT,
    timestamp TEXT NOT NULL,
    metadata TEXT DEFAULT '{}',

    -- Index for artifact lookups
    UNIQUE(artifact_hash, artifact_type)
);

-- Index for efficient range queries
CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON log_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_entries_type ON log_entries(artifact_type);

-- Tree metadata (root hash, size, etc.)
CREATE TABLE IF NOT EXISTS tree_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Signed Tree Heads (checkpoints)
CREATE TABLE IF NOT EXISTS signed_tree_heads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_size INTEGER NOT NULL,
    root_hash TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sth_size ON signed_tree_heads(tree_size);

-- Initialize metadata
INSERT OR IGNORE INTO tree_metadata (key, value) VALUES ('root_hash', '');
INSERT OR IGNORE INTO tree_metadata (key, value) VALUES ('timestamp', datetime('now'));
INSERT OR IGNORE INTO tree_metadata (key, value) VALUES ('tree_size', '0');
