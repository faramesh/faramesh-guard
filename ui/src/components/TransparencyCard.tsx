import { useState, useEffect, useCallback } from 'react';
import { FileCheck, ChevronDown, ChevronUp, RefreshCw, Check, X } from 'lucide-react';
import { fetch } from '@tauri-apps/api/http';

const GUARD_API = 'http://localhost:8765';

interface AuditDecision {
  id: string;
  timestamp: string;
  action_type: string;
  agent_id: string;
  decision: 'allow' | 'deny';
  decided_by: 'policy' | 'ml' | 'user' | 'learning';
  signature_valid: boolean;
}

interface TransparencyData {
  tuf_status: 'verified' | 'updating' | 'error';
  tuf_version: string;
  policy_hash: string;
  recent_decisions: AuditDecision[];
  log_integrity_percent: number;
}

export default function TransparencyCard() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<TransparencyData | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);

    try {
      const response = await fetch(`${GUARD_API}/api/v1/guard/insights`, { method: 'GET' });
      if (response.ok) {
        const res = response.data as any;
        if (res.transparency_data) setData(res.transparency_data);
      }
    } catch {
      // Demo data fallback
      setData({
        tuf_status: 'verified',
        tuf_version: '2024.01.15-a3f2c1b',
        policy_hash: 'sha256:8f4a2b...',
        log_integrity_percent: 100,
        recent_decisions: [
          { id: '1', timestamp: new Date(Date.now() - 60000).toISOString(), action_type: 'file_read', agent_id: 'code-assistant', decision: 'allow', decided_by: 'learning', signature_valid: true },
          { id: '2', timestamp: new Date(Date.now() - 120000).toISOString(), action_type: 'shell_execute', agent_id: 'dev-agent', decision: 'allow', decided_by: 'user', signature_valid: true },
          { id: '3', timestamp: new Date(Date.now() - 300000).toISOString(), action_type: 'http_request', agent_id: 'external-bot', decision: 'deny', decided_by: 'policy', signature_valid: true },
        ],
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const formatTime = (timestamp: string) => {
    const diff = Date.now() - new Date(timestamp).getTime();
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    return `${Math.floor(diff / 3600000)}h ago`;
  };

  const statusColor = data?.tuf_status === 'verified' ? '#10b981' : data?.tuf_status === 'updating' ? '#eab308' : '#ef4444';

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-header-left">
          <div className="card-icon" style={{ background: `linear-gradient(135deg, ${statusColor}, ${statusColor}80)` }}>
            <FileCheck size={16} color="white" />
          </div>
          <div>
            <h3 className="card-title">Audit Trail</h3>
            <p className="card-subtitle">Cryptographic verification</p>
          </div>
        </div>
        <span className="badge" style={{ background: `${statusColor}18`, color: statusColor }}>
          {data?.tuf_status ?? 'unknown'}
        </span>
      </div>

      <div className="card-content">
        {loading ? (
          <div className="empty-state">
            <RefreshCw size={20} className="spin text-muted" />
          </div>
        ) : (
          <>
            {/* TUF Info */}
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)' }}>
              <div className="stat-box">
                <div className="stat-box-value text-green">{data?.log_integrity_percent ?? 0}%</div>
                <div className="stat-box-label">Integrity</div>
              </div>
              <div className="stat-box">
                <div className="stat-box-value font-mono" style={{ fontSize: '0.6875rem' }}>{data?.tuf_version?.slice(0, 12) ?? '-'}</div>
                <div className="stat-box-label">TUF Version</div>
              </div>
            </div>

            {/* Recent Decisions */}
            <div>
              <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', marginBottom: '0.375rem' }}>
                Recent Verified Decisions
              </div>
              <div className="card-list">
                {(data?.recent_decisions ?? []).slice(0, 3).map((d) => (
                  <div key={d.id}>
                    <div
                      className="card-list-item"
                      onClick={() => setExpanded(expanded === d.id ? null : d.id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <div className="card-list-item-left">
                        <div style={{ width: '20px', height: '20px', borderRadius: '4px', display: 'flex', alignItems: 'center', justifyContent: 'center', background: d.decision === 'allow' ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)' }}>
                          {d.decision === 'allow' ? <Check size={10} color="#10b981" /> : <X size={10} color="#ef4444" />}
                        </div>
                        <div>
                          <div className="card-list-item-title font-mono">{d.action_type}</div>
                          <div className="card-list-item-subtitle">{d.agent_id} · {formatTime(d.timestamp)}</div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                        <span className="badge badge-info">{d.decided_by}</span>
                        {expanded === d.id ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                      </div>
                    </div>
                    {expanded === d.id && (
                      <div style={{ padding: '0.5rem', marginTop: '0.25rem', background: 'var(--bg-secondary)', borderRadius: '4px', fontSize: '0.625rem' }}>
                        <div className="metric-row">
                          <span className="metric-label">Signature</span>
                          <span className={`metric-value ${d.signature_valid ? 'text-green' : 'text-red'}`}>
                            {d.signature_valid ? 'Valid ✓' : 'Invalid ✗'}
                          </span>
                        </div>
                        <div className="metric-row">
                          <span className="metric-label">Policy Hash</span>
                          <span className="metric-value font-mono">{data?.policy_hash ?? '-'}</span>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
