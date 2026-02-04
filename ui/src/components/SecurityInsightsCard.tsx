import { useState, useEffect, useCallback } from 'react';
import { Shield, ShieldCheck, ShieldAlert, AlertTriangle, Activity, Eye, Clock, RefreshCw } from 'lucide-react';
import { fetch } from '@tauri-apps/api/http';

const GUARD_API = 'http://localhost:8765';

interface CriticalMovement {
  type: string;
  description: string;
  timestamp: string;
  severity: 'warning' | 'critical';
}

interface HighRiskAgent {
  agent_id: string;
  risk_score: number;
  flagged_actions: number;
}

interface SecurityInsights {
  overall_risk_level: 'low' | 'medium' | 'high' | 'critical';
  risk_score_avg_24h: number;
  anomalies_detected_24h: number;
  blocked_actions_24h: number;
  high_risk_agents: HighRiskAgent[];
  critical_movements: CriticalMovement[];
  transparency_metrics: {
    log_entries_24h: number;
    verification_success_rate: number;
    tamper_attempts_detected: number;
  };
}

export default function SecurityInsightsCard() {
  const [loading, setLoading] = useState(true);
  const [insights, setInsights] = useState<SecurityInsights | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);

    try {
      const response = await fetch(`${GUARD_API}/api/v1/guard/insights`, { method: 'GET' });
      if (response.ok) setInsights(response.data as SecurityInsights);
    } catch {
      // Demo data fallback
      setInsights({
        overall_risk_level: 'low',
        risk_score_avg_24h: 23,
        anomalies_detected_24h: 3,
        blocked_actions_24h: 12,
        high_risk_agents: [
          { agent_id: 'external-api-bot', risk_score: 72, flagged_actions: 5 },
          { agent_id: 'data-export-agent', risk_score: 65, flagged_actions: 3 },
        ],
        critical_movements: [
          { type: 'data_access', description: 'Large batch export attempted', timestamp: new Date(Date.now() - 3600000).toISOString(), severity: 'warning' },
          { type: 'permission', description: 'Elevated permissions requested', timestamp: new Date(Date.now() - 7200000).toISOString(), severity: 'critical' },
        ],
        transparency_metrics: { log_entries_24h: 1847, verification_success_rate: 99.8, tamper_attempts_detected: 0 },
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const getRiskColor = (level: string) => {
    const colors: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#10b981' };
    return colors[level] || colors.low;
  };

  const getRiskIcon = (level: string) => {
    if (level === 'critical' || level === 'high') return <ShieldAlert size={16} />;
    if (level === 'medium') return <Shield size={16} />;
    return <ShieldCheck size={16} />;
  };

  const formatTime = (timestamp: string) => {
    const diff = Date.now() - new Date(timestamp).getTime();
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    return `${Math.floor(diff / 3600000)}h ago`;
  };

  const level = insights?.overall_risk_level ?? 'low';
  const color = getRiskColor(level);

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-header-left">
          <div className="card-icon" style={{ background: `linear-gradient(135deg, ${color}, ${color}80)` }}>
            {getRiskIcon(level)}
          </div>
          <div>
            <h3 className="card-title">Security Insights</h3>
            <p className="card-subtitle">Real-time threat monitoring</p>
          </div>
        </div>
        <span className="badge" style={{ background: `${color}18`, color }}>{level} risk</span>
      </div>

      <div className="card-content">
        {loading ? (
          <div className="empty-state">
            <RefreshCw size={20} className="spin text-muted" />
          </div>
        ) : (
          <>
            {/* Key Metrics */}
            <div className="stats-grid">
              <div className="stat-box">
                <div className="stat-box-value">{insights?.risk_score_avg_24h ?? 0}</div>
                <div className="stat-box-label">Avg Score</div>
              </div>
              <div className="stat-box">
                <div className="stat-box-value text-yellow">{insights?.anomalies_detected_24h ?? 0}</div>
                <div className="stat-box-label">Anomalies</div>
              </div>
              <div className="stat-box">
                <div className="stat-box-value text-red">{insights?.blocked_actions_24h ?? 0}</div>
                <div className="stat-box-label">Blocked</div>
              </div>
            </div>

            {/* Critical Movements */}
            {insights?.critical_movements && insights.critical_movements.length > 0 && (
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.625rem', color: 'var(--text-muted)', marginBottom: '0.375rem' }}>
                  <Activity size={10} /> Critical Movements
                </div>
                <div className="card-list">
                  {insights.critical_movements.slice(0, 2).map((m, i) => (
                    <div
                      key={i}
                      className="card-list-item"
                      style={{ borderLeft: `2px solid ${m.severity === 'critical' ? '#ef4444' : '#f97316'}` }}
                    >
                      <div className="card-list-item-left">
                        <AlertTriangle size={12} color={m.severity === 'critical' ? '#ef4444' : '#f97316'} />
                        <div>
                          <div className="card-list-item-title">{m.description}</div>
                          <div className="card-list-item-subtitle"><Clock size={8} /> {formatTime(m.timestamp)}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* High Risk Agents */}
            {insights?.high_risk_agents && insights.high_risk_agents.length > 0 && (
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.625rem', color: 'var(--text-muted)', marginBottom: '0.375rem' }}>
                  <Eye size={10} /> High Risk Agents
                </div>
                <div className="card-list">
                  {insights.high_risk_agents.slice(0, 2).map((agent, i) => (
                    <div key={i} className="card-list-item">
                      <span className="font-mono card-list-item-title">{agent.agent_id}</span>
                      <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.625rem' }}>
                        <span style={{ color: getRiskColor(agent.risk_score >= 70 ? 'high' : 'medium') }}>{agent.risk_score}%</span>
                        <span className="text-muted">{agent.flagged_actions} flagged</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Metrics Footer */}
            <div className="section-divider">
              <div className="metric-row">
                <span className="metric-label">Audit Log (24h)</span>
                <span className="metric-value">{insights?.transparency_metrics.log_entries_24h ?? 0}</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Verification</span>
                <span className="metric-value text-green">{insights?.transparency_metrics.verification_success_rate ?? 0}%</span>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
