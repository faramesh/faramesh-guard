import { useState, useEffect, useCallback } from 'react';
import { Zap, Check, X, RefreshCw } from 'lucide-react';
import { fetch } from '@tauri-apps/api/http';

const GUARD_API = 'http://localhost:8765';

interface LearnedPattern {
  id: string;
  action_type: string;
  agent_id: string;
  context_hash: string;
  confidence: number;
  occurrences: number;
  auto_approve_enabled: boolean;
}

interface BehavioralInsights {
  patterns_learned_24h: number;
  auto_approved_24h: number;
  fatigue_reduction_percent: number;
  top_patterns: LearnedPattern[];
}

export default function BehavioralInsightsCard() {
  const [loading, setLoading] = useState(true);
  const [insights, setInsights] = useState<BehavioralInsights | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);

    try {
      const response = await fetch(`${GUARD_API}/api/v1/guard/insights`, { method: 'GET' });
      if (response.ok) {
        const data = response.data as any;
        if (data.behavioral_insights) setInsights(data.behavioral_insights);
      }
    } catch {
      // Demo data fallback
      setInsights({
        patterns_learned_24h: 8,
        auto_approved_24h: 234,
        fatigue_reduction_percent: 35,
        top_patterns: [
          { id: '1', action_type: 'file_read', agent_id: 'code-assistant', context_hash: 'src/**', confidence: 0.95, occurrences: 127, auto_approve_enabled: true },
          { id: '2', action_type: 'shell_execute', agent_id: 'dev-agent', context_hash: 'npm run *', confidence: 0.89, occurrences: 45, auto_approve_enabled: true },
          { id: '3', action_type: 'http_request', agent_id: 'api-agent', context_hash: 'api.internal/*', confidence: 0.82, occurrences: 89, auto_approve_enabled: false },
        ],
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 20000);
    return () => clearInterval(interval);
  }, [fetchData]);

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-header-left">
          <div className="card-icon bg-blue">
            <Zap size={16} color="white" />
          </div>
          <div>
            <h3 className="card-title">Behavioral Learning</h3>
            <p className="card-subtitle">Automatic pattern detection</p>
          </div>
        </div>
        <span className="badge badge-success">Active</span>
      </div>

      <div className="card-content">
        {loading ? (
          <div className="empty-state">
            <RefreshCw size={20} className="spin text-muted" />
          </div>
        ) : (
          <>
            {/* Stats */}
            <div className="stats-grid">
              <div className="stat-box">
                <div className="stat-box-value text-purple">{insights?.patterns_learned_24h ?? 0}</div>
                <div className="stat-box-label">Learned</div>
              </div>
              <div className="stat-box">
                <div className="stat-box-value text-green">{insights?.auto_approved_24h ?? 0}</div>
                <div className="stat-box-label">Auto OK</div>
              </div>
              <div className="stat-box">
                <div className="stat-box-value text-blue">-{insights?.fatigue_reduction_percent ?? 0}%</div>
                <div className="stat-box-label">Fatigue</div>
              </div>
            </div>

            {/* Patterns List */}
            <div>
              <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', marginBottom: '0.375rem' }}>
                Top Learned Patterns
              </div>
              <div className="card-list">
                {(insights?.top_patterns ?? []).slice(0, 3).map((pattern) => (
                  <div key={pattern.id} className="card-list-item">
                    <div className="card-list-item-left">
                      <div style={{ width: '24px', height: '24px', borderRadius: '4px', display: 'flex', alignItems: 'center', justifyContent: 'center', background: pattern.auto_approve_enabled ? 'rgba(16,185,129,0.1)' : 'rgba(113,113,122,0.1)' }}>
                        {pattern.auto_approve_enabled ? <Check size={12} color="#10b981" /> : <X size={12} color="#71717a" />}
                      </div>
                      <div>
                        <div className="card-list-item-title font-mono">{pattern.action_type}</div>
                        <div className="card-list-item-subtitle">{pattern.agent_id} · {pattern.occurrences}x</div>
                      </div>
                    </div>
                    <span style={{ fontSize: '0.625rem', color: pattern.confidence > 0.9 ? '#10b981' : '#eab308' }}>
                      {(pattern.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Info */}
            <div className="section-divider">
              <div className="metric-row">
                <span className="metric-label">Learning Model</span>
                <span className="metric-value">Contextual Patterns v2</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Min Confidence</span>
                <span className="metric-value">80%</span>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
