import { Bot, Terminal, Shield, Plus } from 'lucide-react';
import { TrustProfile } from '../types';

// Mock data for demo - in production this would come from the API
const mockTrustProfiles: TrustProfile[] = [
  {
    id: '1',
    name: 'claude-agent',
    type: 'agent',
    trust_level: 'full',
    created_at: Date.now() / 1000 - 86400 * 7,
    last_used: Date.now() / 1000 - 3600,
    usage_count: 156,
  },
  {
    id: '2',
    name: 'read_file',
    type: 'tool',
    trust_level: 'full',
    created_at: Date.now() / 1000 - 86400 * 30,
    usage_count: 892,
  },
  {
    id: '3',
    name: 'run_command',
    type: 'tool',
    trust_level: 'limited',
    created_at: Date.now() / 1000 - 86400 * 30,
    usage_count: 45,
  },
];

const getTypeIcon = (type: string) => {
  switch (type) {
    case 'agent': return Bot;
    case 'tool': return Terminal;
    default: return Shield;
  }
};

const getTrustColor = (level: string) => {
  switch (level) {
    case 'full': return '#22c55e';
    case 'limited': return '#eab308';
    case 'restricted': return '#f97316';
    case 'blocked': return '#ef4444';
    default: return '#6b7280';
  }
};

export default function TrustManagement() {
  return (
    <>
      <div>
        <h3>Trust Profiles</h3>
        <div className="trust-list">
          {mockTrustProfiles.map(profile => {
            const Icon = getTypeIcon(profile.type);
            return (
              <div key={profile.id} className="trust-item">
                <div className="trust-item-left">
                  <div className="trust-item-icon">
                    <Icon size={16} color="var(--text-secondary)" />
                  </div>
                  <div className="trust-item-info">
                    <h5>{profile.name}</h5>
                    <p>{profile.usage_count} uses</p>
                  </div>
                </div>
                <span
                  className="trust-badge"
                  style={{
                    backgroundColor: `${getTrustColor(profile.trust_level)}20`,
                    color: getTrustColor(profile.trust_level),
                  }}
                >
                  {profile.trust_level}
                </span>
              </div>
            );
          })}
        </div>

        <button style={{
          width: '100%',
          marginTop: '0.75rem',
          padding: '0.75rem',
          backgroundColor: 'var(--bg-tertiary)',
          border: '1px dashed var(--border-color)',
          borderRadius: '8px',
          color: 'var(--text-muted)',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '0.5rem',
          fontSize: '0.75rem',
          transition: 'all 0.2s',
        }}>
          <Plus size={14} />
          Add Trust Profile
        </button>
      </div>

      <div className="quick-stats">
        <h4>Today's Summary</h4>
        <div className="quick-stat-row">
          <span className="quick-stat-label">Total Requests</span>
          <span className="quick-stat-value">247</span>
        </div>
        <div className="quick-stat-row">
          <span className="quick-stat-label">Auto-approved</span>
          <span className="quick-stat-value" style={{ color: 'var(--accent-green)' }}>234</span>
        </div>
        <div className="quick-stat-row">
          <span className="quick-stat-label">Manual Review</span>
          <span className="quick-stat-value" style={{ color: 'var(--accent-yellow)' }}>10</span>
        </div>
        <div className="quick-stat-row">
          <span className="quick-stat-label">Blocked</span>
          <span className="quick-stat-value" style={{ color: 'var(--accent-red)' }}>3</span>
        </div>
        <div className="quick-stat-row">
          <span className="quick-stat-label">Avg Latency</span>
          <span className="quick-stat-value">12ms</span>
        </div>
      </div>

      <div className="quick-stats">
        <h4>Policy Status</h4>
        <div className="quick-stat-row">
          <span className="quick-stat-label">Active Rules</span>
          <span className="quick-stat-value">24</span>
        </div>
        <div className="quick-stat-row">
          <span className="quick-stat-label">Last Updated</span>
          <span className="quick-stat-value">2h ago</span>
        </div>
        <div className="quick-stat-row">
          <span className="quick-stat-label">Integrity</span>
          <span className="quick-stat-value" style={{ color: 'var(--accent-green)' }}>✓ Valid</span>
        </div>
      </div>
    </>
  );
}
