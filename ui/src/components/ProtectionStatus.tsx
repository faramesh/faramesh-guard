import { Shield, ShieldAlert, ShieldOff, Activity, CheckCircle, XCircle } from 'lucide-react';
import { HealthStatus, Stats } from '../types';

interface ProtectionStatusProps {
  connected: boolean;
  health: HealthStatus | null;
  stats: Stats;
}

export default function ProtectionStatus({ connected, health, stats }: ProtectionStatusProps) {
  const getStatusIcon = () => {
    if (!connected) {
      return <ShieldOff size={24} />;
    }
    if (health?.status === 'healthy') {
      return <Shield size={24} />;
    }
    return <ShieldAlert size={24} />;
  };

  const getStatusClass = () => {
    if (!connected) return 'error';
    if (health?.status === 'healthy') return 'active';
    return 'paused';
  };

  const getStatusText = () => {
    if (!connected) return 'Disconnected';
    if (health?.status === 'healthy') return 'Protection Active';
    return 'Issues Detected';
  };

  const getStatusDescription = () => {
    if (!connected) return 'Cannot connect to Guard daemon';
    if (health?.status === 'healthy') {
      return `Running v${health.version}`;
    }
    return 'Some components may not be working';
  };

  const formatUptime = (seconds: number) => {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
    return `${Math.floor(seconds / 86400)}d`;
  };

  return (
    <div className="protection-status">
      <div className="status-header">
        <div className={`status-icon ${getStatusClass()}`}>
          {getStatusIcon()}
        </div>
        <div className="status-text">
          <h3>{getStatusText()}</h3>
          <p>{getStatusDescription()}</p>
        </div>
      </div>

      <div className="status-stats">
        <div className="stat-item">
          <div className="stat-value" style={{ color: '#22c55e' }}>
            {stats.allowed}
          </div>
          <div className="stat-label">Allowed</div>
        </div>
        <div className="stat-item">
          <div className="stat-value" style={{ color: '#ef4444' }}>
            {stats.denied}
          </div>
          <div className="stat-label">Denied</div>
        </div>
        <div className="stat-item">
          <div className="stat-value" style={{ color: '#eab308' }}>
            {stats.pending}
          </div>
          <div className="stat-label">Pending</div>
        </div>
        <div className="stat-item">
          <div className="stat-value" style={{ color: '#3b82f6' }}>
            {connected && health ? formatUptime(health.uptime_seconds) : '--'}
          </div>
          <div className="stat-label">Uptime</div>
        </div>
      </div>

      {/* Component Health */}
      {connected && health && (
        <div style={{ marginTop: '1rem', borderTop: '1px solid var(--border-color)', paddingTop: '1rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
            Components
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            {Object.entries(health.components).map(([name, status]) => (
              <div key={name} style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '0.75rem'
              }}>
                <span style={{ color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                  {name.replace('_', ' ')}
                </span>
                {status ? (
                  <CheckCircle size={14} color="var(--accent-green)" />
                ) : (
                  <XCircle size={14} color="var(--accent-red)" />
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
