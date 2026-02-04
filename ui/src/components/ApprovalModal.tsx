import { X, AlertTriangle, Terminal, FileText, Globe, Clock } from 'lucide-react';
import { PendingApproval } from '../types';

interface ApprovalModalProps {
  approval: PendingApproval;
  onApprove: () => void;
  onDeny: () => void;
  onClose: () => void;
}

const getRiskColor = (level: string) => {
  switch (level) {
    case 'critical': return '#ef4444';
    case 'high': return '#eab308';
    case 'medium': return '#3b82f6';
    default: return '#22c55e';
  }
};

const formatTimeRemaining = (expiresAt?: number) => {
  if (!expiresAt) return null;
  const now = Date.now() / 1000;
  const remaining = expiresAt - now;
  if (remaining <= 0) return 'Expired';
  if (remaining < 60) return `${Math.floor(remaining)}s remaining`;
  return `${Math.floor(remaining / 60)}m remaining`;
};

export default function ApprovalModal({ approval, onApprove, onDeny, onClose }: ApprovalModalProps) {
  const timeRemaining = formatTimeRemaining(approval.expires_at);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>
            <AlertTriangle
              size={18}
              color={getRiskColor(approval.risk_level)}
              style={{ marginRight: '0.5rem', verticalAlign: 'middle' }}
            />
            Approval Required
          </h2>
          <button className="modal-close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <div className="modal-body">
          {/* Risk Badge */}
          <div style={{
            display: 'inline-block',
            padding: '0.25rem 0.75rem',
            borderRadius: '6px',
            fontSize: '0.75rem',
            fontWeight: 600,
            textTransform: 'uppercase',
            backgroundColor: `${getRiskColor(approval.risk_level)}20`,
            color: getRiskColor(approval.risk_level),
            marginBottom: '1rem',
          }}>
            {approval.risk_level} Risk
          </div>

          {/* Time remaining */}
          {timeRemaining && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              fontSize: '0.75rem',
              color: 'var(--accent-yellow)',
              marginBottom: '1rem',
            }}>
              <Clock size={14} />
              {timeRemaining}
            </div>
          )}

          {/* Details */}
          <div style={{ marginBottom: '1.5rem' }}>
            <div style={{
              display: 'grid',
              gridTemplateColumns: '100px 1fr',
              gap: '0.75rem',
              fontSize: '0.875rem',
            }}>
              <span style={{ color: 'var(--text-muted)' }}>Tool:</span>
              <span style={{ fontWeight: 500 }}>{approval.tool_name}</span>

              <span style={{ color: 'var(--text-muted)' }}>Agent:</span>
              <span>{approval.agent_id}</span>

              <span style={{ color: 'var(--text-muted)' }}>Action:</span>
              <span>{approval.action}</span>
            </div>
          </div>

          {/* Parameters */}
          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{
              fontSize: '0.75rem',
              color: 'var(--text-muted)',
              marginBottom: '0.5rem',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}>
              Parameters
            </h4>
            <pre style={{
              backgroundColor: 'var(--bg-tertiary)',
              padding: '1rem',
              borderRadius: '8px',
              fontSize: '0.75rem',
              overflow: 'auto',
              maxHeight: '200px',
              color: 'var(--text-secondary)',
              fontFamily: "'Monaco', 'Menlo', monospace",
            }}>
              {JSON.stringify(approval.parameters, null, 2)}
            </pre>
          </div>

          {/* Reason */}
          {approval.reason && (
            <div style={{
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.2)',
              borderRadius: '8px',
              padding: '1rem',
              fontSize: '0.875rem',
            }}>
              <strong style={{ color: 'var(--accent-red)' }}>Reason for approval:</strong>
              <p style={{ marginTop: '0.5rem', color: 'var(--text-secondary)' }}>
                {approval.reason}
              </p>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button
            className="deny-btn"
            onClick={onDeny}
            style={{ padding: '0.75rem 1.5rem' }}
          >
            Deny
          </button>
          <button
            className="approve-btn"
            onClick={onApprove}
            style={{ padding: '0.75rem 1.5rem' }}
          >
            Approve Action
          </button>
        </div>
      </div>
    </div>
  );
}
