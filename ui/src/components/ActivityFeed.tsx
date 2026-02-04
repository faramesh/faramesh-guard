import { useState } from 'react';
import { Check, X, Clock, Terminal, FileText, Globe, Database } from 'lucide-react';
import { Activity, PendingApproval } from '../types';

interface ActivityFeedProps {
  activities: Activity[];
  pendingApprovals: PendingApproval[];
  onApprovalClick: (approval: PendingApproval) => void;
}

type FilterType = 'all' | 'pending' | 'allowed' | 'denied';

const getToolIcon = (toolName: string) => {
  const lowerName = toolName.toLowerCase();
  if (lowerName.includes('bash') || lowerName.includes('terminal') || lowerName.includes('shell')) {
    return Terminal;
  }
  if (lowerName.includes('file') || lowerName.includes('read') || lowerName.includes('write')) {
    return FileText;
  }
  if (lowerName.includes('http') || lowerName.includes('browser') || lowerName.includes('fetch')) {
    return Globe;
  }
  return Database;
};

const formatTime = (timestamp: number) => {
  const date = new Date(timestamp * 1000);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
  return date.toLocaleDateString();
};

const truncateParams = (params: Record<string, unknown>) => {
  const str = JSON.stringify(params);
  if (str.length > 80) return str.slice(0, 77) + '...';
  return str;
};

export default function ActivityFeed({ activities, pendingApprovals, onApprovalClick }: ActivityFeedProps) {
  const [filter, setFilter] = useState<FilterType>('all');

  // Combine and sort items
  const allItems = [
    ...pendingApprovals.map(p => ({
      ...p,
      id: p.request_id,
      decision: 'pending' as const,
      isPending: true,
    })),
    ...activities.map(a => ({
      ...a,
      isPending: false,
    })),
  ].sort((a, b) => b.timestamp - a.timestamp);

  const filteredItems = allItems.filter(item => {
    if (filter === 'all') return true;
    if (filter === 'pending') return item.decision === 'pending';
    if (filter === 'allowed') return item.decision === 'allow';
    if (filter === 'denied') return item.decision === 'deny';
    return true;
  });

  return (
    <>
      <div className="panel-header">
        <h3>Activity Feed</h3>
        <div className="filter-buttons">
          {(['all', 'pending', 'allowed', 'denied'] as FilterType[]).map(f => (
            <button
              key={f}
              className={`filter-btn ${filter === f ? 'active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
              {f === 'pending' && pendingApprovals.length > 0 && (
                <span style={{
                  marginLeft: '0.25rem',
                  backgroundColor: 'var(--accent-yellow)',
                  color: 'black',
                  padding: '0 0.375rem',
                  borderRadius: '4px',
                  fontSize: '0.625rem',
                  fontWeight: 600,
                }}>
                  {pendingApprovals.length}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="activity-feed">
        {filteredItems.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">📋</div>
            <h4>No activity yet</h4>
            <p>Actions from AI agents will appear here</p>
          </div>
        ) : (
          filteredItems.map(item => {
            const Icon = getToolIcon(item.tool_name);
            const isPending = item.decision === 'pending';

            return (
              <div
                key={item.id}
                className={`activity-item ${isPending ? 'pending' : ''}`}
                onClick={() => isPending && onApprovalClick(item as PendingApproval)}
                style={isPending ? { cursor: 'pointer' } : undefined}
              >
                <div className={`activity-icon ${item.decision}`}>
                  {item.decision === 'allow' && <Check size={20} />}
                  {item.decision === 'deny' && <X size={20} />}
                  {item.decision === 'pending' && <Clock size={20} />}
                </div>

                <div className="activity-content">
                  <div className="activity-header">
                    <span className="activity-tool">
                      <Icon size={14} style={{ marginRight: '0.25rem', verticalAlign: 'middle' }} />
                      {item.tool_name}
                    </span>
                    <span className="activity-time">{formatTime(item.timestamp)}</span>
                  </div>

                  <div className="activity-agent">
                    Agent: {item.agent_id}
                    <span style={{
                      marginLeft: '0.5rem',
                      padding: '0.125rem 0.375rem',
                      borderRadius: '4px',
                      fontSize: '0.625rem',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      backgroundColor:
                        item.risk_level === 'critical' ? 'rgba(239, 68, 68, 0.2)' :
                        item.risk_level === 'high' ? 'rgba(234, 179, 8, 0.2)' :
                        item.risk_level === 'medium' ? 'rgba(59, 130, 246, 0.2)' :
                        'rgba(34, 197, 94, 0.2)',
                      color:
                        item.risk_level === 'critical' ? 'var(--accent-red)' :
                        item.risk_level === 'high' ? 'var(--accent-yellow)' :
                        item.risk_level === 'medium' ? 'var(--accent-blue)' :
                        'var(--accent-green)',
                    }}>
                      {item.risk_level}
                    </span>
                  </div>

                  {item.parameters && Object.keys(item.parameters).length > 0 && (
                    <div className="activity-params">
                      {truncateParams(item.parameters)}
                    </div>
                  )}

                  {isPending && (
                    <div className="approval-actions">
                      <button
                        className="approve-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          onApprovalClick(item as PendingApproval);
                        }}
                      >
                        Review & Approve
                      </button>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </>
  );
}
