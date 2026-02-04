import { useState, useEffect } from 'react';
import {
  CalendarDays,
  Download,
  Filter,
  Search,
  Check,
  X,
  Clock,
  Terminal,
  FileText,
  Globe,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { Activity } from '../types';

interface HistoryViewProps {
  activities?: Activity[];
}

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
  return Terminal;
};

const formatDate = (timestamp: number) => {
  return new Date(timestamp * 1000).toLocaleString();
};

// Mock history data
const mockHistory: Activity[] = [
  {
    id: '1',
    timestamp: Date.now() / 1000 - 300,
    agent_id: 'claude-agent-1',
    tool_name: 'read_file',
    action: 'read',
    decision: 'allow',
    risk_level: 'low',
    parameters: { path: '/src/main.ts' },
  },
  {
    id: '2',
    timestamp: Date.now() / 1000 - 600,
    agent_id: 'claude-agent-1',
    tool_name: 'bash',
    action: 'execute',
    decision: 'allow',
    risk_level: 'medium',
    parameters: { command: 'npm test' },
  },
  {
    id: '3',
    timestamp: Date.now() / 1000 - 900,
    agent_id: 'claude-agent-1',
    tool_name: 'bash',
    action: 'execute',
    decision: 'deny',
    risk_level: 'high',
    parameters: { command: 'rm -rf /tmp/cache' },
    reason: 'Dangerous command pattern detected',
  },
  {
    id: '4',
    timestamp: Date.now() / 1000 - 1200,
    agent_id: 'copilot-agent',
    tool_name: 'write_file',
    action: 'write',
    decision: 'allow',
    risk_level: 'medium',
    parameters: { path: '/src/utils.ts', content: '...' },
  },
];

export default function HistoryView({ activities }: HistoryViewProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [dateFilter, setDateFilter] = useState('today');
  const [decisionFilter, setDecisionFilter] = useState<string | null>(null);
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());

  const data = activities || mockHistory;

  const filteredHistory = data.filter(item => {
    if (searchQuery && !item.tool_name.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !item.agent_id.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    if (decisionFilter && item.decision !== decisionFilter) {
      return false;
    }
    return true;
  });

  const toggleExpand = (id: string) => {
    const newExpanded = new Set(expandedItems);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedItems(newExpanded);
  };

  const getDecisionIcon = (decision: string) => {
    switch (decision) {
      case 'allow': return <Check size={14} color="#22c55e" />;
      case 'deny': return <X size={14} color="#ef4444" />;
      case 'pending': return <Clock size={14} color="#eab308" />;
      default: return null;
    }
  };

  return (
    <div style={{
      backgroundColor: 'var(--bg-secondary)',
      borderRadius: '12px',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        padding: '1rem 1.5rem',
        borderBottom: '1px solid var(--border-color)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Action History</h3>
        <button style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.5rem 1rem',
          backgroundColor: 'var(--bg-tertiary)',
          border: '1px solid var(--border-color)',
          borderRadius: '6px',
          color: 'var(--text-secondary)',
          fontSize: '0.75rem',
          cursor: 'pointer',
        }}>
          <Download size={14} />
          Export
        </button>
      </div>

      {/* Filters */}
      <div style={{
        padding: '1rem 1.5rem',
        borderBottom: '1px solid var(--border-color)',
        display: 'flex',
        gap: '0.75rem',
        flexWrap: 'wrap',
      }}>
        {/* Search */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          backgroundColor: 'var(--bg-tertiary)',
          padding: '0.5rem 1rem',
          borderRadius: '6px',
          flex: 1,
          minWidth: '200px',
        }}>
          <Search size={14} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Search by tool or agent..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-primary)',
              fontSize: '0.875rem',
              width: '100%',
              outline: 'none',
            }}
          />
        </div>

        {/* Date filter */}
        <select
          value={dateFilter}
          onChange={e => setDateFilter(e.target.value)}
          style={{
            padding: '0.5rem 1rem',
            backgroundColor: 'var(--bg-tertiary)',
            border: '1px solid var(--border-color)',
            borderRadius: '6px',
            color: 'var(--text-secondary)',
            fontSize: '0.75rem',
            cursor: 'pointer',
          }}
        >
          <option value="today">Today</option>
          <option value="week">This Week</option>
          <option value="month">This Month</option>
          <option value="all">All Time</option>
        </select>

        {/* Decision filter buttons */}
        <div style={{ display: 'flex', gap: '0.25rem' }}>
          {['allow', 'deny', 'pending'].map(d => (
            <button
              key={d}
              onClick={() => setDecisionFilter(decisionFilter === d ? null : d)}
              style={{
                padding: '0.5rem 0.75rem',
                backgroundColor: decisionFilter === d ?
                  d === 'allow' ? 'rgba(34, 197, 94, 0.2)' :
                  d === 'deny' ? 'rgba(239, 68, 68, 0.2)' :
                  'rgba(234, 179, 8, 0.2)' :
                  'var(--bg-tertiary)',
                border: `1px solid ${decisionFilter === d ?
                  d === 'allow' ? '#22c55e' :
                  d === 'deny' ? '#ef4444' :
                  '#eab308' :
                  'var(--border-color)'}`,
                borderRadius: '6px',
                color: decisionFilter === d ?
                  d === 'allow' ? '#22c55e' :
                  d === 'deny' ? '#ef4444' :
                  '#eab308' :
                  'var(--text-secondary)',
                fontSize: '0.75rem',
                cursor: 'pointer',
                textTransform: 'capitalize',
              }}
            >
              {d}
            </button>
          ))}
        </div>
      </div>

      {/* History List */}
      <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
        {filteredHistory.length === 0 ? (
          <div style={{
            padding: '3rem',
            textAlign: 'center',
            color: 'var(--text-muted)'
          }}>
            No matching history entries
          </div>
        ) : (
          filteredHistory.map(item => {
            const Icon = getToolIcon(item.tool_name);
            const isExpanded = expandedItems.has(item.id);

            return (
              <div
                key={item.id}
                style={{
                  borderBottom: '1px solid var(--border-color)',
                }}
              >
                {/* Main row */}
                <div
                  onClick={() => toggleExpand(item.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '0.75rem 1.5rem',
                    cursor: 'pointer',
                    transition: 'background-color 0.2s',
                  }}
                >
                  {/* Expand icon */}
                  <div style={{ marginRight: '0.5rem', color: 'var(--text-muted)' }}>
                    {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  </div>

                  {/* Decision icon */}
                  <div style={{ marginRight: '0.75rem' }}>
                    {getDecisionIcon(item.decision)}
                  </div>

                  {/* Tool info */}
                  <div style={{ flex: 1 }}>
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      fontSize: '0.875rem',
                      fontWeight: 500,
                    }}>
                      <Icon size={14} color="var(--text-secondary)" />
                      {item.tool_name}
                    </div>
                    <div style={{
                      fontSize: '0.75rem',
                      color: 'var(--text-muted)',
                      marginTop: '0.125rem',
                    }}>
                      {item.agent_id}
                    </div>
                  </div>

                  {/* Time */}
                  <div style={{
                    fontSize: '0.75rem',
                    color: 'var(--text-muted)',
                  }}>
                    {formatDate(item.timestamp)}
                  </div>
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <div style={{
                    padding: '1rem 1.5rem',
                    paddingLeft: '3.5rem',
                    backgroundColor: 'var(--bg-tertiary)',
                    borderTop: '1px solid var(--border-color)',
                  }}>
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: '100px 1fr',
                      gap: '0.5rem',
                      fontSize: '0.75rem',
                    }}>
                      <span style={{ color: 'var(--text-muted)' }}>Action:</span>
                      <span>{item.action}</span>

                      <span style={{ color: 'var(--text-muted)' }}>Risk Level:</span>
                      <span style={{
                        textTransform: 'uppercase',
                        color: item.risk_level === 'high' || item.risk_level === 'critical'
                          ? 'var(--accent-red)'
                          : item.risk_level === 'medium'
                          ? 'var(--accent-yellow)'
                          : 'var(--accent-green)',
                      }}>
                        {item.risk_level}
                      </span>

                      <span style={{ color: 'var(--text-muted)' }}>Parameters:</span>
                      <pre style={{
                        backgroundColor: 'var(--bg-secondary)',
                        padding: '0.5rem',
                        borderRadius: '4px',
                        fontSize: '0.7rem',
                        overflow: 'auto',
                        margin: 0,
                      }}>
                        {JSON.stringify(item.parameters, null, 2)}
                      </pre>

                      {item.reason && (
                        <>
                          <span style={{ color: 'var(--text-muted)' }}>Reason:</span>
                          <span style={{ color: 'var(--accent-red)' }}>{item.reason}</span>
                        </>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
