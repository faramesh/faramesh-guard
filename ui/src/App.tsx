import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { fetch } from '@tauri-apps/api/http';
import { sendNotification } from '@tauri-apps/api/notification';
import ProtectionStatus from './components/ProtectionStatus';
import SafetyModeSelector from './components/SafetyModeSelector';
import ActivityFeed from './components/ActivityFeed';
import ApprovalModal from './components/ApprovalModal';
import TrustManagement from './components/TrustManagement';
import MLRiskCard from './components/MLRiskCard';
import BehavioralInsightsCard from './components/BehavioralInsightsCard';
import SecurityInsightsCard from './components/SecurityInsightsCard';
import TransparencyCard from './components/TransparencyCard';
import { Activity, SafetyMode, HealthStatus, PendingApproval } from './types';
import { Shield, Wifi, WifiOff, LayoutDashboard, Activity as ActivityIcon } from 'lucide-react';

const GUARD_API = 'http://localhost:8765';

function App() {
  const [connected, setConnected] = useState(false);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [safetyMode, setSafetyMode] = useState<SafetyMode>('balanced');
  const [activities, setActivities] = useState<Activity[]>([]);
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>([]);
  const [selectedApproval, setSelectedApproval] = useState<PendingApproval | null>(null);
  const [activeView, setActiveView] = useState<'activity' | 'insights'>('activity');
  const [stats, setStats] = useState({
    allowed: 0,
    denied: 0,
    pending: 0,
    todayTotal: 0,
  });

  // Check Guard health
  const checkHealth = useCallback(async () => {
    try {
      const response = await fetch(`${GUARD_API}/health`, {
        method: 'GET',
        timeout: 5,
      });

      if (response.ok) {
        setConnected(true);
        setHealth(response.data as HealthStatus);
      } else {
        setConnected(false);
        setHealth(null);
      }
    } catch (error) {
      setConnected(false);
      setHealth(null);
    }
  }, []);

  // Fetch pending approvals
  const fetchPendingApprovals = useCallback(async () => {
    if (!connected) return;

    try {
      const response = await fetch(`${GUARD_API}/pending`, {
        method: 'GET',
      });

      if (response.ok) {
        const data = response.data as { pending: PendingApproval[] };
        setPendingApprovals(data.pending);
        setStats(prev => ({ ...prev, pending: data.pending.length }));

        // Notify on new approvals
        if (data.pending.length > 0 && pendingApprovals.length === 0) {
          sendNotification({
            title: 'Approval Required',
            body: `${data.pending.length} action(s) waiting for approval`,
          });
        }
      }
    } catch (error) {
      console.error('Failed to fetch pending approvals:', error);
    }
  }, [connected, pendingApprovals.length]);

  // Fetch activity history
  const fetchActivities = useCallback(async () => {
    if (!connected) return;

    try {
      const response = await fetch(`${GUARD_API}/history?limit=50`, {
        method: 'GET',
      });

      if (response.ok) {
        const data = response.data as { history: Activity[] };
        setActivities(data.history);

        // Calculate stats
        const today = new Date().toDateString();
        const todayActivities = data.history.filter(
          a => new Date(a.timestamp * 1000).toDateString() === today
        );

        setStats(prev => ({
          ...prev,
          allowed: todayActivities.filter(a => a.decision === 'allow').length,
          denied: todayActivities.filter(a => a.decision === 'deny').length,
          todayTotal: todayActivities.length,
        }));
      }
    } catch (error) {
      console.error('Failed to fetch activities:', error);
    }
  }, [connected]);

  // Handle approval decision
  const handleApprovalDecision = async (requestId: string, approved: boolean) => {
    try {
      const response = await fetch(`${GUARD_API}/approve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: {
          type: 'Json',
          payload: {
            request_id: requestId,
            approved,
            approver: 'user',
          },
        },
      });

      if (response.ok) {
        // Refresh data
        await fetchPendingApprovals();
        await fetchActivities();
        setSelectedApproval(null);
      }
    } catch (error) {
      console.error('Failed to submit approval:', error);
    }
  };

  // Handle safety mode change
  const handleSafetyModeChange = async (mode: SafetyMode) => {
    setSafetyMode(mode);

    // TODO: Send mode change to Guard API when endpoint exists
    console.log('Safety mode changed to:', mode);
  };

  // Polling effect
  useEffect(() => {
    // Initial check
    checkHealth();
    fetchPendingApprovals();
    fetchActivities();

    // Set up polling
    const healthInterval = setInterval(checkHealth, 5000);
    const approvalInterval = setInterval(fetchPendingApprovals, 2000);
    const activityInterval = setInterval(fetchActivities, 10000);

    return () => {
      clearInterval(healthInterval);
      clearInterval(approvalInterval);
      clearInterval(activityInterval);
    };
  }, [checkHealth, fetchPendingApprovals, fetchActivities]);

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <div className="logo">
            <div className="logo-icon">
              <Shield size={18} color="white" />
            </div>
            <span className="logo-text">Faramesh Guard</span>
          </div>
          <div className="connection-status">
            <span className={`connection-dot ${connected ? 'connected' : 'disconnected'}`} />
            {connected ? (
              <>
                <Wifi size={14} />
                <span>Connected to Guard</span>
              </>
            ) : (
              <>
                <WifiOff size={14} />
                <span>Disconnected</span>
              </>
            )}
          </div>
        </div>

        {/* View Toggle */}
        <div className="view-toggle">
          <button
            onClick={() => setActiveView('activity')}
            className={`${activeView === 'activity' ? 'active activity' : ''}`}
          >
            <ActivityIcon size={14} />
            Activity
          </button>
          <button
            onClick={() => setActiveView('insights')}
            className={`${activeView === 'insights' ? 'active insights' : ''}`}
          >
            <LayoutDashboard size={14} />
            Insights
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="main">
        {/* Left Sidebar */}
        <aside className="sidebar">
          <ProtectionStatus
            connected={connected}
            health={health}
            stats={stats}
          />
          <SafetyModeSelector
            mode={safetyMode}
            onModeChange={handleSafetyModeChange}
          />
        </aside>

        {/* Center - Activity Feed or Enterprise Insights */}
        {activeView === 'activity' ? (
          <section className="activity-panel">
            <ActivityFeed
              activities={activities}
              pendingApprovals={pendingApprovals}
              onApprovalClick={setSelectedApproval}
            />
          </section>
        ) : (
          <section className="insights-panel">
            <div className="insights-header">
              <h2>Enterprise Security Insights</h2>
              <p>Real-time ML risk analysis, behavioral learning, and cryptographic audit trail</p>
            </div>

            {/* Insights Grid */}
            <div className="insights-grid">
              <SecurityInsightsCard />
              <MLRiskCard />
              <BehavioralInsightsCard />
              <TransparencyCard />
            </div>
          </section>
        )}

        {/* Right Sidebar */}
        <aside className="trust-panel">
          <TrustManagement />
        </aside>
      </main>

      {/* Approval Modal */}
      {selectedApproval && (
        <ApprovalModal
          approval={selectedApproval}
          onApprove={() => handleApprovalDecision(selectedApproval.request_id, true)}
          onDeny={() => handleApprovalDecision(selectedApproval.request_id, false)}
          onClose={() => setSelectedApproval(null)}
        />
      )}
    </div>
  );
}

export default App;
