// Type definitions for Faramesh Guard UI

export type SafetyMode = 'strict' | 'balanced' | 'permissive';

export interface HealthStatus {
  status: string;
  version: string;
  uptime_seconds: number;
  policy_loaded: boolean;
  components: {
    decision_engine: boolean;
    approval_queue: boolean;
    audit_log: boolean;
  };
}

export interface Activity {
  id: string;
  timestamp: number;
  agent_id: string;
  tool_name: string;
  action: string;
  decision: 'allow' | 'deny' | 'pending';
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  parameters?: Record<string, unknown>;
  reason?: string;
}

export interface PendingApproval {
  request_id: string;
  timestamp: number;
  agent_id: string;
  tool_name: string;
  action: string;
  parameters: Record<string, unknown>;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  reason?: string;
  timeout_seconds?: number;
  expires_at?: number;
}

export interface TrustProfile {
  id: string;
  name: string;
  type: 'agent' | 'tool' | 'pattern';
  trust_level: 'full' | 'limited' | 'restricted' | 'blocked';
  created_at: number;
  last_used?: number;
  usage_count: number;
}

export interface Stats {
  allowed: number;
  denied: number;
  pending: number;
  todayTotal: number;
}
