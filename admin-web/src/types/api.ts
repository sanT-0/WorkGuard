export type DeviceStatus = 'enrolled' | 'compliant' | 'noncompliant' | 'stale' | 'revoked' | 'unknown';
export type ControlStatus = 'enforced' | 'partial' | 'failed' | 'unsupported' | 'not_configured' | 'unknown';
export type PolicyLifecycle = 'draft' | 'submitted' | 'approved' | 'published' | 'retired';

export interface ControlResult {
  control_id: string;
  status: ControlStatus;
  provider: string;
  observed_at: string;
  error_code?: string | null;
  safe_details?: string | null;
}

export interface DeviceSummary {
  id: string;
  display_name: string;
  assigned_user_id?: string | null;
  os_version: string;
  agent_version: string;
  status: DeviceStatus;
  last_seen_at?: string | null;
}

export interface DeviceDetail extends DeviceSummary {
  os_edition: string;
  policy_version_desired?: number | null;
  policy_version_observed?: number | null;
  controls: ControlResult[];
}

export interface PolicySummary {
  id: string;
  name: string;
  lifecycle_state: PolicyLifecycle;
  version?: number | null;
  updated_at: string;
}

export interface SecurityEvent {
  id: string;
  device_id?: string | null;
  event_type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  occurred_at: string;
  source: string;
  response_state: string;
}
