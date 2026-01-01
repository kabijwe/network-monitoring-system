// User and Authentication Types
export interface User {
  id: string; // UUID from Django
  username: string;
  email: string;
  full_name: string; // Changed from first_name/last_name to match API
  department?: string;
  mfa_enabled: boolean;
  is_staff: boolean;
  is_superuser: boolean;
  is_active?: boolean;
  date_joined?: string;
  roles?: UserRole[];
  locations?: Location[];
  groups?: DeviceGroup[];
}

export interface UserRole {
  role: string; // e.g., 'superadmin', 'admin', etc.
  display_name: string;
  location?: Location | null;
  group?: DeviceGroup | null;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AuthTokens {
  access: string;
  refresh: string;
}

export interface AuthState {
  user: User | null;
  tokens: AuthTokens | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

// Location and Device Types
export interface Location {
  id: number;
  name: string;
  address: string;
  city: string;
  state: string;
  country: string;
  latitude?: number;
  longitude?: number;
  created_at: string;
  updated_at: string;
}

export interface DeviceGroup {
  id: number;
  name: string;
  description: string;
  location: Location;
  created_at: string;
  updated_at: string;
}

export interface Host {
  id: number;
  hostname: string;
  ip_address: string;
  device_type: string;
  location: Location;
  group: DeviceGroup;
  snmp_community?: string;
  snmp_version: '2c' | '3';
  snmp_port: number;
  monitoring_enabled: boolean;
  ping_enabled: boolean;
  snmp_enabled: boolean;
  service_checks_enabled: boolean;
  status: 'up' | 'down' | 'warning' | 'unknown';
  last_check: string;
  created_at: string;
  updated_at: string;
}

// Monitoring Types
export interface MonitoringResult {
  id: number;
  host: Host;
  check_type: 'ping' | 'snmp' | 'service';
  status: 'up' | 'down' | 'warning';
  response_time?: number;
  packet_loss?: number;
  error_message?: string;
  timestamp: string;
}

export interface Alert {
  id: number;
  host: Host;
  alert_type: 'ping_down' | 'snmp_timeout' | 'service_down' | 'threshold_exceeded';
  severity: 'warning' | 'critical';
  message: string;
  status: 'active' | 'acknowledged' | 'resolved';
  created_at: string;
  acknowledged_at?: string;
  acknowledged_by?: User;
  acknowledgment_comment?: string;
  resolved_at?: string;
}

export interface Threshold {
  id: number;
  name: string;
  metric_type: string;
  warning_threshold: number;
  critical_threshold: number;
  hosts: Host[];
  groups: DeviceGroup[];
  created_at: string;
  updated_at: string;
}

// Dashboard Types
export interface DashboardStats {
  total_hosts: number;
  hosts_up: number;
  hosts_down: number;
  hosts_warning: number;
  active_alerts: number;
  acknowledged_alerts: number;
  locations_count: number;
  groups_count: number;
}

export interface LocationHealth {
  location: Location;
  total_hosts: number;
  hosts_up: number;
  hosts_down: number;
  hosts_warning: number;
  health_percentage: number;
}

export interface ActivityLogEntry {
  id: number;
  timestamp: string;
  user?: User;
  action: string;
  target_type: string;
  target_id: number;
  target_name: string;
  details: string;
}

// API Response Types
export interface ApiResponse<T> {
  data: T;
  message?: string;
  success: boolean;
}

export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

// Form Types
export interface HostFormData {
  hostname: string;
  ip_address: string;
  device_type: string;
  location_id: number;
  group_id: number;
  snmp_community?: string;
  snmp_version: '2c' | '3';
  snmp_port: number;
  monitoring_enabled: boolean;
  ping_enabled: boolean;
  snmp_enabled: boolean;
  service_checks_enabled: boolean;
}

export interface LocationFormData {
  name: string;
  address: string;
  city: string;
  state: string;
  country: string;
  latitude?: number;
  longitude?: number;
}

export interface GroupFormData {
  name: string;
  description: string;
  location_id: number;
}

// Table Types
export interface TableColumn<T> {
  key: keyof T;
  label: string;
  sortable?: boolean;
  render?: (value: any, row: T) => React.ReactNode;
}

export interface TableProps<T> {
  data: T[];
  columns: TableColumn<T>[];
  loading?: boolean;
  pagination?: {
    current: number;
    total: number;
    pageSize: number;
    onChange: (page: number) => void;
  };
  onSort?: (key: keyof T, direction: 'asc' | 'desc') => void;
}

// Notification Types
export interface NotificationChannel {
  id: number;
  name: string;
  type: 'email' | 'telegram' | 'slack' | 'teams' | 'sms';
  configuration: Record<string, any>;
  enabled: boolean;
}

export interface NotificationRule {
  id: number;
  name: string;
  conditions: Record<string, any>;
  channels: NotificationChannel[];
  escalation_delay: number;
  enabled: boolean;
}

// Maintenance Types
export interface MaintenanceWindow {
  id: number;
  name: string;
  description: string;
  start_time: string;
  end_time: string;
  hosts: Host[];
  groups: DeviceGroup[];
  suppress_alerts: boolean;
  created_by: User;
  created_at: string;
}

// Export Types
export interface ExportRequest {
  format: 'excel' | 'csv' | 'json' | 'pdf';
  data_type: 'hosts' | 'alerts' | 'logs' | 'reports';
  filters?: Record<string, any>;
  date_range?: {
    start: string;
    end: string;
  };
}