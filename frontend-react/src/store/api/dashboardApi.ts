import { apiSlice } from './apiSlice';

export interface DashboardSummary {
  total_hosts: number;
  up_hosts: number;
  down_hosts: number;
  warning_hosts: number;
  maintenance_hosts: number;
  unknown_hosts: number;
}

export interface LocationHealth {
  id: number;
  name: string;
  total_hosts: number;
  up_hosts: number;
  down_hosts: number;
  warning_hosts: number;
  maintenance_hosts: number;
  health_percentage: number;
  status: 'healthy' | 'warning' | 'critical';
}

export interface ActivityLogEntry {
  id: number;
  timestamp: string;
  host_name: string;
  host_ip: string;
  event_type: 'status_change' | 'alert' | 'acknowledgment' | 'maintenance';
  old_status?: string;
  new_status?: string;
  message: string;
  user?: string;
  severity?: 'info' | 'warning' | 'error' | 'critical';
}

export interface DashboardData {
  summary: DashboardSummary;
  location_health: LocationHealth[];
  recent_activity: ActivityLogEntry[];
  last_updated: string;
}

export const dashboardApi = apiSlice.injectEndpoints({
  endpoints: (builder) => ({
    getDashboardData: builder.query<DashboardData, void>({
      query: () => 'dashboard/',
      providesTags: ['Host', 'Alert', 'ActivityLog'],
    }),
    
    getDashboardSummary: builder.query<DashboardSummary, void>({
      query: () => 'dashboard/summary/',
      providesTags: ['Host'],
    }),
    
    getLocationHealth: builder.query<LocationHealth[], void>({
      query: () => 'dashboard/locations/',
      providesTags: ['Host', 'Location'],
    }),
    
    getRecentActivity: builder.query<ActivityLogEntry[], { limit?: number }>({
      query: ({ limit = 50 } = {}) => `dashboard/activity/?limit=${limit}`,
      providesTags: ['ActivityLog', 'Alert'],
    }),
  }),
});

export const {
  useGetDashboardDataQuery,
  useGetDashboardSummaryQuery,
  useGetLocationHealthQuery,
  useGetRecentActivityQuery,
} = dashboardApi;