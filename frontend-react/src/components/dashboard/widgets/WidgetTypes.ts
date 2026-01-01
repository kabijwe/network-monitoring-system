export interface BaseWidget {
  id: string;
  type: WidgetType;
  title: string;
  position: {
    x: number;
    y: number;
  };
  size: {
    width: number;
    height: number;
  };
  config: Record<string, any>;
}

export type WidgetType = 
  | 'summary-cards'
  | 'location-overview'
  | 'activity-log'
  | 'chart'
  | 'map'
  | 'top-10-list';

export interface ChartWidgetConfig {
  chartType: 'line' | 'bar' | 'pie' | 'area';
  metric: string;
  timeRange: '1h' | '6h' | '24h' | '7d' | '30d';
  refreshInterval: number;
}

export interface MapWidgetConfig {
  showLabels: boolean;
  colorBy: 'status' | 'location' | 'group';
  zoomLevel: number;
  centerLat?: number;
  centerLng?: number;
}

export interface Top10ListConfig {
  metric: 'latency' | 'packet_loss' | 'uptime' | 'traffic_in' | 'traffic_out';
  sortOrder: 'asc' | 'desc';
  showValues: boolean;
  timeRange: '1h' | '6h' | '24h' | '7d';
}

export interface WidgetLayout {
  id: string;
  name: string;
  widgets: BaseWidget[];
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface DragItem {
  type: string;
  id: string;
  widget?: BaseWidget;
}

export const WIDGET_TYPES: Record<WidgetType, { name: string; description: string; defaultSize: { width: number; height: number } }> = {
  'summary-cards': {
    name: 'Summary Cards',
    description: 'Device status overview cards',
    defaultSize: { width: 12, height: 2 }
  },
  'location-overview': {
    name: 'Location Overview',
    description: 'Location health table',
    defaultSize: { width: 6, height: 4 }
  },
  'activity-log': {
    name: 'Activity Log',
    description: 'Live activity feed',
    defaultSize: { width: 6, height: 4 }
  },
  'chart': {
    name: 'Chart',
    description: 'Time-series charts and graphs',
    defaultSize: { width: 6, height: 4 }
  },
  'map': {
    name: 'Network Map',
    description: 'Interactive network topology',
    defaultSize: { width: 8, height: 6 }
  },
  'top-10-list': {
    name: 'Top 10 List',
    description: 'Top devices by metric',
    defaultSize: { width: 4, height: 4 }
  }
};