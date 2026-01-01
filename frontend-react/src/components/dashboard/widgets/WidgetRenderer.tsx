import React from 'react';
import { BaseWidget } from './WidgetTypes';
import { SummaryCards } from '../SummaryCards';
import { LocationOverview } from '../LocationOverview';
import { LiveActivityLog } from '../LiveActivityLog';
import { ChartWidget } from './ChartWidget';
import { MapWidget } from './MapWidget';
import { Top10ListWidget } from './Top10ListWidget';

interface WidgetRendererProps {
  widget: BaseWidget;
  dashboardData?: any;
  isLoading?: boolean;
}

export const WidgetRenderer: React.FC<WidgetRendererProps> = ({
  widget,
  dashboardData,
  isLoading = false
}) => {
  const renderWidgetContent = () => {
    switch (widget.type) {
      case 'summary-cards':
        return (
          <SummaryCards
            summary={dashboardData?.summary || {
              total_hosts: 0,
              up_hosts: 0,
              down_hosts: 0,
              warning_hosts: 0,
              maintenance_hosts: 0,
              unknown_hosts: 0
            }}
            isLoading={isLoading}
          />
        );

      case 'location-overview':
        return (
          <LocationOverview
            locations={dashboardData?.location_health || []}
            isLoading={isLoading}
          />
        );

      case 'activity-log':
        return (
          <LiveActivityLog
            activities={dashboardData?.recent_activity || []}
            isLoading={isLoading}
            autoScroll={true}
          />
        );

      case 'chart':
        return (
          <ChartWidget
            config={{
              chartType: 'line',
              metric: 'latency',
              timeRange: '24h',
              refreshInterval: 30,
              ...widget.config
            }}
          />
        );

      case 'map':
        return (
          <MapWidget
            config={{
              showLabels: true,
              colorBy: 'status',
              zoomLevel: 10,
              ...widget.config
            }}
          />
        );

      case 'top-10-list':
        return (
          <Top10ListWidget
            config={{
              metric: 'latency',
              sortOrder: 'desc',
              showValues: true,
              timeRange: '24h',
              ...widget.config
            }}
          />
        );

      default:
        return (
          <div className="h-full flex items-center justify-center text-gray-500">
            <div className="text-center">
              <svg className="w-12 h-12 mx-auto mb-2 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
              <p className="text-sm">Unknown widget type</p>
              <p className="text-xs text-gray-400">{widget.type}</p>
            </div>
          </div>
        );
    }
  };

  return (
    <div className="h-full">
      {renderWidgetContent()}
    </div>
  );
};