import React, { useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { ActivityLogEntry } from '../../store/api/dashboardApi';

interface LiveActivityLogProps {
  activities: ActivityLogEntry[];
  isLoading?: boolean;
  autoScroll?: boolean;
}

const ActivityIcon: React.FC<{ eventType: string; severity?: string }> = ({ eventType, severity }) => {
  const getIconAndColor = () => {
    switch (eventType) {
      case 'status_change':
        return {
          icon: (
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clipRule="evenodd" />
            </svg>
          ),
          color: severity === 'error' || severity === 'critical' ? 'text-red-500 bg-red-50' : 
                severity === 'warning' ? 'text-yellow-500 bg-yellow-50' : 'text-blue-500 bg-blue-50'
        };
      case 'alert':
        return {
          icon: (
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
          ),
          color: severity === 'critical' ? 'text-red-500 bg-red-50' : 
                severity === 'warning' ? 'text-yellow-500 bg-yellow-50' : 'text-orange-500 bg-orange-50'
        };
      case 'acknowledgment':
        return {
          icon: (
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
          ),
          color: 'text-green-500 bg-green-50'
        };
      case 'maintenance':
        return {
          icon: (
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd" />
            </svg>
          ),
          color: 'text-blue-500 bg-blue-50'
        };
      default:
        return {
          icon: (
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
          ),
          color: 'text-gray-500 bg-gray-50'
        };
    }
  };

  const { icon, color } = getIconAndColor();

  return (
    <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${color}`}>
      {icon}
    </div>
  );
};

const formatTimestamp = (timestamp: string): string => {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  
  return date.toLocaleDateString();
};

const LoadingSkeleton: React.FC = () => (
  <div className="animate-pulse space-y-4">
    {[...Array(8)].map((_, index) => (
      <div key={index} className="flex items-start space-x-3">
        <div className="w-8 h-8 bg-gray-200 rounded-full"></div>
        <div className="flex-1 space-y-2">
          <div className="h-4 bg-gray-200 rounded w-3/4"></div>
          <div className="h-3 bg-gray-200 rounded w-1/2"></div>
        </div>
        <div className="h-3 bg-gray-200 rounded w-16"></div>
      </div>
    ))}
  </div>
);

export const LiveActivityLog: React.FC<LiveActivityLogProps> = ({ 
  activities, 
  isLoading = false,
  autoScroll = true 
}) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && scrollRef.current && activities.length > 0) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [activities, autoScroll]);

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>Live Activity Log</span>
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
            <span className="text-sm font-normal text-gray-500">Live</span>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <LoadingSkeleton />
        ) : activities.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <svg className="mx-auto h-12 w-12 text-gray-400 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
            <p>No recent activity</p>
          </div>
        ) : (
          <div 
            ref={scrollRef}
            className="space-y-4 max-h-96 overflow-y-auto pr-2"
            style={{ scrollBehavior: 'smooth' }}
          >
            {activities.map((activity) => (
              <div key={activity.id} className="flex items-start space-x-3 group hover:bg-gray-50 p-2 rounded-lg transition-colors">
                <ActivityIcon eventType={activity.event_type} severity={activity.severity} />
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium text-gray-900 truncate">
                      {activity.host_name}
                    </p>
                    <span className="text-xs text-gray-500 flex-shrink-0 ml-2">
                      {formatTimestamp(activity.timestamp)}
                    </span>
                  </div>
                  
                  <p className="text-xs text-gray-600 mb-1">
                    {activity.host_ip}
                  </p>
                  
                  <p className="text-sm text-gray-700">
                    {activity.message}
                  </p>
                  
                  {activity.old_status && activity.new_status && (
                    <div className="flex items-center space-x-2 mt-1">
                      <span className="text-xs px-2 py-1 bg-gray-100 text-gray-600 rounded">
                        {activity.old_status}
                      </span>
                      <svg className="w-3 h-3 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clipRule="evenodd" />
                      </svg>
                      <span className="text-xs px-2 py-1 bg-blue-100 text-blue-600 rounded">
                        {activity.new_status}
                      </span>
                    </div>
                  )}
                  
                  {activity.user && (
                    <p className="text-xs text-gray-500 mt-1">
                      by {activity.user}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};