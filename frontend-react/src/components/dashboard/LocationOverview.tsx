import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { LocationHealth } from '../../store/api/dashboardApi';

interface LocationOverviewProps {
  locations: LocationHealth[];
  isLoading?: boolean;
}

const StatusBadge: React.FC<{ status: 'healthy' | 'warning' | 'critical' }> = ({ status }) => {
  const getStatusStyles = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'warning':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getStatusStyles(status)}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
};

const HealthBar: React.FC<{ percentage: number; status: 'healthy' | 'warning' | 'critical' }> = ({ 
  percentage, 
  status 
}) => {
  const getBarColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'bg-green-500';
      case 'warning':
        return 'bg-yellow-500';
      case 'critical':
        return 'bg-red-500';
      default:
        return 'bg-gray-500';
    }
  };

  return (
    <div className="w-full bg-gray-200 rounded-full h-2">
      <div
        className={`h-2 rounded-full transition-all duration-300 ${getBarColor(status)}`}
        style={{ width: `${Math.max(0, Math.min(100, percentage))}%` }}
      />
    </div>
  );
};

const LoadingSkeleton: React.FC = () => (
  <div className="animate-pulse">
    {[...Array(5)].map((_, index) => (
      <div key={index} className="border-b border-gray-200 py-4">
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <div className="h-4 bg-gray-200 rounded w-1/3 mb-2"></div>
            <div className="h-3 bg-gray-200 rounded w-1/4 mb-2"></div>
            <div className="h-2 bg-gray-200 rounded w-full"></div>
          </div>
          <div className="ml-4">
            <div className="h-6 bg-gray-200 rounded-full w-16"></div>
          </div>
        </div>
      </div>
    ))}
  </div>
);

export const LocationOverview: React.FC<LocationOverviewProps> = ({ 
  locations, 
  isLoading = false 
}) => {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>Location Overview</span>
          <span className="text-sm font-normal text-gray-500">
            Health Status
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <LoadingSkeleton />
        ) : locations.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <svg className="mx-auto h-12 w-12 text-gray-400 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            <p>No locations found</p>
          </div>
        ) : (
          <div className="space-y-4 max-h-96 overflow-y-auto">
            {locations.map((location) => (
              <div key={location.id} className="border-b border-gray-200 pb-4 last:border-b-0">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex-1">
                    <h4 className="font-medium text-gray-900">{location.name}</h4>
                    <p className="text-sm text-gray-500">
                      {location.up_hosts} UP, {location.down_hosts} DOWN, {location.warning_hosts} WARNING
                      {location.maintenance_hosts > 0 && `, ${location.maintenance_hosts} MAINTENANCE`}
                    </p>
                  </div>
                  <StatusBadge status={location.status} />
                </div>
                
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-600">Health: {location.health_percentage}%</span>
                    <span className="text-gray-600">{location.total_hosts} hosts</span>
                  </div>
                  <HealthBar percentage={location.health_percentage} status={location.status} />
                </div>
                
                {/* Detailed breakdown */}
                <div className="mt-3 grid grid-cols-4 gap-2 text-xs">
                  <div className="text-center">
                    <div className="font-medium text-green-600">{location.up_hosts}</div>
                    <div className="text-gray-500">UP</div>
                  </div>
                  <div className="text-center">
                    <div className="font-medium text-red-600">{location.down_hosts}</div>
                    <div className="text-gray-500">DOWN</div>
                  </div>
                  <div className="text-center">
                    <div className="font-medium text-yellow-600">{location.warning_hosts}</div>
                    <div className="text-gray-500">WARN</div>
                  </div>
                  <div className="text-center">
                    <div className="font-medium text-blue-600">{location.maintenance_hosts}</div>
                    <div className="text-gray-500">MAINT</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};