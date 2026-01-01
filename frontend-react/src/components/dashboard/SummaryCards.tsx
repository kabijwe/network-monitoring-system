import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { DashboardSummary } from '../../store/api/dashboardApi';

interface SummaryCardsProps {
  summary: DashboardSummary;
  isLoading?: boolean;
}

interface SummaryCardProps {
  title: string;
  value: number;
  total: number;
  status: 'up' | 'down' | 'warning' | 'maintenance' | 'unknown';
  isLoading?: boolean;
}

const SummaryCard: React.FC<SummaryCardProps> = ({ 
  title, 
  value, 
  total, 
  status, 
  isLoading = false 
}) => {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'up':
        return 'text-green-600 bg-green-50 border-green-200';
      case 'down':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'warning':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'maintenance':
        return 'text-blue-600 bg-blue-50 border-blue-200';
      case 'unknown':
        return 'text-gray-600 bg-gray-50 border-gray-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'up':
        return (
          <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
          </svg>
        );
      case 'down':
        return (
          <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
          </svg>
        );
      case 'warning':
        return (
          <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
        );
      case 'maintenance':
        return (
          <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd" />
          </svg>
        );
      default:
        return (
          <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
          </svg>
        );
    }
  };

  const percentage = total > 0 ? Math.round((value / total) * 100) : 0;

  return (
    <Card className={`border-2 ${getStatusColor(status)}`}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <div className={`p-2 rounded-full ${getStatusColor(status)}`}>
          {getStatusIcon(status)}
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="animate-pulse">
            <div className="h-8 bg-gray-200 rounded mb-2"></div>
            <div className="h-4 bg-gray-200 rounded w-3/4"></div>
          </div>
        ) : (
          <>
            <div className="text-2xl font-bold">{value.toLocaleString()}</div>
            <p className="text-xs text-gray-600">
              {percentage}% of {total.toLocaleString()} total
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
};

export const SummaryCards: React.FC<SummaryCardsProps> = ({ 
  summary, 
  isLoading = false 
}) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
      <SummaryCard
        title="UP"
        value={summary.up_hosts}
        total={summary.total_hosts}
        status="up"
        isLoading={isLoading}
      />
      <SummaryCard
        title="DOWN"
        value={summary.down_hosts}
        total={summary.total_hosts}
        status="down"
        isLoading={isLoading}
      />
      <SummaryCard
        title="WARNING"
        value={summary.warning_hosts}
        total={summary.total_hosts}
        status="warning"
        isLoading={isLoading}
      />
      <SummaryCard
        title="MAINTENANCE"
        value={summary.maintenance_hosts}
        total={summary.total_hosts}
        status="maintenance"
        isLoading={isLoading}
      />
      <SummaryCard
        title="TOTAL"
        value={summary.total_hosts}
        total={summary.total_hosts}
        status="unknown"
        isLoading={isLoading}
      />
    </div>
  );
};