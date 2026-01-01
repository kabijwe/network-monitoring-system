import React from 'react';
import { Top10ListConfig } from './WidgetTypes';

interface Top10ListWidgetProps {
  config: Top10ListConfig;
}

interface DeviceMetric {
  id: string;
  name: string;
  ip: string;
  value: number;
  unit: string;
  status: 'up' | 'down' | 'warning' | 'maintenance';
}

export const Top10ListWidget: React.FC<Top10ListWidgetProps> = ({ config }) => {
  // Generate sample data based on the selected metric
  const generateSampleData = (): DeviceMetric[] => {
    const devices = [
      { id: '1', name: 'Router-Core-01', ip: '192.168.1.1' },
      { id: '2', name: 'Switch-Floor-2A', ip: '192.168.2.10' },
      { id: '3', name: 'AP-Lobby-01', ip: '192.168.3.15' },
      { id: '4', name: 'AP-Office-12', ip: '192.168.3.28' },
      { id: '5', name: 'Firewall-DMZ', ip: '192.168.1.254' },
      { id: '6', name: 'Switch-Floor-1B', ip: '192.168.2.5' },
      { id: '7', name: 'AP-Conference', ip: '192.168.3.42' },
      { id: '8', name: 'Router-Backup', ip: '192.168.1.2' },
      { id: '9', name: 'AP-Cafeteria', ip: '192.168.3.33' },
      { id: '10', name: 'Switch-Server', ip: '192.168.2.100' },
    ];

    const statuses: Array<'up' | 'down' | 'warning' | 'maintenance'> = ['up', 'up', 'up', 'warning', 'up', 'down', 'up', 'maintenance', 'up', 'up'];

    return devices.map((device, index) => {
      let value: number;
      let unit: string;

      switch (config.metric) {
        case 'latency':
          value = Math.random() * 200 + 10; // 10-210ms
          unit = 'ms';
          break;
        case 'packet_loss':
          value = Math.random() * 15; // 0-15%
          unit = '%';
          break;
        case 'uptime':
          value = Math.random() * 100; // 0-100%
          unit = '%';
          break;
        case 'traffic_in':
          value = Math.random() * 1000; // 0-1000 Mbps
          unit = 'Mbps';
          break;
        case 'traffic_out':
          value = Math.random() * 800; // 0-800 Mbps
          unit = 'Mbps';
          break;
        default:
          value = Math.random() * 100;
          unit = '';
      }

      return {
        ...device,
        value: Math.round(value * 100) / 100,
        unit,
        status: statuses[index]
      };
    }).sort((a, b) => {
      return config.sortOrder === 'desc' ? b.value - a.value : a.value - b.value;
    });
  };

  const data = generateSampleData();

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'up': return 'text-green-600';
      case 'down': return 'text-red-600';
      case 'warning': return 'text-yellow-600';
      case 'maintenance': return 'text-gray-600';
      default: return 'text-gray-400';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'up':
        return (
          <svg className="w-3 h-3 text-green-500" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
          </svg>
        );
      case 'down':
        return (
          <svg className="w-3 h-3 text-red-500" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
          </svg>
        );
      case 'warning':
        return (
          <svg className="w-3 h-3 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
        );
      case 'maintenance':
        return (
          <svg className="w-3 h-3 text-gray-500" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM7 9a1 1 0 000 2h6a1 1 0 100-2H7z" clipRule="evenodd" />
          </svg>
        );
      default:
        return null;
    }
  };

  const getMetricLabel = () => {
    switch (config.metric) {
      case 'latency': return 'Highest Latency';
      case 'packet_loss': return 'Highest Packet Loss';
      case 'uptime': return 'Lowest Uptime';
      case 'traffic_in': return 'Highest Traffic In';
      case 'traffic_out': return 'Highest Traffic Out';
      default: return 'Top Devices';
    }
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-sm font-medium text-gray-700">{getMetricLabel()}</h4>
        <span className="text-xs text-gray-500">{config.timeRange}</span>
      </div>
      
      <div className="flex-1 overflow-y-auto">
        <div className="space-y-2">
          {data.map((device, index) => (
            <div
              key={device.id}
              className="flex items-center justify-between p-2 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
            >
              <div className="flex items-center space-x-3 flex-1 min-w-0">
                <div className="flex items-center space-x-1">
                  <span className="text-xs font-medium text-gray-500 w-4">
                    #{index + 1}
                  </span>
                  {getStatusIcon(device.status)}
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-gray-900 truncate">
                    {device.name}
                  </div>
                  <div className="text-xs text-gray-500">
                    {device.ip}
                  </div>
                </div>
              </div>
              
              {config.showValues !== false && (
                <div className="text-right">
                  <div className={`text-sm font-medium ${getStatusColor(device.status)}`}>
                    {device.value}{device.unit}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
      
      <div className="text-xs text-gray-500 mt-2 pt-2 border-t">
        Sorted by {config.metric} ({config.sortOrder === 'desc' ? 'highest first' : 'lowest first'})
      </div>
    </div>
  );
};