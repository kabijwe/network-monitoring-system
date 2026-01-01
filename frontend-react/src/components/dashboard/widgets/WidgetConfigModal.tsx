import React, { useState, useEffect } from 'react';
import { BaseWidget, ChartWidgetConfig, MapWidgetConfig, Top10ListConfig } from './WidgetTypes';
import { Card, CardContent, CardHeader, CardTitle } from '../../ui/Card';

interface WidgetConfigModalProps {
  widget: BaseWidget | null;
  isVisible: boolean;
  onSave: (widget: BaseWidget) => void;
  onClose: () => void;
}

export const WidgetConfigModal: React.FC<WidgetConfigModalProps> = ({
  widget,
  isVisible,
  onSave,
  onClose
}) => {
  const [title, setTitle] = useState('');
  const [config, setConfig] = useState<Record<string, any>>({});

  useEffect(() => {
    if (widget) {
      setTitle(widget.title);
      setConfig(widget.config || {});
    }
  }, [widget]);

  if (!isVisible || !widget) return null;

  const handleSave = () => {
    const updatedWidget: BaseWidget = {
      ...widget,
      title,
      config
    };
    onSave(updatedWidget);
    onClose();
  };

  const renderConfigFields = () => {
    switch (widget.type) {
      case 'chart':
        return <ChartConfig config={config as ChartWidgetConfig} onChange={setConfig} />;
      case 'map':
        return <MapConfig config={config as MapWidgetConfig} onChange={setConfig} />;
      case 'top-10-list':
        return <Top10Config config={config as Top10ListConfig} onChange={setConfig} />;
      default:
        return (
          <div className="text-sm text-gray-500">
            No configuration options available for this widget type.
          </div>
        );
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center">
      <Card className="w-96 max-h-[80vh] overflow-y-auto">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Configure Widget</CardTitle>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 transition-colors"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Widget Title
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter widget title"
            />
          </div>

          {renderConfigFields()}

          <div className="flex justify-end space-x-3 pt-4 border-t">
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md transition-colors"
            >
              Save Changes
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

const ChartConfig: React.FC<{
  config: ChartWidgetConfig;
  onChange: (config: ChartWidgetConfig) => void;
}> = ({ config, onChange }) => {
  const updateConfig = (key: keyof ChartWidgetConfig, value: any) => {
    onChange({ ...config, [key]: value });
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Chart Type
        </label>
        <select
          value={config.chartType || 'line'}
          onChange={(e) => updateConfig('chartType', e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="line">Line Chart</option>
          <option value="bar">Bar Chart</option>
          <option value="pie">Pie Chart</option>
          <option value="area">Area Chart</option>
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Metric
        </label>
        <select
          value={config.metric || 'latency'}
          onChange={(e) => updateConfig('metric', e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="latency">Latency</option>
          <option value="packet_loss">Packet Loss</option>
          <option value="uptime">Uptime</option>
          <option value="traffic_in">Traffic In</option>
          <option value="traffic_out">Traffic Out</option>
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Time Range
        </label>
        <select
          value={config.timeRange || '24h'}
          onChange={(e) => updateConfig('timeRange', e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="1h">Last Hour</option>
          <option value="6h">Last 6 Hours</option>
          <option value="24h">Last 24 Hours</option>
          <option value="7d">Last 7 Days</option>
          <option value="30d">Last 30 Days</option>
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Refresh Interval (seconds)
        </label>
        <input
          type="number"
          value={config.refreshInterval || 30}
          onChange={(e) => updateConfig('refreshInterval', parseInt(e.target.value))}
          min="10"
          max="300"
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>
    </div>
  );
};

const MapConfig: React.FC<{
  config: MapWidgetConfig;
  onChange: (config: MapWidgetConfig) => void;
}> = ({ config, onChange }) => {
  const updateConfig = (key: keyof MapWidgetConfig, value: any) => {
    onChange({ ...config, [key]: value });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center">
        <input
          type="checkbox"
          id="showLabels"
          checked={config.showLabels || false}
          onChange={(e) => updateConfig('showLabels', e.target.checked)}
          className="mr-2"
        />
        <label htmlFor="showLabels" className="text-sm font-medium text-gray-700">
          Show Device Labels
        </label>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Color By
        </label>
        <select
          value={config.colorBy || 'status'}
          onChange={(e) => updateConfig('colorBy', e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="status">Device Status</option>
          <option value="location">Location</option>
          <option value="group">Device Group</option>
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Zoom Level
        </label>
        <input
          type="range"
          min="1"
          max="20"
          value={config.zoomLevel || 10}
          onChange={(e) => updateConfig('zoomLevel', parseInt(e.target.value))}
          className="w-full"
        />
        <div className="text-xs text-gray-500 mt-1">
          Current: {config.zoomLevel || 10}
        </div>
      </div>
    </div>
  );
};

const Top10Config: React.FC<{
  config: Top10ListConfig;
  onChange: (config: Top10ListConfig) => void;
}> = ({ config, onChange }) => {
  const updateConfig = (key: keyof Top10ListConfig, value: any) => {
    onChange({ ...config, [key]: value });
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Metric
        </label>
        <select
          value={config.metric || 'latency'}
          onChange={(e) => updateConfig('metric', e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="latency">Highest Latency</option>
          <option value="packet_loss">Highest Packet Loss</option>
          <option value="uptime">Lowest Uptime</option>
          <option value="traffic_in">Highest Traffic In</option>
          <option value="traffic_out">Highest Traffic Out</option>
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Sort Order
        </label>
        <select
          value={config.sortOrder || 'desc'}
          onChange={(e) => updateConfig('sortOrder', e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="desc">Highest to Lowest</option>
          <option value="asc">Lowest to Highest</option>
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Time Range
        </label>
        <select
          value={config.timeRange || '24h'}
          onChange={(e) => updateConfig('timeRange', e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="1h">Last Hour</option>
          <option value="6h">Last 6 Hours</option>
          <option value="24h">Last 24 Hours</option>
          <option value="7d">Last 7 Days</option>
        </select>
      </div>

      <div className="flex items-center">
        <input
          type="checkbox"
          id="showValues"
          checked={config.showValues !== false}
          onChange={(e) => updateConfig('showValues', e.target.checked)}
          className="mr-2"
        />
        <label htmlFor="showValues" className="text-sm font-medium text-gray-700">
          Show Metric Values
        </label>
      </div>
    </div>
  );
};