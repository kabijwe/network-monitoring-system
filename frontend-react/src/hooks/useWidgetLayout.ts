import { useState, useEffect } from 'react';
import { BaseWidget, WidgetLayout, WidgetType, WIDGET_TYPES } from '../components/dashboard/widgets/WidgetTypes';

const STORAGE_KEY = 'nms_dashboard_layout';

export const useWidgetLayout = () => {
  const [currentLayout, setCurrentLayout] = useState<WidgetLayout | null>(null);
  const [isEditMode, setIsEditMode] = useState(false);

  // Load layout from localStorage on mount
  useEffect(() => {
    const savedLayout = localStorage.getItem(STORAGE_KEY);
    if (savedLayout) {
      try {
        const layout = JSON.parse(savedLayout);
        setCurrentLayout(layout);
      } catch (error) {
        console.error('Failed to parse saved layout:', error);
        setCurrentLayout(getDefaultLayout());
      }
    } else {
      setCurrentLayout(getDefaultLayout());
    }
  }, []);

  // Save layout to localStorage whenever it changes
  useEffect(() => {
    if (currentLayout) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(currentLayout));
    }
  }, [currentLayout]);

  const getDefaultLayout = (): WidgetLayout => {
    return {
      id: 'default',
      name: 'Default Layout',
      isDefault: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      widgets: [
        {
          id: 'summary-cards-1',
          type: 'summary-cards',
          title: 'Device Status Summary',
          position: { x: 0, y: 0 },
          size: { width: 12, height: 2 },
          config: {}
        },
        {
          id: 'location-overview-1',
          type: 'location-overview',
          title: 'Location Health Overview',
          position: { x: 0, y: 2 },
          size: { width: 6, height: 4 },
          config: {}
        },
        {
          id: 'activity-log-1',
          type: 'activity-log',
          title: 'Live Activity Log',
          position: { x: 6, y: 2 },
          size: { width: 6, height: 4 },
          config: {}
        }
      ]
    };
  };

  const addWidget = (widgetType: WidgetType, position: { x: number; y: number }) => {
    if (!currentLayout) return;

    const widgetInfo = WIDGET_TYPES[widgetType];
    const newWidget: BaseWidget = {
      id: `${widgetType}-${Date.now()}`,
      type: widgetType,
      title: widgetInfo.name,
      position,
      size: widgetInfo.defaultSize,
      config: getDefaultConfig(widgetType)
    };

    const updatedLayout: WidgetLayout = {
      ...currentLayout,
      widgets: [...currentLayout.widgets, newWidget],
      updatedAt: new Date().toISOString()
    };

    setCurrentLayout(updatedLayout);
  };

  const updateWidget = (updatedWidget: BaseWidget) => {
    if (!currentLayout) return;

    const updatedLayout: WidgetLayout = {
      ...currentLayout,
      widgets: currentLayout.widgets.map(widget =>
        widget.id === updatedWidget.id ? updatedWidget : widget
      ),
      updatedAt: new Date().toISOString()
    };

    setCurrentLayout(updatedLayout);
  };

  const deleteWidget = (widgetId: string) => {
    if (!currentLayout) return;

    const updatedLayout: WidgetLayout = {
      ...currentLayout,
      widgets: currentLayout.widgets.filter(widget => widget.id !== widgetId),
      updatedAt: new Date().toISOString()
    };

    setCurrentLayout(updatedLayout);
  };

  const moveWidget = (widgetId: string, newPosition: { x: number; y: number }) => {
    if (!currentLayout) return;

    const updatedLayout: WidgetLayout = {
      ...currentLayout,
      widgets: currentLayout.widgets.map(widget =>
        widget.id === widgetId
          ? { ...widget, position: newPosition }
          : widget
      ),
      updatedAt: new Date().toISOString()
    };

    setCurrentLayout(updatedLayout);
  };

  const resetToDefault = () => {
    const defaultLayout = getDefaultLayout();
    setCurrentLayout(defaultLayout);
  };

  const saveLayout = (name: string) => {
    if (!currentLayout) return;

    const savedLayout: WidgetLayout = {
      ...currentLayout,
      name,
      isDefault: false,
      updatedAt: new Date().toISOString()
    };

    setCurrentLayout(savedLayout);
    
    // In a real app, this would also save to the backend
    console.log('Layout saved:', savedLayout);
  };

  const getDefaultConfig = (widgetType: WidgetType): Record<string, any> => {
    switch (widgetType) {
      case 'chart':
        return {
          chartType: 'line',
          metric: 'latency',
          timeRange: '24h',
          refreshInterval: 30
        };
      case 'map':
        return {
          showLabels: true,
          colorBy: 'status',
          zoomLevel: 10
        };
      case 'top-10-list':
        return {
          metric: 'latency',
          sortOrder: 'desc',
          showValues: true,
          timeRange: '24h'
        };
      default:
        return {};
    }
  };

  return {
    currentLayout,
    isEditMode,
    setIsEditMode,
    addWidget,
    updateWidget,
    deleteWidget,
    moveWidget,
    resetToDefault,
    saveLayout
  };
};