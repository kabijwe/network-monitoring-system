import React, { useRef } from 'react';
import { useDrag } from 'react-dnd';
import { WidgetType, WIDGET_TYPES, DragItem } from './WidgetTypes';
import { Card, CardContent } from '../../ui/Card';

interface WidgetPaletteProps {
  isVisible: boolean;
  onClose: () => void;
}

interface DraggableWidgetTypeProps {
  widgetType: WidgetType;
}

const DraggableWidgetType: React.FC<DraggableWidgetTypeProps> = ({ widgetType }) => {
  const ref = useRef<HTMLDivElement>(null);
  
  const [{ isDragging }, drag] = useDrag<DragItem, void, { isDragging: boolean }>({
    type: 'widget-type',
    item: { type: 'widget-type', id: widgetType },
    collect: (monitor) => ({
      isDragging: monitor.isDragging(),
    }),
  });

  // Connect the drag source to the ref
  drag(ref);

  const widgetInfo = WIDGET_TYPES[widgetType];

  return (
    <div
      ref={ref}
      className={`
        p-3 border rounded-lg cursor-move transition-all duration-200
        ${isDragging ? 'opacity-50 scale-95' : 'opacity-100 scale-100'}
        hover:border-blue-300 hover:bg-blue-50
      `}
    >
      <div className="flex items-center space-x-3">
        <div className="w-8 h-8 bg-blue-100 rounded flex items-center justify-center">
          <WidgetIcon type={widgetType} />
        </div>
        <div>
          <h4 className="font-medium text-sm">{widgetInfo.name}</h4>
          <p className="text-xs text-gray-500">{widgetInfo.description}</p>
        </div>
      </div>
    </div>
  );
};

const WidgetIcon: React.FC<{ type: WidgetType }> = ({ type }) => {
  const iconClass = "w-4 h-4 text-blue-600";
  
  switch (type) {
    case 'summary-cards':
      return (
        <svg className={iconClass} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
        </svg>
      );
    case 'location-overview':
      return (
        <svg className={iconClass} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
      );
    case 'activity-log':
      return (
        <svg className={iconClass} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
        </svg>
      );
    case 'chart':
      return (
        <svg className={iconClass} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
        </svg>
      );
    case 'map':
      return (
        <svg className={iconClass} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
        </svg>
      );
    case 'top-10-list':
      return (
        <svg className={iconClass} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
        </svg>
      );
    default:
      return (
        <svg className={iconClass} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
        </svg>
      );
  }
};

export const WidgetPalette: React.FC<WidgetPaletteProps> = ({ isVisible, onClose }) => {
  if (!isVisible) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center">
      <Card className="w-96 max-h-[80vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b">
          <h3 className="text-lg font-semibold">Add Widget</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <CardContent className="p-4">
          <p className="text-sm text-gray-600 mb-4">
            Drag and drop widgets onto your dashboard to customize the layout.
          </p>
          <div className="space-y-3">
            {Object.keys(WIDGET_TYPES).map((widgetType) => (
              <DraggableWidgetType
                key={widgetType}
                widgetType={widgetType as WidgetType}
              />
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};