import React, { useRef } from 'react';
import { useDrag } from 'react-dnd';
import { BaseWidget, DragItem } from './WidgetTypes';
import { Card, CardContent, CardHeader, CardTitle } from '../../ui/Card';

interface DraggableWidgetProps {
  widget: BaseWidget;
  children: React.ReactNode;
  onEdit?: (widget: BaseWidget) => void;
  onDelete?: (widgetId: string) => void;
  isEditMode?: boolean;
}

export const DraggableWidget: React.FC<DraggableWidgetProps> = ({
  widget,
  children,
  onEdit,
  onDelete,
  isEditMode = false
}) => {
  const ref = useRef<HTMLDivElement>(null);
  
  const [{ isDragging }, drag] = useDrag<DragItem, void, { isDragging: boolean }>({
    type: 'widget',
    item: { type: 'widget', id: widget.id, widget },
    collect: (monitor) => ({
      isDragging: monitor.isDragging(),
    }),
    canDrag: isEditMode,
  });

  // Connect the drag source to the ref
  drag(ref);

  const handleEdit = (e: React.MouseEvent) => {
    e.stopPropagation();
    onEdit?.(widget);
  };

  const handleDelete = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (window.confirm('Are you sure you want to delete this widget?')) {
      onDelete?.(widget.id);
    }
  };

  return (
    <div
      ref={ref}
      className={`
        relative transition-all duration-200
        ${isDragging ? 'opacity-50 scale-95' : 'opacity-100 scale-100'}
        ${isEditMode ? 'cursor-move' : 'cursor-default'}
      `}
      style={{
        gridColumn: `span ${widget.size.width}`,
        gridRow: `span ${widget.size.height}`,
      }}
    >
      <Card className={`h-full ${isEditMode ? 'border-dashed border-2 border-blue-300' : ''}`}>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">{widget.title}</CardTitle>
          {isEditMode && (
            <div className="flex items-center space-x-1">
              <button
                onClick={handleEdit}
                className="p-1 text-gray-400 hover:text-blue-600 transition-colors"
                title="Edit widget"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
              </button>
              <button
                onClick={handleDelete}
                className="p-1 text-gray-400 hover:text-red-600 transition-colors"
                title="Delete widget"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </div>
          )}
        </CardHeader>
        <CardContent className="h-full pb-4">
          {children}
        </CardContent>
      </Card>
    </div>
  );
};