import React, { useRef } from 'react';
import { useDrop } from 'react-dnd';
import { DragItem, BaseWidget, WidgetType, WIDGET_TYPES } from './WidgetTypes';

interface DropZoneProps {
  onDrop: (item: DragItem, position: { x: number; y: number }) => void;
  children: React.ReactNode;
  isEditMode: boolean;
}

export const DropZone: React.FC<DropZoneProps> = ({ onDrop, children, isEditMode }) => {
  const ref = useRef<HTMLDivElement>(null);
  
  const [{ isOver, canDrop }, drop] = useDrop({
    accept: ['widget', 'widget-type'],
    drop: (item: DragItem, monitor) => {
      if (!monitor.didDrop()) {
        const clientOffset = monitor.getClientOffset();
        if (clientOffset && ref.current) {
          // Convert screen coordinates to grid position
          const dropZoneRect = ref.current.getBoundingClientRect();
          
          const x = Math.floor((clientOffset.x - dropZoneRect.left) / 100); // Assuming 100px grid
          const y = Math.floor((clientOffset.y - dropZoneRect.top) / 100);
          onDrop(item, { x: Math.max(0, x), y: Math.max(0, y) });
        }
      }
    },
    collect: (monitor) => ({
      isOver: monitor.isOver({ shallow: true }),
      canDrop: monitor.canDrop(),
    }),
  });

  // Connect the drop target to the ref
  drop(ref);

  return (
    <div
      ref={ref}
      data-drop-zone
      className={`
        min-h-screen transition-all duration-200
        ${isEditMode && isOver && canDrop ? 'bg-blue-50 border-2 border-dashed border-blue-300' : ''}
        ${isEditMode ? 'relative' : ''}
      `}
    >
      {children}
      {isEditMode && isOver && canDrop && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="bg-blue-100 border-2 border-blue-300 rounded-lg p-4">
            <p className="text-blue-700 font-medium">Drop widget here</p>
          </div>
        </div>
      )}
    </div>
  );
};