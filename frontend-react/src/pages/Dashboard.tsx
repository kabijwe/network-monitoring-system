import React, { useState } from 'react';
import { DndProvider } from 'react-dnd';
import { HTML5Backend } from 'react-dnd-html5-backend';
import { useAuth } from '../hooks/useAuth';
import { LogoutButton } from '../components/auth/LogoutButton';
import { RoleGuard } from '../components/auth/RoleGuard';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { useGetDashboardDataQuery } from '../store/api/dashboardApi';
import { useWidgetLayout } from '../hooks/useWidgetLayout';
import { DraggableWidget } from '../components/dashboard/widgets/DraggableWidget';
import { DropZone } from '../components/dashboard/widgets/DropZone';
import { WidgetPalette } from '../components/dashboard/widgets/WidgetPalette';
import { WidgetConfigModal } from '../components/dashboard/widgets/WidgetConfigModal';
import { WidgetRenderer } from '../components/dashboard/widgets/WidgetRenderer';
import { BaseWidget, DragItem, WidgetType } from '../components/dashboard/widgets/WidgetTypes';

export const Dashboard: React.FC = () => {
  const { user, getHighestRole } = useAuth();
  const { 
    data: dashboardData, 
    isLoading, 
    error,
    refetch 
  } = useGetDashboardDataQuery(undefined, {
    pollingInterval: 30000, // Refetch every 30 seconds
  });

  const {
    currentLayout,
    isEditMode,
    setIsEditMode,
    addWidget,
    updateWidget,
    deleteWidget,
    moveWidget,
    resetToDefault,
    saveLayout
  } = useWidgetLayout();

  const [showWidgetPalette, setShowWidgetPalette] = useState(false);
  const [configWidget, setConfigWidget] = useState<BaseWidget | null>(null);

  const handleDrop = (item: DragItem, position: { x: number; y: number }) => {
    if (item.type === 'widget-type') {
      // Adding new widget from palette
      addWidget(item.id as WidgetType, position);
    } else if (item.type === 'widget' && item.widget) {
      // Moving existing widget
      moveWidget(item.widget.id, position);
    }
  };

  const handleEditWidget = (widget: BaseWidget) => {
    setConfigWidget(widget);
  };

  const handleSaveWidget = (widget: BaseWidget) => {
    updateWidget(widget);
    setConfigWidget(null);
  };

  const toggleEditMode = () => {
    setIsEditMode(!isEditMode);
    if (showWidgetPalette) {
      setShowWidgetPalette(false);
    }
  };

  return (
    <DndProvider backend={HTML5Backend}>
      <div className="min-h-screen bg-gray-50">
        {/* Header */}
        <header className="bg-white shadow-sm border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center h-16">
              <div className="flex items-center space-x-4">
                <div className="w-8 h-8 bg-gradient-to-br from-blue-600 to-indigo-700 rounded-lg flex items-center justify-center">
                  <span className="text-white text-sm font-bold">WL</span>
                </div>
                <h1 className="text-xl font-semibold text-gray-900">
                  WorldLink NMS
                </h1>
              </div>
              
              <div className="flex items-center space-x-4">
                {dashboardData?.last_updated && (
                  <span className="text-xs text-gray-500">
                    Updated: {new Date(dashboardData.last_updated).toLocaleTimeString()}
                  </span>
                )}
                <span className="text-sm text-gray-600">
                  Welcome, {user?.full_name || user?.username}
                </span>
                <LogoutButton />
              </div>
            </div>
          </div>
        </header>

        {/* Dashboard Controls */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-2xl font-bold text-gray-900 mb-2">Dashboard</h2>
              <p className="text-gray-600">
                Network monitoring and management overview
              </p>
            </div>
            
            <div className="flex items-center space-x-3">
              {error && (
                <div className="flex items-center space-x-2">
                  <svg className="w-5 h-5 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                  <span className="text-sm text-red-600">Failed to load data</span>
                  <button 
                    onClick={() => refetch()}
                    className="text-sm text-blue-600 hover:text-blue-800 underline"
                  >
                    Retry
                  </button>
                </div>
              )}
              
              <RoleGuard requiredRole="Editor">
                <div className="flex items-center space-x-2">
                  {isEditMode && (
                    <>
                      <button
                        onClick={() => setShowWidgetPalette(true)}
                        className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                      >
                        Add Widget
                      </button>
                      <button
                        onClick={resetToDefault}
                        className="px-3 py-1 text-sm bg-gray-600 text-white rounded hover:bg-gray-700 transition-colors"
                      >
                        Reset
                      </button>
                    </>
                  )}
                  <button
                    onClick={toggleEditMode}
                    className={`px-3 py-1 text-sm rounded transition-colors ${
                      isEditMode
                        ? 'bg-green-600 text-white hover:bg-green-700'
                        : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                    }`}
                  >
                    {isEditMode ? 'Done' : 'Edit Layout'}
                  </button>
                </div>
              </RoleGuard>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-8">
          <DropZone onDrop={handleDrop} isEditMode={isEditMode}>
            <div className="grid grid-cols-12 gap-4 auto-rows-min">
              {currentLayout?.widgets.map((widget) => (
                <DraggableWidget
                  key={widget.id}
                  widget={widget}
                  onEdit={handleEditWidget}
                  onDelete={deleteWidget}
                  isEditMode={isEditMode}
                >
                  <WidgetRenderer
                    widget={widget}
                    dashboardData={dashboardData}
                    isLoading={isLoading}
                  />
                </DraggableWidget>
              ))}
            </div>
          </DropZone>

          {/* Fallback content when no widgets */}
          {!currentLayout?.widgets.length && (
            <div className="text-center py-12">
              <svg className="w-16 h-16 mx-auto text-gray-300 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              <h3 className="text-lg font-medium text-gray-900 mb-2">No widgets configured</h3>
              <p className="text-gray-500 mb-4">Add widgets to customize your dashboard</p>
              <RoleGuard requiredRole="Editor">
                <button
                  onClick={() => {
                    setIsEditMode(true);
                    setShowWidgetPalette(true);
                  }}
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                >
                  Add Your First Widget
                </button>
              </RoleGuard>
            </div>
          )}
        </main>

        {/* Widget Palette Modal */}
        <WidgetPalette
          isVisible={showWidgetPalette}
          onClose={() => setShowWidgetPalette(false)}
        />

        {/* Widget Configuration Modal */}
        <WidgetConfigModal
          widget={configWidget}
          isVisible={!!configWidget}
          onSave={handleSaveWidget}
          onClose={() => setConfigWidget(null)}
        />
      </div>
    </DndProvider>
  );
};