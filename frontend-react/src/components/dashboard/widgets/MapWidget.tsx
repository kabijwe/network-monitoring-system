import React, { useEffect, useRef } from 'react';
import { MapWidgetConfig } from './WidgetTypes';

interface MapWidgetProps {
  config: MapWidgetConfig;
}

interface NetworkNode {
  id: string;
  name: string;
  x: number;
  y: number;
  status: 'up' | 'down' | 'warning' | 'maintenance';
  type: 'router' | 'switch' | 'ap' | 'server';
}

interface NetworkEdge {
  from: string;
  to: string;
  status: 'active' | 'inactive';
}

export const MapWidget: React.FC<MapWidgetProps> = ({ config }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Sample network topology data
  const nodes: NetworkNode[] = [
    { id: '1', name: 'Core Router', x: 200, y: 150, status: 'up', type: 'router' },
    { id: '2', name: 'Switch A', x: 100, y: 100, status: 'up', type: 'switch' },
    { id: '3', name: 'Switch B', x: 300, y: 100, status: 'warning', type: 'switch' },
    { id: '4', name: 'AP-001', x: 50, y: 50, status: 'up', type: 'ap' },
    { id: '5', name: 'AP-002', x: 150, y: 50, status: 'down', type: 'ap' },
    { id: '6', name: 'AP-003', x: 250, y: 50, status: 'up', type: 'ap' },
    { id: '7', name: 'AP-004', x: 350, y: 50, status: 'maintenance', type: 'ap' },
    { id: '8', name: 'Server', x: 200, y: 250, status: 'up', type: 'server' },
  ];

  const edges: NetworkEdge[] = [
    { from: '1', to: '2', status: 'active' },
    { from: '1', to: '3', status: 'active' },
    { from: '1', to: '8', status: 'active' },
    { from: '2', to: '4', status: 'active' },
    { from: '2', to: '5', status: 'inactive' },
    { from: '3', to: '6', status: 'active' },
    { from: '3', to: '7', status: 'active' },
  ];

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    drawNetworkMap(ctx, canvas.width, canvas.height);
  }, [config]);

  const drawNetworkMap = (ctx: CanvasRenderingContext2D, width: number, height: number) => {
    // Clear canvas
    ctx.clearRect(0, 0, width, height);

    // Draw edges first (so they appear behind nodes)
    edges.forEach(edge => {
      const fromNode = nodes.find(n => n.id === edge.from);
      const toNode = nodes.find(n => n.id === edge.to);
      
      if (fromNode && toNode) {
        drawEdge(ctx, fromNode, toNode, edge.status);
      }
    });

    // Draw nodes
    nodes.forEach(node => {
      drawNode(ctx, node, config);
    });
  };

  const drawEdge = (
    ctx: CanvasRenderingContext2D,
    from: NetworkNode,
    to: NetworkNode,
    status: 'active' | 'inactive'
  ) => {
    ctx.beginPath();
    ctx.moveTo(from.x, from.y);
    ctx.lineTo(to.x, to.y);
    ctx.strokeStyle = status === 'active' ? '#10b981' : '#ef4444';
    ctx.lineWidth = 2;
    ctx.stroke();
  };

  const drawNode = (ctx: CanvasRenderingContext2D, node: NetworkNode, config: MapWidgetConfig) => {
    const radius = 15;
    
    // Determine node color based on config.colorBy
    let color = getNodeColor(node, config.colorBy);
    
    // Draw node circle
    ctx.beginPath();
    ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Draw node icon
    drawNodeIcon(ctx, node, radius);

    // Draw label if enabled
    if (config.showLabels) {
      ctx.fillStyle = '#374151';
      ctx.font = '10px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(node.name, node.x, node.y + radius + 15);
    }
  };

  const getNodeColor = (node: NetworkNode, colorBy: string) => {
    switch (colorBy) {
      case 'status':
        switch (node.status) {
          case 'up': return '#10b981';
          case 'down': return '#ef4444';
          case 'warning': return '#f59e0b';
          case 'maintenance': return '#6b7280';
          default: return '#9ca3af';
        }
      case 'location':
        // Color by location (simplified)
        return ['#3b82f6', '#10b981', '#f59e0b', '#ef4444'][parseInt(node.id) % 4];
      case 'group':
        // Color by device type
        switch (node.type) {
          case 'router': return '#8b5cf6';
          case 'switch': return '#3b82f6';
          case 'ap': return '#10b981';
          case 'server': return '#f59e0b';
          default: return '#9ca3af';
        }
      default:
        return '#9ca3af';
    }
  };

  const drawNodeIcon = (ctx: CanvasRenderingContext2D, node: NetworkNode, radius: number) => {
    ctx.fillStyle = '#ffffff';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    
    let icon = '';
    switch (node.type) {
      case 'router': icon = 'R'; break;
      case 'switch': icon = 'S'; break;
      case 'ap': icon = 'A'; break;
      case 'server': icon = 'H'; break;
      default: icon = '?';
    }
    
    ctx.fillText(icon, node.x, node.y);
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 relative">
        <canvas
          ref={canvasRef}
          width={400}
          height={300}
          className="w-full h-full border rounded"
          style={{ maxHeight: '300px' }}
        />
      </div>
      <div className="flex justify-between items-center text-xs text-gray-500 mt-2">
        <span>Colored by: {config.colorBy}</span>
        <span>Zoom: {config.zoomLevel || 10}</span>
      </div>
    </div>
  );
};