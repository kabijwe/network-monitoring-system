import React, { useEffect, useRef } from 'react';
import { ChartWidgetConfig } from './WidgetTypes';

interface ChartWidgetProps {
  config: ChartWidgetConfig;
}

export const ChartWidget: React.FC<ChartWidgetProps> = ({ config }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    // This would integrate with Chart.js or similar library
    // For now, we'll show a placeholder
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw placeholder chart
    drawPlaceholderChart(ctx, canvas.width, canvas.height, config);
  }, [config]);

  const drawPlaceholderChart = (
    ctx: CanvasRenderingContext2D,
    width: number,
    height: number,
    config: ChartWidgetConfig
  ) => {
    const padding = 40;
    const chartWidth = width - 2 * padding;
    const chartHeight = height - 2 * padding;

    // Draw axes
    ctx.strokeStyle = '#e5e7eb';
    ctx.lineWidth = 1;
    
    // Y-axis
    ctx.beginPath();
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, height - padding);
    ctx.stroke();
    
    // X-axis
    ctx.beginPath();
    ctx.moveTo(padding, height - padding);
    ctx.lineTo(width - padding, height - padding);
    ctx.stroke();

    // Generate sample data based on chart type
    if (config.chartType === 'line' || config.chartType === 'area') {
      drawLineChart(ctx, padding, chartWidth, chartHeight, config);
    } else if (config.chartType === 'bar') {
      drawBarChart(ctx, padding, chartWidth, chartHeight, config);
    } else if (config.chartType === 'pie') {
      drawPieChart(ctx, width / 2, height / 2, Math.min(chartWidth, chartHeight) / 3, config);
    }

    // Draw title
    ctx.fillStyle = '#374151';
    ctx.font = '14px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(`${config.metric} (${config.timeRange})`, width / 2, 20);
  };

  const drawLineChart = (
    ctx: CanvasRenderingContext2D,
    padding: number,
    chartWidth: number,
    chartHeight: number,
    config: ChartWidgetConfig
  ) => {
    const points = 20;
    const data = Array.from({ length: points }, () => Math.random() * 100);
    
    ctx.strokeStyle = '#3b82f6';
    ctx.lineWidth = 2;
    ctx.beginPath();

    for (let i = 0; i < points; i++) {
      const x = padding + (i / (points - 1)) * chartWidth;
      const y = padding + chartHeight - (data[i] / 100) * chartHeight;
      
      if (i === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    }
    
    ctx.stroke();

    if (config.chartType === 'area') {
      ctx.lineTo(padding + chartWidth, padding + chartHeight);
      ctx.lineTo(padding, padding + chartHeight);
      ctx.closePath();
      ctx.fillStyle = 'rgba(59, 130, 246, 0.1)';
      ctx.fill();
    }
  };

  const drawBarChart = (
    ctx: CanvasRenderingContext2D,
    padding: number,
    chartWidth: number,
    chartHeight: number,
    config: ChartWidgetConfig
  ) => {
    const bars = 8;
    const barWidth = chartWidth / bars * 0.8;
    const barSpacing = chartWidth / bars * 0.2;
    
    ctx.fillStyle = '#3b82f6';
    
    for (let i = 0; i < bars; i++) {
      const height = Math.random() * chartHeight;
      const x = padding + i * (barWidth + barSpacing);
      const y = padding + chartHeight - height;
      
      ctx.fillRect(x, y, barWidth, height);
    }
  };

  const drawPieChart = (
    ctx: CanvasRenderingContext2D,
    centerX: number,
    centerY: number,
    radius: number,
    config: ChartWidgetConfig
  ) => {
    const data = [30, 25, 20, 15, 10];
    const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];
    let currentAngle = -Math.PI / 2;
    
    data.forEach((value, index) => {
      const sliceAngle = (value / 100) * 2 * Math.PI;
      
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
      ctx.closePath();
      ctx.fillStyle = colors[index];
      ctx.fill();
      
      currentAngle += sliceAngle;
    });
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 relative">
        <canvas
          ref={canvasRef}
          width={400}
          height={300}
          className="w-full h-full"
          style={{ maxHeight: '300px' }}
        />
      </div>
      <div className="text-xs text-gray-500 mt-2">
        Refreshes every {config.refreshInterval || 30}s
      </div>
    </div>
  );
};