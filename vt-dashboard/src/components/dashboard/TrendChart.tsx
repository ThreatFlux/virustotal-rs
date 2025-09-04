import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer 
} from 'recharts';
import { TrendingUp } from 'lucide-react';

interface TrendData {
  date: string;
  malicious: number;
  suspicious: number;
  clean: number;
  undetected: number;
}

interface TrendChartProps {
  data: TrendData[];
  isLoading?: boolean;
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    const total = payload.reduce((sum: number, item: any) => sum + item.value, 0);
    
    return (
      <div className="rounded-lg border bg-background p-3 shadow-md">
        <p className="font-medium mb-2">{new Date(label).toLocaleDateString()}</p>
        <div className="space-y-1">
          {payload.map((item: any, index: number) => (
            <div key={index} className="flex items-center justify-between space-x-3">
              <div className="flex items-center space-x-2">
                <div 
                  className="w-3 h-3 rounded-full" 
                  style={{ backgroundColor: item.color }}
                />
                <span className="text-sm capitalize">{item.dataKey}</span>
              </div>
              <span className="text-sm font-medium">{item.value.toLocaleString()}</span>
            </div>
          ))}
          <div className="border-t pt-1 mt-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Total</span>
              <span className="text-sm font-medium">{total.toLocaleString()}</span>
            </div>
          </div>
        </div>
      </div>
    );
  }
  return null;
};

export function TrendChart({ data, isLoading = false }: TrendChartProps) {
  if (isLoading) {
    return (
      <Card className="col-span-2">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <TrendingUp className="h-5 w-5" />
            <span>Detection Trends (30 days)</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-80 flex items-center justify-center">
            <div className="w-full h-40 bg-muted animate-pulse rounded" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (data.length === 0) {
    return (
      <Card className="col-span-2">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <TrendingUp className="h-5 w-5" />
            <span>Detection Trends (30 days)</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-80 flex items-center justify-center text-muted-foreground">
            No trend data available
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="col-span-2">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <TrendingUp className="h-5 w-5" />
          <span>Detection Trends (30 days)</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis 
                dataKey="date" 
                className="text-xs"
                tickFormatter={(value) => new Date(value).toLocaleDateString('en-US', { 
                  month: 'short', 
                  day: 'numeric' 
                })}
              />
              <YAxis className="text-xs" />
              <Tooltip content={<CustomTooltip />} />
              <Legend 
                wrapperStyle={{ fontSize: '12px' }}
              />
              <Line
                type="monotone"
                dataKey="malicious"
                stroke="hsl(var(--malicious))"
                strokeWidth={2}
                dot={{ fill: 'hsl(var(--malicious))', strokeWidth: 2, r: 3 }}
                name="Malicious"
              />
              <Line
                type="monotone"
                dataKey="suspicious"
                stroke="hsl(var(--suspicious))"
                strokeWidth={2}
                dot={{ fill: 'hsl(var(--suspicious))', strokeWidth: 2, r: 3 }}
                name="Suspicious"
              />
              <Line
                type="monotone"
                dataKey="clean"
                stroke="hsl(var(--clean))"
                strokeWidth={2}
                dot={{ fill: 'hsl(var(--clean))', strokeWidth: 2, r: 3 }}
                name="Clean"
              />
              <Line
                type="monotone"
                dataKey="undetected"
                stroke="hsl(var(--undetected))"
                strokeWidth={2}
                dot={{ fill: 'hsl(var(--undetected))', strokeWidth: 2, r: 3 }}
                name="Undetected"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}