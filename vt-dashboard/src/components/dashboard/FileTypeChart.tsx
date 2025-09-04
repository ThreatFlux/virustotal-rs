import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { FileType } from 'lucide-react';

interface FileTypeData {
  type: string;
  count: number;
}

interface FileTypeChartProps {
  data: FileTypeData[];
  isLoading?: boolean;
}

const COLORS = [
  'hsl(var(--chart-1))',
  'hsl(var(--chart-2))',
  'hsl(var(--chart-3))',
  'hsl(var(--chart-4))',
  'hsl(var(--chart-5))',
  'hsl(12 76% 61%)',
  'hsl(173 58% 39%)',
  'hsl(197 37% 24%)',
  'hsl(43 74% 66%)',
  'hsl(27 87% 67%)',
];

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="rounded-lg border bg-background p-2 shadow-md">
        <p className="font-medium">{data.type}</p>
        <p className="text-sm text-muted-foreground">
          {data.count.toLocaleString()} files
        </p>
        <p className="text-sm text-muted-foreground">
          {((data.count / data.total) * 100).toFixed(1)}%
        </p>
      </div>
    );
  }
  return null;
};

export function FileTypeChart({ data, isLoading = false }: FileTypeChartProps) {
  const total = data.reduce((sum, item) => sum + item.count, 0);
  const chartData = data.map(item => ({ ...item, total }));

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <FileType className="h-5 w-5" />
            <span>File Types</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-80 flex items-center justify-center">
            <div className="w-40 h-40 bg-muted animate-pulse rounded-full" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <FileType className="h-5 w-5" />
            <span>File Types</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-80 flex items-center justify-center text-muted-foreground">
            No file type data available
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <FileType className="h-5 w-5" />
          <span>File Types</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ type, percent }) => 
                  percent && percent > 0.05 ? `${type} (${(percent * 100).toFixed(0)}%)` : ''
                }
                outerRadius={80}
                fill="#8884d8"
                dataKey="count"
              >
                {chartData.map((entry, index) => (
                  <Cell 
                    key={`cell-${index}`} 
                    fill={COLORS[index % COLORS.length]} 
                  />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend 
                wrapperStyle={{ fontSize: '12px' }}
                formatter={(value, entry: any) => (
                  <span style={{ color: entry.color }}>
                    {value} ({entry.payload?.count?.toLocaleString()})
                  </span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}