import React, { useEffect, useState } from 'react';
import { StatsCard } from '@/components/dashboard/StatsCard';
import { RecentReports } from '@/components/dashboard/RecentReports';
import { FileTypeChart } from '@/components/dashboard/FileTypeChart';
import { MalwareChart } from '@/components/dashboard/MalwareChart';
import { TrendChart } from '@/components/dashboard/TrendChart';
import { getDashboardStats, fetchReports } from '@/services/elasticsearch';
import { DashboardStats, Report } from '@/types';
import {
  Files,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
} from 'lucide-react';

export function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentReports, setRecentReports] = useState<Report[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadDashboardData = async () => {
      setIsLoading(true);
      setError(null);

      try {
        // Fetch dashboard stats and recent reports in parallel
        const [statsResponse, reportsResponse] = await Promise.all([
          getDashboardStats(),
          fetchReports(1, 10)
        ]);

        if (statsResponse.success && statsResponse.data) {
          setStats(statsResponse.data);
        } else {
          setError(statsResponse.error || 'Failed to load dashboard statistics');
        }

        if (reportsResponse.success && reportsResponse.data) {
          setRecentReports(reportsResponse.data.reports);
        } else {
          console.error('Failed to load recent reports:', reportsResponse.error);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load dashboard data');
      } finally {
        setIsLoading(false);
      }
    };

    loadDashboardData();
  }, []);

  const statsCards = [
    {
      title: 'Total Reports',
      value: stats?.total_reports || 0,
      icon: Files,
      description: 'All time',
      variant: 'default' as const,
    },
    {
      title: 'Reports Today',
      value: stats?.reports_today || 0,
      icon: Files,
      description: 'Last 24 hours',
      variant: 'default' as const,
    },
    {
      title: 'Malicious Files',
      value: stats?.malicious_files || 0,
      icon: ShieldAlert,
      description: 'High risk',
      variant: 'danger' as const,
    },
    {
      title: 'Suspicious Files',
      value: stats?.suspicious_files || 0,
      icon: Shield,
      description: 'Medium risk',
      variant: 'warning' as const,
    },
    {
      title: 'Clean Files',
      value: stats?.clean_files || 0,
      icon: ShieldCheck,
      description: 'Safe',
      variant: 'success' as const,
    },
    {
      title: 'Undetected Files',
      value: stats?.undetected_files || 0,
      icon: ShieldQuestion,
      description: 'Unknown',
      variant: 'default' as const,
    },
  ];

  if (error) {
    return (
      <div className="p-6">
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 text-destructive">
          <h3 className="font-semibold">Error loading dashboard</h3>
          <p className="text-sm mt-1">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-foreground">Analytics Dashboard</h1>
        <p className="text-muted-foreground mt-1">
          Charts, trends, and statistical analysis
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {statsCards.map((card, index) => (
          <StatsCard
            key={index}
            title={card.title}
            value={isLoading ? '...' : card.value}
            icon={card.icon}
            description={card.description}
            variant={card.variant}
          />
        ))}
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-4 gap-6">
        {/* Detection Overview Chart */}
        <MalwareChart
          malicious={stats?.malicious_files || 0}
          suspicious={stats?.suspicious_files || 0}
          clean={stats?.clean_files || 0}
          undetected={stats?.undetected_files || 0}
          isLoading={isLoading}
        />

        {/* File Types Chart */}
        <FileTypeChart
          data={stats?.top_file_types || []}
          isLoading={isLoading}
        />

        {/* Trend Chart - spans 2 columns */}
        <TrendChart
          data={stats?.detection_trends || []}
          isLoading={isLoading}
        />
      </div>

      {/* Recent Reports */}
      <RecentReports
        reports={recentReports}
        isLoading={isLoading}
      />
    </div>
  );
}