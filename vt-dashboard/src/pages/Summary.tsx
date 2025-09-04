import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { StatsCard } from '@/components/dashboard/StatsCard';
import { getDashboardStats, fetchReports, searchReports } from '@/services/elasticsearch';
import { DashboardStats, Report, AnalysisResult } from '@/types';
import { formatDate } from '@/lib/utils';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Files,
  AlertTriangle,
  FileSearch,
  Code,
  Activity,
  ExternalLink,
  TrendingUp,
  Eye,
  FileText,
} from 'lucide-react';

interface RuleDetection {
  rule_name: string;
  rule_type: 'yara' | 'sigma';
  file_hash: string;
  file_name: string;
  report_uuid: string;
  severity: 'high' | 'medium' | 'low';
  author?: string;
  description?: string;
  detection_count: number;
}

interface MaliciousIndicator {
  file_hash: string;
  file_name: string;
  report_uuid: string;
  risk_level: 'critical' | 'high' | 'medium';
  malicious_count: number;
  suspicious_count: number;
  total_engines: number;
  top_detections: string[];
  last_seen: string;
}

interface MacroDetection {
  file_hash: string;
  file_name: string;
  report_uuid: string;
  macro_count: number;
  macro_names: string[];
  has_vba: boolean;
  risk_level: 'high' | 'medium';
  detection_time: string;
}

export function Summary() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentRuleDetections, setRecentRuleDetections] = useState<RuleDetection[]>([]);
  const [maliciousIndicators, setMaliciousIndicators] = useState<MaliciousIndicator[]>([]);
  const [macroDetections, setMacroDetections] = useState<MacroDetection[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadSummaryData = async () => {
      setIsLoading(true);
      setError(null);

      try {
        // Fetch dashboard stats
        const [statsResponse, reportsResponse] = await Promise.all([
          getDashboardStats(),
          fetchReports(1, 20)
        ]);

        if (statsResponse.success && statsResponse.data) {
          setStats(statsResponse.data);
        } else {
          setError(statsResponse.error || 'Failed to load dashboard statistics');
        }

        if (reportsResponse.success && reportsResponse.data) {
          // Process recent reports to extract rule detections and malicious indicators
          const reports = reportsResponse.data.reports;
          
          // Mock rule detections for now (in real implementation, this would come from crowdsourced_data)
          const mockRuleDetections: RuleDetection[] = reports
            .slice(0, 5)
            .map((report, index) => ({
              rule_name: ['APT_Malware_Generic', 'Sigma_Suspicious_Process', 'Trojan_Banker_Family', 'Ransomware_Indicator', 'Backdoor_Detection'][index] || 'Generic_Detection',
              rule_type: index % 2 === 0 ? 'yara' : 'sigma',
              file_hash: report.file_hash,
              file_name: report.meaningful_name || report.names?.[0] || 'unknown.exe',
              report_uuid: report.report_uuid,
              severity: ['high', 'medium', 'high', 'high', 'medium'][index] as 'high' | 'medium' | 'low',
              author: ['ACME Security', 'Sigma HQ', 'ThreatHunter', 'CyberDefense', 'MalwareAnalysis'][index],
              description: [
                'Advanced persistent threat malware detection',
                'Suspicious process execution patterns',
                'Banking trojan family identification',
                'Ransomware behavior indicators',
                'Backdoor communication patterns'
              ][index],
              detection_count: Math.floor(Math.random() * 10) + 1
            }));
          
          setRecentRuleDetections(mockRuleDetections);

          // Extract malicious indicators from reports with malicious verdicts
          const mockMaliciousIndicators: MaliciousIndicator[] = reports
            .filter(report => report.last_analysis_stats?.malicious && report.last_analysis_stats.malicious > 0)
            .slice(0, 5)
            .map(report => {
              const maliciousCount = report.last_analysis_stats?.malicious || 0;
              const suspiciousCount = report.last_analysis_stats?.suspicious || 0;
              const totalCount = Object.values(report.last_analysis_stats || {}).reduce((sum: number, count) => sum + (count || 0), 0);
              
              return {
                file_hash: report.file_hash,
                file_name: report.meaningful_name || report.names?.[0] || 'unknown.exe',
                report_uuid: report.report_uuid,
                risk_level: maliciousCount > 10 ? 'critical' : maliciousCount > 5 ? 'high' : 'medium',
                malicious_count: maliciousCount,
                suspicious_count: suspiciousCount,
                total_engines: totalCount,
                top_detections: [
                  'Trojan.Win32.Generic',
                  'Malware.Suspicious',
                  'Win32.Backdoor',
                ].slice(0, Math.min(3, maliciousCount)),
                last_seen: report.last_analysis_date || report.index_time
              };
            });
          
          setMaliciousIndicators(mockMaliciousIndicators);

          // Extract macro detections from reports
          const extractedMacroDetections: MacroDetection[] = reports
            .filter(report => {
              // Check if report has office_info with macros
              const officeInfo = report.office_info || report.additional_info?.office_info;
              return officeInfo?.macros && officeInfo.macros.length > 0;
            })
            .slice(0, 5)
            .map(report => {
              const officeInfo = report.office_info || report.additional_info?.office_info;
              const macros = officeInfo?.macros || [];
              const hasVBAEntries = officeInfo?.entries?.some((entry: any) => 
                entry.name?.includes('VBA') || 
                entry.name?.includes('Macro') ||
                entry.clsid_literal?.includes('VBA')
              );
              
              return {
                file_hash: report.file_hash,
                file_name: report.meaningful_name || report.names?.[0] || 'document.docm',
                report_uuid: report.report_uuid,
                macro_count: macros.length,
                macro_names: macros.map((m: any) => m.name || 'Unnamed Macro').slice(0, 3),
                has_vba: hasVBAEntries || macros.length > 0,
                risk_level: macros.length > 3 || hasVBAEntries ? 'high' : 'medium',
                detection_time: report.last_analysis_date || report.index_time
              };
            });
          
          setMacroDetections(extractedMacroDetections);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load summary data');
      } finally {
        setIsLoading(false);
      }
    };

    loadSummaryData();
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50 dark:bg-red-900/20';
      case 'high': return 'text-red-600 bg-red-50 dark:bg-red-900/20';
      case 'medium': return 'text-orange-600 bg-orange-50 dark:bg-orange-900/20';
      case 'low': return 'text-yellow-600 bg-yellow-50 dark:bg-yellow-900/20';
      default: return 'text-muted-foreground bg-muted/50';
    }
  };

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
          <h3 className="font-semibold">Error loading summary</h3>
          <p className="text-sm mt-1">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-foreground">Security Summary</h1>
        <p className="text-muted-foreground mt-1">
          Rule detections and threat indicators overview
        </p>
      </div>

      {/* Stats Overview */}
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

      {/* Recent Rule Detections - Top Priority */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <FileSearch className="h-5 w-5 text-indigo-600" />
              Recent Rule Detections
              <Badge variant="secondary" className="ml-2">
                {recentRuleDetections.length}
              </Badge>
            </CardTitle>
            <Button variant="outline" size="sm" asChild>
              <Link to="/reports">
                <Eye className="h-4 w-4 mr-2" />
                View All
              </Link>
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-3">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="flex items-center space-x-4 p-4 bg-muted/50 rounded-lg animate-pulse">
                  <div className="w-8 h-8 bg-muted rounded-full" />
                  <div className="flex-1 space-y-2">
                    <div className="h-4 bg-muted rounded w-1/3" />
                    <div className="h-3 bg-muted rounded w-2/3" />
                  </div>
                </div>
              ))}
            </div>
          ) : recentRuleDetections.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <FileSearch className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No recent rule detections</p>
              <p className="text-sm mt-1">New rule matches will appear here</p>
            </div>
          ) : (
            <div className="space-y-3">
              {recentRuleDetections.map((detection, index) => (
                <div
                  key={`${detection.file_hash}-${index}`}
                  className="flex items-start space-x-4 p-4 bg-muted/30 hover:bg-muted/50 rounded-lg transition-colors border"
                >
                  <div className={`p-2 rounded-lg ${detection.rule_type === 'yara' ? 'bg-purple-100 dark:bg-purple-900/20' : 'bg-blue-100 dark:bg-blue-900/20'}`}>
                    {detection.rule_type === 'yara' ? (
                      <Code className="h-5 w-5 text-purple-600" />
                    ) : (
                      <Shield className="h-5 w-5 text-blue-600" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="font-semibold text-sm">{detection.rule_name}</h3>
                      <Badge variant={detection.rule_type === 'yara' ? 'default' : 'secondary'} className="text-xs">
                        {detection.rule_type.toUpperCase()}
                      </Badge>
                      <Badge 
                        variant={detection.severity === 'high' ? 'destructive' : 'outline'} 
                        className="text-xs"
                      >
                        {detection.severity.toUpperCase()}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1 truncate">
                      {detection.description}
                    </p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      <span>File: {detection.file_name}</span>
                      <span>Author: {detection.author}</span>
                      <span>Matches: {detection.detection_count}</span>
                    </div>
                  </div>
                  <Button variant="ghost" size="sm" asChild>
                    <Link to={`/reports/${detection.report_uuid}`}>
                      <ExternalLink className="h-4 w-4" />
                    </Link>
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Malicious Indicators */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-600" />
              Recent Malicious Indicators
              <Badge variant="destructive" className="ml-2">
                {maliciousIndicators.length}
              </Badge>
            </CardTitle>
            <Button variant="outline" size="sm" asChild>
              <Link to="/reports">
                <TrendingUp className="h-4 w-4 mr-2" />
                View Trends
              </Link>
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-3">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="flex items-center space-x-4 p-4 bg-muted/50 rounded-lg animate-pulse">
                  <div className="w-8 h-8 bg-muted rounded-full" />
                  <div className="flex-1 space-y-2">
                    <div className="h-4 bg-muted rounded w-1/3" />
                    <div className="h-3 bg-muted rounded w-2/3" />
                  </div>
                </div>
              ))}
            </div>
          ) : maliciousIndicators.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <ShieldCheck className="h-12 w-12 mx-auto mb-4 opacity-50 text-green-600" />
              <p>No recent malicious indicators</p>
              <p className="text-sm mt-1">This is good news! No high-risk files detected recently</p>
            </div>
          ) : (
            <div className="space-y-3">
              {maliciousIndicators.map((indicator, index) => (
                <div
                  key={`${indicator.file_hash}-${index}`}
                  className="flex items-start space-x-4 p-4 bg-red-50 dark:bg-red-900/10 hover:bg-red-100 dark:hover:bg-red-900/20 rounded-lg transition-colors border border-red-200 dark:border-red-900/30"
                >
                  <div className={`p-2 rounded-lg ${getSeverityColor(indicator.risk_level)}`}>
                    <ShieldAlert className="h-5 w-5" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="font-semibold text-sm">{indicator.file_name}</h3>
                      <Badge 
                        variant={indicator.risk_level === 'critical' ? 'destructive' : 'outline'} 
                        className="text-xs"
                      >
                        {indicator.risk_level.toUpperCase()}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {indicator.malicious_count}/{indicator.total_engines} engines detect as malicious
                      {indicator.suspicious_count > 0 && ` (+${indicator.suspicious_count} suspicious)`}
                    </p>
                    <div className="flex items-center gap-2 mt-2">
                      {indicator.top_detections.slice(0, 2).map((detection, i) => (
                        <Badge key={i} variant="outline" className="text-xs">
                          {detection}
                        </Badge>
                      ))}
                      {indicator.top_detections.length > 2 && (
                        <span className="text-xs text-muted-foreground">
                          +{indicator.top_detections.length - 2} more
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      Last seen: {formatDate(indicator.last_seen)}
                    </div>
                  </div>
                  <Button variant="ghost" size="sm" asChild>
                    <Link to={`/reports/${indicator.report_uuid}`}>
                      <ExternalLink className="h-4 w-4" />
                    </Link>
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Macro Detections */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5 text-orange-600" />
              Office Macro Detections
              <Badge variant="outline" className="ml-2 bg-orange-500/10">
                {macroDetections.length}
              </Badge>
            </CardTitle>
            <Button variant="outline" size="sm" asChild>
              <Link to="/search?query=office_info.macros:*">
                <Eye className="h-4 w-4 mr-2" />
                View All
              </Link>
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-3">
              {[...Array(2)].map((_, i) => (
                <div key={i} className="flex items-center space-x-4 p-4 bg-muted/50 rounded-lg animate-pulse">
                  <div className="w-8 h-8 bg-muted rounded" />
                  <div className="flex-1 space-y-2">
                    <div className="h-4 bg-muted rounded w-1/3" />
                    <div className="h-3 bg-muted rounded w-2/3" />
                  </div>
                </div>
              ))}
            </div>
          ) : macroDetections.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No macro detections recently</p>
              <p className="text-sm mt-1">No Office documents with macros found</p>
            </div>
          ) : (
            <div className="space-y-3">
              {macroDetections.map((detection, index) => (
                <div
                  key={`${detection.file_hash}-${index}`}
                  className="flex items-start space-x-4 p-4 bg-orange-50 dark:bg-orange-900/10 hover:bg-orange-100 dark:hover:bg-orange-900/20 rounded-lg transition-colors border border-orange-200 dark:border-orange-900/30"
                >
                  <div className="p-2 rounded-lg bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400">
                    <FileText className="h-5 w-5" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="font-semibold text-sm">{detection.file_name}</h3>
                      <Badge 
                        variant={detection.risk_level === 'high' ? 'destructive' : 'outline'} 
                        className="text-xs"
                      >
                        {detection.risk_level.toUpperCase()} RISK
                      </Badge>
                      {detection.has_vba && (
                        <Badge variant="outline" className="text-xs bg-red-500/10">
                          VBA
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {detection.macro_count} macro{detection.macro_count > 1 ? 's' : ''} detected
                    </p>
                    <div className="flex items-center gap-2 mt-2 flex-wrap">
                      {detection.macro_names.map((name, i) => (
                        <Badge key={i} variant="outline" className="text-xs font-mono">
                          {name}
                        </Badge>
                      ))}
                      {detection.macro_names.length < detection.macro_count && (
                        <span className="text-xs text-muted-foreground">
                          +{detection.macro_count - detection.macro_names.length} more
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      Detected: {formatDate(detection.detection_time)}
                    </div>
                  </div>
                  <Button variant="ghost" size="sm" asChild>
                    <Link to={`/reports/${detection.report_uuid}`}>
                      <ExternalLink className="h-4 w-4" />
                    </Link>
                  </Button>
                </div>
              ))}
              {macroDetections.length > 0 && (
                <div className="mt-4 p-3 bg-orange-100/50 dark:bg-orange-900/20 rounded-lg border border-orange-200 dark:border-orange-900/30">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-orange-600 flex-shrink-0 mt-0.5" />
                    <div className="text-sm text-orange-700 dark:text-orange-300">
                      <p className="font-medium">Security Notice</p>
                      <p className="text-xs mt-1">
                        Office documents with macros can contain malicious code. Always verify the source before enabling macros.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="cursor-pointer hover:shadow-md transition-shadow">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">
              <Link to="/reports" className="flex items-center gap-2">
                <Files className="h-4 w-4" />
                Browse All Reports
              </Link>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              View detailed analysis reports and file metadata
            </p>
          </CardContent>
        </Card>

        <Card className="cursor-pointer hover:shadow-md transition-shadow">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">
              <Link to="/search" className="flex items-center gap-2">
                <Activity className="h-4 w-4" />
                Advanced Search
              </Link>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Search files by hash, name, type, and detection patterns
            </p>
          </CardContent>
        </Card>

        <Card className="cursor-pointer hover:shadow-md transition-shadow">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">
              <Link to="/analytics" className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4" />
                Analytics Dashboard
              </Link>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              View charts, trends, and statistical analysis
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}