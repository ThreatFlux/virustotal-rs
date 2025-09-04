import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AnalysisDisplay } from '@/components/analysis/AnalysisDisplay';
import { BehavioralAnalysisDisplay } from '@/components/analysis/BehavioralAnalysisDisplay';
import { DetectionRulesViewer } from '@/components/DetectionRulesViewer';
import { YaraRuleViewer } from '@/components/YaraRuleViewer';
import { SigmaRuleViewer } from '@/components/SigmaRuleViewer';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { ScrollArea } from '@/components/ui/scroll-area';
import { fetchFileAnalysis } from '@/services/elasticsearch';
import { FileAnalysis } from '@/types';
import { 
  formatDate, 
  formatBytes, 
  truncateHash, 
  getVerdictBadgeVariant,
  getVerdictColor 
} from '@/lib/utils';
import {
  FileText,
  Shield,
  AlertTriangle,
  Clock,
  Hash,
  Download,
  Copy,
  ExternalLink,
  ChevronLeft,
  Activity,
  Database,
  Network,
  Info,
  CheckCircle,
  XCircle,
  AlertCircle,
  Bug,
  ShieldAlert,
  FileWarning,
  Fingerprint,
  Code,
} from 'lucide-react';

export function ReportDetail() {
  const { reportId } = useParams<{ reportId: string }>();
  const navigate = useNavigate();
  const [analysis, setAnalysis] = useState<FileAnalysis | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [showAllRules, setShowAllRules] = useState(false);
  const [selectedRule, setSelectedRule] = useState<any>(null);
  const [ruleDialogOpen, setRuleDialogOpen] = useState(false);

  useEffect(() => {
    const loadAnalysis = async () => {
      if (!reportId) return;

      setIsLoading(true);
      setError(null);

      try {
        const response = await fetchFileAnalysis(reportId);
        
        if (response.success && response.data) {
          setAnalysis(response.data);
        } else {
          setError(response.error || 'Report not found');
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load report');
      } finally {
        setIsLoading(false);
      }
    };

    loadAnalysis();
  }, [reportId]);

  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedHash(label);
      setTimeout(() => setCopiedHash(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div className="flex items-center space-x-4">
          <div className="h-8 w-8 bg-muted animate-pulse rounded" />
          <div className="space-y-2">
            <div className="h-6 w-48 bg-muted animate-pulse rounded" />
            <div className="h-4 w-32 bg-muted animate-pulse rounded" />
          </div>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="space-y-4">
            <div className="h-32 bg-muted animate-pulse rounded-lg" />
            <div className="h-48 bg-muted animate-pulse rounded-lg" />
          </div>
          <div className="lg:col-span-2">
            <div className="h-96 bg-muted animate-pulse rounded-lg" />
          </div>
        </div>
      </div>
    );
  }

  if (error || !analysis) {
    return (
      <div className="p-6">
        <div className="flex items-center space-x-4 mb-6">
          <Button variant="ghost" size="sm" asChild>
            <Link to="/reports">
              <ChevronLeft className="h-4 w-4 mr-2" />
              Back to Reports
            </Link>
          </Button>
        </div>
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-6 text-destructive">
          <h3 className="font-semibold mb-2">Error loading report</h3>
          <p>{error || 'Report not found'}</p>
        </div>
      </div>
    );
  }

  const { report, analysis_results, sandbox_verdicts, sandbox_behaviors, behavioral_analysis, crowdsourced_data, relationships, risk_score } = analysis;
  
  const detectionCounts = {
    malicious: analysis_results.filter(r => r.category.toLowerCase() === 'malicious').length,
    suspicious: analysis_results.filter(r => r.category.toLowerCase() === 'suspicious').length,
    clean: analysis_results.filter(r => r.category.toLowerCase() === 'harmless' || r.category.toLowerCase() === 'clean').length,
    undetected: analysis_results.filter(r => r.category.toLowerCase() === 'undetected').length,
    timeout: analysis_results.filter(r => r.category.toLowerCase() === 'timeout').length,
    error: analysis_results.filter(r => r.category.toLowerCase() === 'failure').length,
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" asChild>
          <Link to="/reports">
            <ChevronLeft className="h-4 w-4 mr-2" />
            <span className="hidden sm:inline">Back to Reports</span>
            <span className="sm:hidden">Back</span>
          </Link>
        </Button>
        <h1 className="text-xl sm:text-2xl font-bold text-foreground">File Analysis Report</h1>
        <div className="w-24"></div> {/* Spacer for centering */}
      </div>

      {/* Report Navigation Tabs - Summary Tab First */}
      <Tabs defaultValue="summary" className="space-y-6">
        <div className="overflow-x-auto">
          <TabsList className="inline-flex h-10 items-center justify-start rounded-md bg-muted p-1 text-muted-foreground min-w-max">
            <TabsTrigger value="summary" className="whitespace-nowrap">
              <Info className="h-4 w-4 mr-1 sm:mr-2" />
              <span>Summary</span>
            </TabsTrigger>
            <TabsTrigger value="technical" className="whitespace-nowrap">
              <FileText className="h-4 w-4 mr-1 sm:mr-2" />
              <span>Technical</span>
            </TabsTrigger>
            <TabsTrigger value="av-results" className="whitespace-nowrap">
              <Shield className="h-4 w-4 mr-1 sm:mr-2" />
              <span>AV Results</span>
            </TabsTrigger>
            <TabsTrigger value="sandbox" className="whitespace-nowrap">
              <Activity className="h-4 w-4 mr-1 sm:mr-2" />
              <span>Sandbox</span>
            </TabsTrigger>
            <TabsTrigger value="intelligence" className="whitespace-nowrap">
              <Database className="h-4 w-4 mr-1 sm:mr-2" />
              <span className="hidden sm:inline">Intelligence</span>
              <span className="sm:hidden">Intel</span>
            </TabsTrigger>
            <TabsTrigger value="relationships" className="whitespace-nowrap">
              <Network className="h-4 w-4 mr-1 sm:mr-2" />
              <span>Relations</span>
            </TabsTrigger>
          </TabsList>
        </div>

        {/* Summary Tab - New High-Level Overview */}
        <TabsContent value="summary" className="space-y-6">
          {/* File Information Card with integrated detection info */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Fingerprint className="h-5 w-5" />
                  <span>File Information</span>
                </div>
                <div className="flex items-center gap-3">
                  {/* Detection Ratio */}
                  <div className="flex items-center gap-2">
                    <Shield className="h-4 w-4 text-muted-foreground" />
                    <div className="text-2xl font-bold">
                      <span className={detectionCounts.malicious > 0 ? 'text-red-600' : detectionCounts.suspicious > 0 ? 'text-orange-600' : 'text-green-600'}>
                        {detectionCounts.malicious + detectionCounts.suspicious}
                      </span>
                      <span className="text-muted-foreground text-xl">/</span>
                      <span className="text-foreground">{analysis_results.length}</span>
                    </div>
                  </div>
                  {/* Risk Badge */}
                  <Badge 
                    variant={getVerdictBadgeVariant(risk_score.level.toLowerCase())}
                    className="text-sm px-3 py-1"
                  >
                    Risk: {risk_score.level} ({risk_score.score}%)
                  </Badge>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Left Column */}
                <div className="space-y-3">
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">File Name</label>
                    <p className="text-sm font-medium break-all">{report.meaningful_name || report.names?.[0] || 'Unknown'}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-xs font-medium text-muted-foreground">Type</label>
                      <p className="text-sm">{report.type_description || report.type_tag || 'Unknown'}</p>
                    </div>
                    <div>
                      <label className="text-xs font-medium text-muted-foreground">Size</label>
                      <p className="text-sm">{report.size ? formatBytes(report.size) : 'Unknown'}</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-xs font-medium text-muted-foreground">First Seen</label>
                      <p className="text-sm">{report.first_submission_date ? formatDate(report.first_submission_date) : 'Unknown'}</p>
                    </div>
                    <div>
                      <label className="text-xs font-medium text-muted-foreground">Last Analysis</label>
                      <p className="text-sm">{report.last_analysis_date ? formatDate(report.last_analysis_date) : 'Unknown'}</p>
                    </div>
                  </div>
                </div>
                
                {/* Right Column */}
                <div className="space-y-3">
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">SHA256</label>
                    <div className="flex items-center gap-2">
                      <p className="text-xs font-mono break-all flex-1">
                        {report.sha256 || report.file_hash || ''}
                      </p>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(report.sha256 || report.file_hash || '', 'SHA256')}
                        className="h-6 w-6 p-0"
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                  {report.md5 && (
                    <div>
                      <label className="text-xs font-medium text-muted-foreground">MD5</label>
                      <p className="text-xs font-mono break-all">{report.md5}</p>
                    </div>
                  )}
                  {/* AV Detection Summary */}
                  <div className="pt-2 border-t">
                    <label className="text-xs font-medium text-muted-foreground">Detection Summary</label>
                    <p className="text-sm mt-1">
                      {detectionCounts.malicious > 0 
                        ? `${detectionCounts.malicious} engines flagged as malicious${detectionCounts.suspicious > 0 ? `, ${detectionCounts.suspicious} as suspicious` : ''}`
                        : detectionCounts.suspicious > 0 
                        ? `${detectionCounts.suspicious} engines flagged as suspicious`
                        : 'No threats detected'}
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* YARA/Sigma Rules Detection - Enhanced with expandable view */}
          {(() => {
            // Get YARA rules from crowdsourced data
            const yaraRules = crowdsourced_data.filter(item => item.data_type === 'yara');
            
            // Get Sigma rules from both crowdsourced data and sandbox behaviors
            const crowdsourcedSigmaRules = crowdsourced_data.filter(item => item.data_type === 'sigma');
            
            // Convert sandbox behaviors to Sigma rule format (these are Sigma rules detected during sandbox analysis)
            const sandboxSigmaRules = sandbox_behaviors
              .filter(behavior => behavior.rule_source?.includes('Sigma'))
              .map(behavior => ({
                data_type: 'sigma',
                data: {
                  rule_name: behavior.rule_title || behavior.rule_id,
                  author: behavior.rule_author,
                  description: behavior.rule_description,
                  source: behavior.rule_source,
                  level: behavior.severity,
                  event_count: behavior.event_count
                }
              }));
            
            // Combine all Sigma rules
            const sigmaRules = [...crowdsourcedSigmaRules, ...sandboxSigmaRules];
            
            const hasRules = yaraRules.length > 0 || sigmaRules.length > 0;
            
            return hasRules ? (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Bug className="h-5 w-5" />
                      <span>Detection Rules Matched</span>
                      <div className="flex gap-2">
                        {yaraRules.length > 0 && (
                          <Badge variant="outline" className="bg-purple-500/10">
                            {yaraRules.length} YARA
                          </Badge>
                        )}
                        {sigmaRules.length > 0 && (
                          <Badge variant="outline" className="bg-blue-500/10">
                            {sigmaRules.length} Sigma
                          </Badge>
                        )}
                      </div>
                    </div>
                    {(yaraRules.length > 3 || sigmaRules.length > 3) && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setShowAllRules(!showAllRules)}
                        className="text-xs"
                      >
                        {showAllRules ? 'Show Less' : `View All ${yaraRules.length + sigmaRules.length} Rules`}
                      </Button>
                    )}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {!showAllRules ? (
                    // Compact view - show first 3 rules of each type
                    <div className="space-y-4">
                      {yaraRules.length > 0 && (
                        <div className="space-y-2">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge variant="outline" className="bg-purple-500/10">YARA</Badge>
                            <span className="text-sm text-muted-foreground">{yaraRules.length} rule{yaraRules.length > 1 ? 's' : ''} matched</span>
                          </div>
                          {yaraRules.slice(0, 3).map((rule, idx) => {
                            const data = rule.data || {};
                            return (
                              <div key={`yara-preview-${idx}`} className="p-2 rounded-lg bg-muted/50 space-y-1 hover:bg-muted/70 transition-colors">
                                <div className="flex items-start justify-between">
                                  <button
                                    onClick={() => {
                                      setSelectedRule({ type: 'yara', ...data });
                                      setRuleDialogOpen(true);
                                    }}
                                    className="font-medium text-sm text-left hover:text-purple-600 hover:underline transition-colors"
                                  >
                                    {data.rule_name || 'Unknown Rule'}
                                  </button>
                                  {data.severity && (
                                    <Badge variant={data.severity === 'high' ? 'destructive' : data.severity === 'medium' ? 'secondary' : 'outline'} className="text-xs">
                                      {data.severity}
                                    </Badge>
                                  )}
                                </div>
                                {data.description && (
                                  <p className="text-xs text-muted-foreground">{data.description}</p>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                      
                      {sigmaRules.length > 0 && (
                        <div className="space-y-2">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge variant="outline" className="bg-blue-500/10">SIGMA</Badge>
                            <span className="text-sm text-muted-foreground">{sigmaRules.length} rule{sigmaRules.length > 1 ? 's' : ''} matched</span>
                          </div>
                          {sigmaRules.slice(0, 3).map((rule, idx) => {
                            const data = rule.data || {};
                            return (
                              <div key={`sigma-preview-${idx}`} className="p-2 rounded-lg bg-muted/50 space-y-1 hover:bg-muted/70 transition-colors">
                                <div className="flex items-start justify-between">
                                  <button
                                    onClick={() => {
                                      setSelectedRule({ type: 'sigma', ...data });
                                      setRuleDialogOpen(true);
                                    }}
                                    className="font-medium text-sm text-left hover:text-blue-600 hover:underline transition-colors"
                                  >
                                    {data.rule_name || 'Unknown Rule'}
                                  </button>
                                  {data.level && (
                                    <Badge variant={data.level === 'critical' ? 'destructive' : data.level === 'high' ? 'destructive' : 'secondary'} className="text-xs">
                                      {data.level}
                                    </Badge>
                                  )}
                                </div>
                                {data.description && (
                                  <p className="text-xs text-muted-foreground">{data.description}</p>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                      
                      {(yaraRules.length > 3 || sigmaRules.length > 3) && (
                        <p className="text-xs text-center text-muted-foreground pt-2">
                          Click "View All Rules" to see complete rule details
                        </p>
                      )}
                    </div>
                  ) : (
                    // Expanded view - show all rules with full DetectionRulesViewer
                    <div className="mt-2">
                      <DetectionRulesViewer 
                        crowdsourcedData={[...yaraRules, ...sigmaRules]}
                        fileHash={report.sha256 || report.file_hash || ''}
                      />
                    </div>
                  )}
                </CardContent>
              </Card>
            ) : null;
          })()}

          {/* Suspicious Indicators */}
          {(() => {
            const suspiciousIndicators = [];
            
            // Check for high-risk behaviors
            if (behavioral_analysis && behavioral_analysis.total_behaviors > 0) {
              const behaviorCategories = Array.isArray(behavioral_analysis.behavior_categories) 
                ? behavioral_analysis.behavior_categories 
                : [];
              const highRiskBehaviors = behaviorCategories.filter(cat => 
                cat.severity === 'high' || cat.severity === 'critical'
              );
              if (highRiskBehaviors.length > 0) {
                suspiciousIndicators.push({
                  type: 'behavior',
                  title: 'High-Risk Behaviors Detected',
                  count: highRiskBehaviors.length,
                  items: highRiskBehaviors.slice(0, 3).map(b => b.name || 'Unknown behavior')
                });
              }
            }
            
            // Check for malicious detections
            const topMaliciousDetections = analysis_results
              .filter(r => r.category === 'malicious' && r.result)
              .slice(0, 5)
              .map(r => ({ engine: r.engine_name, result: r.result }));
            
            if (topMaliciousDetections.length > 0) {
              suspiciousIndicators.push({
                type: 'detection',
                title: 'Top Malicious Detections',
                count: detectionCounts.malicious,
                items: topMaliciousDetections.map(d => `${d.engine}: ${d.result}`)
              });
            }
            
            // Check sandbox verdicts
            const maliciousSandboxes = sandbox_verdicts.filter(v => 
              v.verdict?.category === 'malicious'
            );
            if (maliciousSandboxes.length > 0) {
              suspiciousIndicators.push({
                type: 'sandbox',
                title: 'Sandbox Analysis',
                count: maliciousSandboxes.length,
                items: maliciousSandboxes.map(s => `${s.sandbox_name}: Malicious`)
              });
            }
            
            // Check for Office macros/VBA
            const officeInfo = report.office_info || report.additional_info?.office_info;
            if (officeInfo?.macros && officeInfo.macros.length > 0) {
              const macroItems = officeInfo.macros.slice(0, 3).map((macro: any) => {
                const name = macro.name || 'Unnamed Macro';
                const size = macro.code_size ? ` (${macro.code_size} bytes)` : '';
                return `${name}${size}`;
              });
              suspiciousIndicators.push({
                type: 'macro',
                title: 'Office Macros/VBA Detected',
                count: officeInfo.macros.length,
                items: macroItems
              });
            }
            
            // Check for VBA-related OLE entries
            if (officeInfo?.entries?.some((entry: any) => 
              entry.name?.includes('VBA') || 
              entry.name?.includes('Macro') ||
              entry.clsid_literal?.includes('VBA')
            )) {
              const allVbaEntries = officeInfo.entries
                .filter((entry: any) => 
                  entry.name?.includes('VBA') || 
                  entry.name?.includes('Macro') ||
                  entry.clsid_literal?.includes('VBA')
                );
              const vbaEntries = allVbaEntries.map((entry: any) => entry.name);
              
              if (vbaEntries.length > 0 && !officeInfo?.macros) {
                suspiciousIndicators.push({
                  type: 'vba',
                  title: 'VBA/Macro OLE Entries Found',
                  count: allVbaEntries.length,
                  items: vbaEntries
                });
              }
            }
            
            // Add macro warning if present
            const hasMacros = (officeInfo?.macros && officeInfo.macros.length > 0) || 
                             (officeInfo?.entries?.some((entry: any) => 
                               entry.name?.includes('VBA') || 
                               entry.name?.includes('Macro') ||
                               entry.clsid_literal?.includes('VBA')
                             ));
            
            return suspiciousIndicators.length > 0 ? (
              <Card className={hasMacros ? "border-orange-200 dark:border-orange-900/30" : ""}>
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="h-5 w-5 text-orange-600" />
                      <span>Suspicious Indicators</span>
                    </div>
                    {hasMacros && (
                      <Badge variant="destructive" className="text-xs">
                        MACROS DETECTED
                      </Badge>
                    )}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Two column grid layout */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    {suspiciousIndicators.map((indicator, idx) => (
                      <div key={idx} className={`p-3 rounded-lg border ${
                        indicator.type === 'macro' ? 'bg-orange-50/50 dark:bg-orange-900/10 border-orange-200 dark:border-orange-900/30' :
                        indicator.type === 'behavior' || indicator.type === 'detection' ? 'bg-red-50/50 dark:bg-red-900/10 border-red-200 dark:border-red-900/30' :
                        'bg-muted/50 border-border'
                      }`}>
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-2">
                            {indicator.type === 'macro' && <FileText className="h-4 w-4 text-orange-600" />}
                            {indicator.type === 'behavior' && <Activity className="h-4 w-4 text-red-600" />}
                            {indicator.type === 'detection' && <Shield className="h-4 w-4 text-red-600" />}
                            {indicator.type === 'sandbox' && <Bug className="h-4 w-4 text-yellow-600" />}
                            {indicator.type === 'vba' && <Code className="h-4 w-4 text-orange-600" />}
                            <h4 className="text-sm font-medium">{indicator.title}</h4>
                          </div>
                          <Badge 
                            variant={indicator.type === 'macro' || indicator.type === 'vba' ? "destructive" : "outline"} 
                            className="text-xs"
                          >
                            {indicator.count}
                          </Badge>
                        </div>
                        <div className="space-y-1 max-h-32 overflow-y-auto">
                          {indicator.items.map((item, itemIdx) => (
                            <div key={itemIdx} className="text-xs text-muted-foreground p-1.5 bg-background/50 rounded">
                              {item}
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                  
                  {/* Macro security warning */}
                  {hasMacros && (
                    <div className="mt-4 p-3 bg-red-100/50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-900/30">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-red-600 flex-shrink-0 mt-0.5" />
                        <div className="text-sm text-red-700 dark:text-red-300">
                          <p className="font-medium">Security Warning - Office Macros</p>
                          <p className="text-xs mt-1">
                            This document contains VBA macros which can execute malicious code. 
                            Only enable macros from trusted sources. Macros are commonly used in malware campaigns.
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            ) : null;
          })()}

          {/* Behavioral Timeline - Key Insights */}
          {behavioral_analysis && behavioral_analysis.behavioral_timeline && behavioral_analysis.behavioral_timeline.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Activity className="h-5 w-5 text-orange-600" />
                    <span>Behavioral Timeline</span>
                  </div>
                  <Badge variant="destructive" className="text-xs">
                    Critical Insight - Affects Risk Score
                  </Badge>
                </CardTitle>
                <p className="text-sm text-muted-foreground mt-2">
                  Key behavioral events that impact the risk assessment
                </p>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-64">
                  <div className="space-y-2">
                    {behavioral_analysis.behavioral_timeline
                      .filter(event => event.severity === 'critical' || event.severity === 'high')
                      .slice(0, 10)
                      .map((event, idx) => (
                        <div 
                          key={idx} 
                          className="border-l-4 pl-3 py-2" 
                          style={{ 
                            borderColor: event.severity === 'critical' ? '#ef4444' : '#f97316'
                          }}
                        >
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="text-sm font-medium">{event.description}</div>
                              <div className="text-xs text-muted-foreground mt-1">
                                {event.event_type} • {formatDate(event.timestamp)}
                              </div>
                            </div>
                            <Badge 
                              variant="destructive"
                              className="text-xs ml-2"
                            >
                              {event.severity}
                            </Badge>
                          </div>
                        </div>
                    ))}
                    {behavioral_analysis.behavioral_timeline.filter(e => e.severity === 'critical' || e.severity === 'high').length > 10 && (
                      <p className="text-xs text-muted-foreground text-center pt-2">
                        +{behavioral_analysis.behavioral_timeline.filter(e => e.severity === 'critical' || e.severity === 'high').length - 10} more critical events
                      </p>
                    )}
                  </div>
                </ScrollArea>
                
                {/* Behavioral Statistics Summary */}
                <div className="mt-4 pt-4 border-t">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                    <div>
                      <div className="text-2xl font-bold text-red-600">
                        {behavioral_analysis.severity_breakdown?.critical || 0}
                      </div>
                      <div className="text-xs text-muted-foreground">Critical Events</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-orange-600">
                        {behavioral_analysis.severity_breakdown?.high || 0}
                      </div>
                      <div className="text-xs text-muted-foreground">High Risk</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold">
                        {behavioral_analysis.total_behaviors || 0}
                      </div>
                      <div className="text-xs text-muted-foreground">Total Behaviors</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-blue-600">
                        {(behavioral_analysis.network_connections?.length || 0) + 
                         (behavioral_analysis.file_operations?.length || 0)}
                      </div>
                      <div className="text-xs text-muted-foreground">IOCs</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Key Behavioral Insights */}
          {behavioral_analysis && behavioral_analysis.total_behaviors > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bug className="h-5 w-5 text-red-600" />
                  <span>Key Behavioral Insights</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Top Processes */}
                {behavioral_analysis.top_processes && behavioral_analysis.top_processes.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Suspicious Process Activity</h4>
                    <div className="space-y-2">
                      {behavioral_analysis.top_processes.slice(0, 3).map((process, idx) => (
                        <div key={idx} className="text-xs p-2 bg-muted/30 rounded flex justify-between">
                          <span className="font-mono truncate flex-1">{process.process_path}</span>
                          <Badge variant="outline" className="text-xs ml-2">{process.count} events</Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* Network Connections */}
                {behavioral_analysis.network_connections && behavioral_analysis.network_connections.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Network Activity</h4>
                    <div className="space-y-2">
                      {behavioral_analysis.network_connections.slice(0, 3).map((conn, idx) => (
                        <div key={idx} className="text-xs p-2 bg-muted/30 rounded">
                          <div className="flex justify-between">
                            <span className="font-mono">{conn.destination_ip}:{conn.destination_port}</span>
                            <Badge variant="outline" className="text-xs">{conn.protocol}</Badge>
                          </div>
                          <span className="text-muted-foreground">{conn.count} connections</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* File Operations */}
                {behavioral_analysis.file_operations && behavioral_analysis.file_operations.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">File System Activity</h4>
                    <div className="space-y-2">
                      {behavioral_analysis.file_operations.slice(0, 3).map((file, idx) => (
                        <div key={idx} className="text-xs p-2 bg-muted/30 rounded">
                          <div className="flex justify-between">
                            <span className="font-mono truncate flex-1">{file.target_file}</span>
                            <Badge variant="outline" className="text-xs ml-2">{file.operation_type}</Badge>
                          </div>
                          <span className="text-muted-foreground">{file.count} operations</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* AV Results Tab */}
        <TabsContent value="av-results" className="space-y-6">
          {/* Detection Statistics */}
          <div>
            <h2 className="text-xl font-semibold mb-4">Detection & Intelligence</h2>
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5" />
                  <span>Detection Statistics</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                  {[
                    { label: 'Malicious', count: detectionCounts.malicious, color: 'hsl(var(--malicious))' },
                    { label: 'Suspicious', count: detectionCounts.suspicious, color: 'hsl(var(--suspicious))' },
                    { label: 'Clean', count: detectionCounts.clean, color: 'hsl(var(--clean))' },
                    { label: 'Undetected', count: detectionCounts.undetected, color: 'hsl(var(--undetected))' },
                    { label: 'Timeout', count: detectionCounts.timeout, color: 'hsl(var(--muted-foreground))' },
                    { label: 'Error', count: detectionCounts.error, color: 'hsl(var(--muted-foreground))' },
                  ].map(stat => (
                    <div key={stat.label} className="text-center">
                      <div 
                        className="w-4 h-4 rounded-full mx-auto mb-2" 
                        style={{ backgroundColor: stat.color }}
                      />
                      <div className="text-2xl font-bold">{stat.count}</div>
                      <div className="text-xs text-muted-foreground">{stat.label}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-4 pt-4 border-t text-center">
                  <div className="text-lg font-semibold">Total Engines: {analysis_results.length}</div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* AV Detection Results */}
          <Card>
            <CardHeader>
              <CardTitle>Antivirus Detection Results</CardTitle>
            </CardHeader>
            <CardContent>
              {/* Malicious Detections */}
              {analysis_results.filter(r => r.category === 'malicious').length > 0 && (
                <div className="mb-6">
                  <h3 className="text-sm font-semibold text-red-600 mb-3 flex items-center gap-2">
                    <div className="w-2 h-2 bg-red-600 rounded-full"/>
                    Malicious Detections ({analysis_results.filter(r => r.category === 'malicious').length})
                  </h3>
                  <div className="space-y-2">
                    {analysis_results
                      .filter(r => r.category === 'malicious')
                      .sort((a, b) => a.engine_name.localeCompare(b.engine_name))
                      .map((result, idx) => (
                        <div key={`malicious-${idx}`} className="flex items-center gap-3 p-2 rounded-md hover:bg-accent/50 transition-colors">
                          <div className="w-24 text-sm font-medium truncate" title={result.engine_name}>
                            {result.engine_name}
                          </div>
                          <div className="flex-1 bg-red-600/20 rounded-md p-1.5">
                            <div className="bg-red-600 h-2 rounded-sm" style={{ width: '100%' }}/>
                          </div>
                          <div className="flex-1 text-sm font-mono">
                            {result.result ? (
                              <button
                                onClick={() => navigate(`/search?q=${encodeURIComponent(result.result)}`)}
                                className="text-red-600 hover:underline cursor-pointer text-left truncate block w-full"
                                title={`Search for ${result.result}`}
                              >
                                {result.result}
                              </button>
                            ) : (
                              <span className="text-muted-foreground">No signature</span>
                            )}
                          </div>
                        </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Suspicious Detections */}
              {analysis_results.filter(r => r.category === 'suspicious').length > 0 && (
                <div className="mb-6">
                  <h3 className="text-sm font-semibold text-orange-600 mb-3 flex items-center gap-2">
                    <div className="w-2 h-2 bg-orange-600 rounded-full"/>
                    Suspicious Detections ({analysis_results.filter(r => r.category === 'suspicious').length})
                  </h3>
                  <div className="space-y-2">
                    {analysis_results
                      .filter(r => r.category === 'suspicious')
                      .sort((a, b) => a.engine_name.localeCompare(b.engine_name))
                      .map((result, idx) => (
                        <div key={`suspicious-${idx}`} className="flex items-center gap-3 p-2 rounded-md hover:bg-accent/50 transition-colors">
                          <div className="w-24 text-sm font-medium truncate" title={result.engine_name}>
                            {result.engine_name}
                          </div>
                          <div className="flex-1 bg-orange-600/20 rounded-md p-1.5">
                            <div className="bg-orange-600 h-2 rounded-sm" style={{ width: '100%' }}/>
                          </div>
                          <div className="flex-1 text-sm font-mono">
                            {result.result ? (
                              <button
                                onClick={() => navigate(`/search?q=${encodeURIComponent(result.result)}`)}
                                className="text-orange-600 hover:underline cursor-pointer text-left truncate block w-full"
                                title={`Search for ${result.result}`}
                              >
                                {result.result}
                              </button>
                            ) : (
                              <span className="text-muted-foreground">No signature</span>
                            )}
                          </div>
                        </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Clean/Undetected Summary */}
              {(analysis_results.filter(r => r.category === 'clean' || r.category === 'undetected').length > 0) && (
                <div className="mb-6">
                  <h3 className="text-sm font-semibold text-green-600 mb-3 flex items-center gap-2">
                    <div className="w-2 h-2 bg-green-600 rounded-full"/>
                    Clean/Undetected ({analysis_results.filter(r => r.category === 'clean' || r.category === 'undetected').length})
                  </h3>
                  <div className="grid grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2">
                    {analysis_results
                      .filter(r => r.category === 'clean' || r.category === 'undetected')
                      .sort((a, b) => a.engine_name.localeCompare(b.engine_name))
                      .map((result, idx) => (
                        <div key={`clean-${idx}`} className="text-xs text-muted-foreground p-1.5 bg-green-600/10 rounded text-center" title={result.engine_name}>
                          {result.engine_name}
                        </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Detailed Table View (collapsible) */}
              <details className="mt-6 border-t pt-4">
                <summary className="cursor-pointer text-sm font-medium text-muted-foreground hover:text-foreground">
                  View detailed results table
                </summary>
                <div className="mt-4">
                  <ScrollArea className="h-96">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Engine</TableHead>
                          <TableHead>Version</TableHead>
                          <TableHead>Category</TableHead>
                          <TableHead>Result</TableHead>
                          <TableHead>Update</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {analysis_results
                          .sort((a, b) => {
                            const categoryOrder = ['malicious', 'suspicious', 'harmless', 'clean', 'undetected', 'timeout', 'failure'];
                            const aIndex = categoryOrder.indexOf(a.category.toLowerCase());
                            const bIndex = categoryOrder.indexOf(b.category.toLowerCase());
                            if (aIndex !== bIndex) return aIndex - bIndex;
                            return a.engine_name.localeCompare(b.engine_name);
                          })
                          .map((result, idx) => (
                            <TableRow key={`${result.engine_name}-${idx}`}>
                              <TableCell className="font-medium">{result.engine_name}</TableCell>
                              <TableCell className="text-sm text-muted-foreground">
                                {result.engine_version || 'N/A'}
                              </TableCell>
                              <TableCell>
                                <Badge 
                                  variant={getVerdictBadgeVariant(result.category)}
                                  className="text-xs"
                                >
                                  {result.category}
                                </Badge>
                              </TableCell>
                              <TableCell className="font-mono text-sm">
                                {result.result ? (
                                  <button
                                    onClick={() => navigate(`/search?q=${encodeURIComponent(result.result)}`)}
                                    className="text-primary hover:underline cursor-pointer text-left"
                                    title={`Search for ${result.result}`}
                                  >
                                    {result.result}
                                  </button>
                                ) : (
                                  'Clean'
                                )}
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {result.engine_update || 'N/A'}
                              </TableCell>
                            </TableRow>
                          ))}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                </div>
              </details>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Sandbox Results Tab */}
        <TabsContent value="sandbox" className="space-y-4">
          <h2 className="text-xl font-semibold mb-4">Sandbox Analysis</h2>
          {behavioral_analysis && behavioral_analysis.total_behaviors > 0 ? (
            <BehavioralAnalysisDisplay 
              behavioral_analysis={behavioral_analysis} 
              sandbox_behaviors={sandbox_behaviors || []}
            />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Sandbox Analysis</CardTitle>
                {sandbox_verdicts.length > 0 && (
                  <p className="text-sm text-muted-foreground mt-2">
                    Analyzed by {sandbox_verdicts.length} sandbox environment{sandbox_verdicts.length > 1 ? 's' : ''}
                  </p>
                )}
              </CardHeader>
              <CardContent>
                {sandbox_verdicts.length === 0 ? (
                  <div className="p-6 text-center text-muted-foreground">
                    <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No sandbox analysis results available</p>
                    <p className="text-xs mt-2">This file may not have been analyzed in sandbox environments</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {sandbox_verdicts.map((verdict, idx) => {
                      const category = verdict.verdict?.category || 'unknown';
                      return (
                        <div key={`${verdict.sandbox_name}-${idx}`} className="border rounded-lg p-4">
                          <div className="flex items-start justify-between">
                            <div className="flex items-center gap-3">
                              <div className="p-2 bg-muted rounded-lg">
                                <Activity className="h-4 w-4" />
                              </div>
                              <div>
                                <div className="font-medium">{verdict.sandbox_name}</div>
                                <div className="text-xs text-muted-foreground">Sandbox Environment</div>
                              </div>
                            </div>
                            <Badge 
                              variant={getVerdictBadgeVariant(category)}
                              className="text-xs"
                            >
                              {category}
                            </Badge>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Intelligence Tab */}
        <TabsContent value="intelligence" className="space-y-4">
          <h2 className="text-xl font-semibold mb-4">Threat Intelligence</h2>
          {(() => {
            const detectionRules = crowdsourced_data.filter(item => 
              item.data_type === 'yara' || item.data_type === 'sigma'
            );
            const otherIntel = crowdsourced_data.filter(item => 
              item.data_type !== 'yara' && item.data_type !== 'sigma'
            );
            
            return (
              <>
                {detectionRules.length > 0 && (
                  <DetectionRulesViewer 
                    crowdsourcedData={detectionRules} 
                    fileHash={report.sha256 || report.file_hash || ''}
                  />
                )}
                
                {otherIntel.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle>Other Threat Intelligence</CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      <ScrollArea className="h-96">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Type</TableHead>
                              <TableHead>Source</TableHead>
                              <TableHead>Description</TableHead>
                              <TableHead>Author</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {otherIntel.map((item, idx) => {
                              const data = item.data || {};
                              const dataType = item.data_type || 'unknown';
                              const description = data.description || item.description || '';
                              const author = data.author || item.author || 'N/A';
                              const source = data.source || item.source || 'N/A';
                              
                              return (
                                <TableRow key={`${dataType}-${idx}`}>
                                  <TableCell className="font-medium">
                                    <Badge variant="outline" className="text-xs">
                                      {dataType.toUpperCase()}
                                    </Badge>
                                  </TableCell>
                                  <TableCell className="font-mono text-sm">{source}</TableCell>
                                  <TableCell className="text-sm max-w-md">
                                    <div className="truncate" title={description}>
                                      {description || 'No description available'}
                                    </div>
                                  </TableCell>
                                  <TableCell className="text-sm">{author}</TableCell>
                                </TableRow>
                              );
                            })}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                )}
                
                {crowdsourced_data.length === 0 && (
                  <Card>
                    <CardContent className="p-6">
                      <div className="text-center text-muted-foreground">
                        No threat intelligence data available
                      </div>
                    </CardContent>
                  </Card>
                )}
              </>
            );
          })()}
        </TabsContent>

        {/* Relationships Tab */}
        <TabsContent value="relationships" className="space-y-4">
          <h2 className="text-xl font-semibold mb-4">File Relationships</h2>
          <Card>
            <CardHeader>
              <CardTitle>File Relationships</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {relationships.length === 0 ? (
                <div className="p-6 text-center text-muted-foreground">
                  No file relationships available
                </div>
              ) : (
                <ScrollArea className="h-96">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Relationship Type</TableHead>
                        <TableHead>Target ID</TableHead>
                        <TableHead>Target Type</TableHead>
                        <TableHead>Context</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {relationships.map((rel, idx) => (
                        <TableRow key={`${rel.relation_type}-${idx}`}>
                          <TableCell className="font-medium">{rel.relation_type || 'N/A'}</TableCell>
                          <TableCell className="font-mono text-sm">
                            {rel.target_id ? truncateHash(rel.target_id, 20) : 'N/A'}
                          </TableCell>
                          <TableCell>{rel.target_type || 'N/A'}</TableCell>
                          <TableCell className="text-sm">{rel.context || 'N/A'}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Technical Analysis Tab */}
        <TabsContent value="technical" className="space-y-6">
          <h2 className="text-xl font-semibold mb-4">Technical Analysis</h2>
          <AnalysisDisplay report={report} />

          {/* File Metadata Section */}
          <div>
            <h2 className="text-xl font-semibold mb-4">File Metadata</h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* File Information */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <FileText className="h-5 w-5" />
                    <span>File Information</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3">
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">File Name</label>
                      <button
                        onClick={() => navigate(`/search?q=${encodeURIComponent(report.meaningful_name || report.names?.[0] || '')}`)}
                        className="text-sm font-mono break-all text-left text-primary hover:underline cursor-pointer block"
                        title={`Search for filename: ${report.meaningful_name || report.names?.[0] || 'Unknown'}`}
                      >
                        {report.meaningful_name || report.names?.[0] || 'Unknown'}
                      </button>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">File Type</label>
                      <button
                        onClick={() => navigate(`/search?q=${encodeURIComponent(report.type_description || report.type_tag || '')}`)}
                        className="text-sm text-left text-primary hover:underline cursor-pointer block"
                        title={`Search for file type: ${report.type_description || report.type_tag || 'Unknown'}`}
                      >
                        {report.type_description || report.type_tag || 'Unknown'}
                      </button>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">File Size</label>
                      <p className="text-sm">{report.size ? formatBytes(report.size) : 'Unknown'}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Magic</label>
                      {report.magic && report.magic !== 'N/A' ? (
                        <button
                          onClick={() => navigate(`/search?q=${encodeURIComponent(report.magic)}`)}
                          className="text-sm text-left text-primary hover:underline cursor-pointer block"
                          title={`Search for magic: ${report.magic}`}
                        >
                          {report.magic}
                        </button>
                      ) : (
                        <p className="text-sm">N/A</p>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* File Hashes */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Hash className="h-5 w-5" />
                    <span>File Hashes</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {[
                    { label: 'SHA256', value: report.sha256 || report.file_hash },
                    { label: 'SHA1', value: report.sha1 },
                    { label: 'MD5', value: report.md5 },
                    { label: 'SSDEEP', value: report.ssdeep },
                    { label: 'TLSH', value: report.tlsh },
                    { label: 'Imphash', value: report.imphash },
                    { label: 'Authentihash', value: report.authentihash },
                  ].map(hash => hash.value && (
                    <div key={hash.label} className="space-y-1">
                      <label className="text-sm font-medium text-muted-foreground">{hash.label}</label>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => navigate(`/search?q=${encodeURIComponent(hash.value!)}`)}
                          className="text-xs font-mono break-all flex-1 text-left text-primary hover:underline cursor-pointer"
                          title={`Search for ${hash.label}: ${hash.value}`}
                        >
                          {hash.value}
                        </button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(hash.value!, hash.label)}
                          className="h-6 w-6 p-0"
                          title={`Copy ${hash.label}`}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                      {copiedHash === hash.label && (
                        <p className="text-xs text-green-600">Copied!</p>
                      )}
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>
      </Tabs>

      {/* Rule Detail Dialog */}
      <Dialog open={ruleDialogOpen} onOpenChange={setRuleDialogOpen}>
        <DialogContent className="w-[95vw] max-w-4xl max-h-[90vh] sm:max-h-[80vh] overflow-hidden">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Code className={`h-5 w-5 ${selectedRule?.type === 'yara' ? 'text-purple-600' : 'text-blue-600'}`} />
              {selectedRule?.rule_name || 'Rule Details'}
            </DialogTitle>
            <DialogDescription>
              {selectedRule?.description || `${selectedRule?.type?.toUpperCase() || 'Detection'} rule details`}
            </DialogDescription>
          </DialogHeader>
          
          <div className="mt-4">
            {selectedRule?.type === 'yara' ? (
              <YaraRuleViewer 
                rules={[{
                  rule_name: selectedRule.rule_name,
                  author: selectedRule.author,
                  description: selectedRule.description,
                  source: selectedRule.source,
                  ruleset_name: selectedRule.ruleset_name,
                  ruleset_id: selectedRule.ruleset_id
                }]}
                fileHash={analysis?.sha256 || analysis?.file_hash || ''}
              />
            ) : selectedRule?.type === 'sigma' ? (
              <SigmaRuleViewer
                rules={[{
                  rule_name: selectedRule.rule_name,
                  author: selectedRule.author,
                  description: selectedRule.description,
                  source: selectedRule.source,
                  ruleset_name: selectedRule.ruleset_name,
                  ruleset_id: selectedRule.ruleset_id,
                  level: selectedRule.level,
                  status: selectedRule.status,
                  tags: selectedRule.tags
                }]}
                fileHash={analysis?.sha256 || analysis?.file_hash || ''}
              />
            ) : (
              <div className="p-6 text-center text-muted-foreground">
                <p>No rule details available</p>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}