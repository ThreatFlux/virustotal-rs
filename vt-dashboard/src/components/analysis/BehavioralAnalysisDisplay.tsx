import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { formatDate } from '@/lib/utils';
import { Activity } from 'lucide-react';
import { BehavioralAnalysis, SandboxBehavior } from '@/types';

interface BehavioralAnalysisDisplayProps {
  behavioral_analysis: BehavioralAnalysis;
  sandbox_behaviors: SandboxBehavior[];
}

export function BehavioralAnalysisDisplay({ behavioral_analysis, sandbox_behaviors }: BehavioralAnalysisDisplayProps) {
  if (!behavioral_analysis || behavioral_analysis.total_behaviors === 0) {
    return (
      <div className="p-6 text-center text-muted-foreground">
        <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No behavioral analysis data available</p>
        <p className="text-xs mt-2">This file may not have been analyzed for behavioral patterns</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Behavioral Analysis Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Activity className="h-5 w-5" />
            <span>Behavioral Analysis Overview</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
            <div className="text-center">
              <div className="text-2xl font-bold">{behavioral_analysis.total_behaviors}</div>
              <div className="text-xs text-muted-foreground">Total Behaviors</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-red-500">
                {behavioral_analysis.severity_breakdown.critical + behavioral_analysis.severity_breakdown.high}
              </div>
              <div className="text-xs text-muted-foreground">High Risk</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold">{behavioral_analysis.behavior_categories.process_activity}</div>
              <div className="text-xs text-muted-foreground">Process Activity</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold">{behavioral_analysis.behavior_categories.network_activity}</div>
              <div className="text-xs text-muted-foreground">Network Activity</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold">{behavioral_analysis.behavior_categories.file_operations}</div>
              <div className="text-xs text-muted-foreground">File Operations</div>
            </div>
          </div>

          {/* Severity Breakdown */}
          <div className="mb-6">
            <h4 className="text-sm font-medium mb-3">Severity Distribution</h4>
            <div className="grid grid-cols-5 gap-2">
              {[
                { label: 'Critical', count: behavioral_analysis.severity_breakdown.critical, color: 'bg-red-500' },
                { label: 'High', count: behavioral_analysis.severity_breakdown.high, color: 'bg-orange-500' },
                { label: 'Medium', count: behavioral_analysis.severity_breakdown.medium, color: 'bg-yellow-500' },
                { label: 'Low', count: behavioral_analysis.severity_breakdown.low, color: 'bg-blue-500' },
                { label: 'Info', count: behavioral_analysis.severity_breakdown.info, color: 'bg-gray-400' },
              ].map(severity => (
                <div key={severity.label} className="text-center">
                  <div 
                    className={`w-full h-2 rounded-full mb-2 ${severity.color}`} 
                    style={{ opacity: severity.count > 0 ? 1 : 0.2 }} 
                  />
                  <div className="text-sm font-medium">{severity.count}</div>
                  <div className="text-xs text-muted-foreground">{severity.label}</div>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Detailed Behavioral Data */}
      <Tabs defaultValue="processes" className="space-y-4">
        <div className="overflow-x-auto">
          <TabsList className="inline-flex h-10 items-center justify-start rounded-md bg-muted p-1 text-muted-foreground min-w-max">
            <TabsTrigger value="processes" className="whitespace-nowrap">Process Activity</TabsTrigger>
            <TabsTrigger value="network" className="whitespace-nowrap">Network Activity</TabsTrigger>
            <TabsTrigger value="files" className="whitespace-nowrap">File Operations</TabsTrigger>
            <TabsTrigger value="registry" className="whitespace-nowrap">Registry Operations</TabsTrigger>
            <TabsTrigger value="timeline" className="whitespace-nowrap">Timeline</TabsTrigger>
            <TabsTrigger value="rules" className="whitespace-nowrap">Detection Rules</TabsTrigger>
          </TabsList>
        </div>

        <TabsContent value="processes" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Process Activity</CardTitle>
            </CardHeader>
            <CardContent>
              {behavioral_analysis.top_processes.length === 0 ? (
                <div className="text-center text-muted-foreground py-8">No process activity detected</div>
              ) : (
                <div className="space-y-4">
                  {behavioral_analysis.top_processes.map((process, idx) => (
                    <div key={idx} className="border rounded-lg p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div className="font-mono text-sm break-all flex-1 mr-4">{process.process_path}</div>
                        <Badge variant="outline" className="text-xs whitespace-nowrap">{process.count} events</Badge>
                      </div>
                      {process.command_lines.length > 0 && (
                        <div className="mt-3 pt-3 border-t">
                          <div className="text-xs text-muted-foreground mb-2">Command Lines:</div>
                          <div className="space-y-1">
                            {process.command_lines.slice(0, 3).map((cmd, cmdIdx) => (
                              <div key={cmdIdx} className="font-mono text-xs bg-muted p-2 rounded break-all">{cmd}</div>
                            ))}
                            {process.command_lines.length > 3 && (
                              <div className="text-xs text-muted-foreground">+{process.command_lines.length - 3} more command lines</div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="network" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Network Connections</CardTitle>
            </CardHeader>
            <CardContent>
              {behavioral_analysis.network_connections.length === 0 ? (
                <div className="text-center text-muted-foreground py-8">No network activity detected</div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {behavioral_analysis.network_connections.map((conn, idx) => (
                    <div key={idx} className="border rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="font-mono text-sm">{conn.destination_ip}</div>
                        <Badge variant="outline" className="text-xs">{conn.count} connections</Badge>
                      </div>
                      <div className="text-xs text-muted-foreground space-y-1">
                        <div>Port: {conn.destination_port}</div>
                        <div>Protocol: {conn.protocol}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="files" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>File Operations</CardTitle>
            </CardHeader>
            <CardContent>
              {behavioral_analysis.file_operations.length === 0 ? (
                <div className="text-center text-muted-foreground py-8">No file operations detected</div>
              ) : (
                <div className="space-y-3">
                  {behavioral_analysis.file_operations.map((file, idx) => (
                    <div key={idx} className="border rounded-lg p-4">
                      <div className="flex items-start justify-between">
                        <div className="font-mono text-sm break-all flex-1 mr-4">{file.target_file}</div>
                        <div className="text-right">
                          <Badge variant="outline" className="text-xs mb-1">{file.count} operations</Badge>
                          <div className="text-xs text-muted-foreground">{file.operation_type}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="registry" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Registry Operations</CardTitle>
            </CardHeader>
            <CardContent>
              {behavioral_analysis.registry_operations.length === 0 ? (
                <div className="text-center text-muted-foreground py-8">No registry operations detected</div>
              ) : (
                <div className="space-y-3">
                  {behavioral_analysis.registry_operations.map((registry, idx) => (
                    <div key={idx} className="border rounded-lg p-4">
                      <div className="flex items-start justify-between">
                        <div className="font-mono text-sm break-all flex-1 mr-4">{registry.registry_key}</div>
                        <div className="text-right">
                          <Badge variant="outline" className="text-xs mb-1">{registry.count} operations</Badge>
                          <div className="text-xs text-muted-foreground">{registry.operation_type}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="timeline" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Behavioral Timeline</CardTitle>
            </CardHeader>
            <CardContent>
              {behavioral_analysis.behavioral_timeline.length === 0 ? (
                <div className="text-center text-muted-foreground py-8">No timeline data available</div>
              ) : (
                <ScrollArea className="h-96">
                  <div className="space-y-3">
                    {behavioral_analysis.behavioral_timeline.map((event, idx) => (
                      <div 
                        key={idx} 
                        className="border-l-4 pl-4 py-2" 
                        style={{ 
                          borderColor: event.severity === 'critical' ? '#ef4444' : 
                                      event.severity === 'high' ? '#f97316' : 
                                      event.severity === 'medium' ? '#eab308' : '#6b7280' 
                        }}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="text-sm font-medium">{event.description}</div>
                            <div className="text-xs text-muted-foreground mt-1">
                              {formatDate(event.timestamp)} • {event.event_type}
                            </div>
                          </div>
                          <Badge 
                            variant={event.severity === 'critical' || event.severity === 'high' ? 'destructive' : 'outline'}
                            className="text-xs ml-2"
                          >
                            {event.severity}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="rules" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Detection Rules Triggered</CardTitle>
            </CardHeader>
            <CardContent>
              {sandbox_behaviors.length === 0 ? (
                <div className="text-center text-muted-foreground py-8">No detection rules triggered</div>
              ) : (
                <div className="space-y-4">
                  {sandbox_behaviors.map((behavior, idx) => (
                    <div key={idx} className="border rounded-lg p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="font-medium text-sm">{behavior.rule_title || behavior.rule_id}</div>
                          <div className="text-xs text-muted-foreground mt-1">{behavior.rule_author}</div>
                        </div>
                        <div className="flex flex-col items-end gap-2">
                          <Badge 
                            variant={
                              behavior.severity === 'critical' || behavior.severity === 'high' 
                                ? 'destructive' 
                                : behavior.severity === 'medium' 
                                ? 'default'
                                : 'secondary'
                            }
                            className="text-xs"
                          >
                            {behavior.severity}
                          </Badge>
                          {behavior.event_count && (
                            <Badge variant="outline" className="text-xs">
                              {behavior.event_count} events
                            </Badge>
                          )}
                        </div>
                      </div>
                      
                      {behavior.rule_description && (
                        <div className="text-sm text-muted-foreground mb-3 p-3 bg-muted rounded">
                          {behavior.rule_description}
                        </div>
                      )}

                      {behavior.rule_source && (
                        <div className="text-xs text-muted-foreground">
                          Source: {behavior.rule_source}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}