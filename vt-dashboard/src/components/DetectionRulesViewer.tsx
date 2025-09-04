import React from 'react';
import { YaraRuleViewer } from './YaraRuleViewer';
import { SigmaRuleViewer } from './SigmaRuleViewer';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Code, Shield, FileSearch } from 'lucide-react';

interface DetectionRule {
  data_type: string;
  data?: any;
  rule_name?: string;
  author?: string;
  description?: string;
  source?: string;
  [key: string]: any;
}

interface DetectionRulesViewerProps {
  crowdsourcedData: DetectionRule[];
  fileHash: string;
}

export function DetectionRulesViewer({ crowdsourcedData, fileHash }: DetectionRulesViewerProps) {
  // Extract YARA rules
  const yaraRules = crowdsourcedData
    .filter(item => item.data_type === 'yara')
    .map(item => ({
      rule_name: item.data?.rule_name || item.rule_name || 'Unknown',
      author: item.data?.author || item.author,
      description: item.data?.description || item.description,
      source: item.data?.source || item.source,
      ruleset_name: item.data?.ruleset_name,
      ruleset_id: item.data?.ruleset_id
    }));

  // Extract Sigma rules
  const sigmaRules = crowdsourcedData
    .filter(item => item.data_type === 'sigma')
    .map(item => ({
      rule_name: item.data?.rule_name || item.rule_name || 'Unknown',
      author: item.data?.author || item.author,
      description: item.data?.description || item.description,
      source: item.data?.source || item.source,
      ruleset_name: item.data?.ruleset_name,
      ruleset_id: item.data?.ruleset_id,
      level: item.data?.level || item.level,
      status: item.data?.status || item.status,
      tags: item.data?.tags || item.tags
    }));

  const totalRules = yaraRules.length + sigmaRules.length;

  if (totalRules === 0) {
    return null;
  }

  // If only one type of rules, show directly without tabs
  if (yaraRules.length > 0 && sigmaRules.length === 0) {
    return <YaraRuleViewer rules={yaraRules} fileHash={fileHash} />;
  }

  if (sigmaRules.length > 0 && yaraRules.length === 0) {
    return <SigmaRuleViewer rules={sigmaRules} fileHash={fileHash} />;
  }

  // If both types exist, show in tabs
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileSearch className="h-5 w-5 text-indigo-600" />
          Detection Rules
          <div className="flex gap-2 ml-auto">
            {yaraRules.length > 0 && (
              <Badge variant="secondary">
                {yaraRules.length} YARA
              </Badge>
            )}
            {sigmaRules.length > 0 && (
              <Badge variant="secondary">
                {sigmaRules.length} Sigma
              </Badge>
            )}
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue={yaraRules.length > 0 ? "yara" : "sigma"}>
          <TabsList className="grid w-full grid-cols-2">
            {yaraRules.length > 0 && (
              <TabsTrigger value="yara" className="text-xs sm:text-sm">
                <Code className="h-4 w-4 mr-1 sm:mr-2" />
                <span className="hidden sm:inline">YARA Rules</span>
                <span className="sm:hidden">YARA</span>
                <span className="ml-1">({yaraRules.length})</span>
              </TabsTrigger>
            )}
            {sigmaRules.length > 0 && (
              <TabsTrigger value="sigma" className="text-xs sm:text-sm">
                <Shield className="h-4 w-4 mr-1 sm:mr-2" />
                <span className="hidden sm:inline">Sigma Rules</span>
                <span className="sm:hidden">Sigma</span>
                <span className="ml-1">({sigmaRules.length})</span>
              </TabsTrigger>
            )}
          </TabsList>
          
          {yaraRules.length > 0 && (
            <TabsContent value="yara" className="mt-4">
              <YaraRuleViewer rules={yaraRules} fileHash={fileHash} />
            </TabsContent>
          )}
          
          {sigmaRules.length > 0 && (
            <TabsContent value="sigma" className="mt-4">
              <SigmaRuleViewer rules={sigmaRules} fileHash={fileHash} />
            </TabsContent>
          )}
        </Tabs>
      </CardContent>
    </Card>
  );
}