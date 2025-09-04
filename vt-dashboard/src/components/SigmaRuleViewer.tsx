import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { ExternalLink, FileSearch, Github, AlertTriangle, Copy, Check, Loader2, Shield } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import Prism from 'prismjs';
import 'prismjs/themes/prism-tomorrow.css';
import 'prismjs/components/prism-yaml';

// Extend YAML syntax for Sigma-specific keywords
if (typeof Prism !== 'undefined' && Prism.languages.yaml) {
  // Add Sigma-specific tokens to YAML
  Prism.languages.sigma = Prism.languages.extend('yaml', {
    'sigma-keyword': {
      pattern: /\b(title|id|status|description|references|author|date|modified|tags|logsource|detection|falsepositives|level|category|product|service|definition|selection|condition|filter|timeframe|fields|correlation|action|threat)\b(?=:)/,
      alias: 'keyword'
    },
    'sigma-level': {
      pattern: /\b(critical|high|medium|low|informational)\b/,
      alias: 'constant'
    },
    'sigma-status': {
      pattern: /\b(stable|test|experimental|deprecated|unsupported)\b/,
      alias: 'builtin'
    },
    'sigma-operator': {
      pattern: /\b(and|or|not|1 of|all of|all of them)\b/,
      alias: 'operator'
    },
    'sigma-modifier': {
      pattern: /\|(?:contains|all|startswith|endswith|base64|base64offset|utf16|utf16le|utf16be|wide|re|regex|cidr|windash)\b/,
      alias: 'function'
    }
  });
}

interface SigmaRule {
  rule_name: string;
  author?: string;
  description?: string;
  source?: string;
  ruleset_name?: string;
  ruleset_id?: string;
  level?: string;
  status?: string;
  tags?: string[];
}

interface SigmaRuleViewerProps {
  rules: SigmaRule[];
  fileHash: string;
}

export function SigmaRuleViewer({ rules, fileHash }: SigmaRuleViewerProps) {
  const [selectedRule, setSelectedRule] = useState<SigmaRule | null>(null);
  const [ruleContent, setRuleContent] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);

  // Group rules by source
  const rulesBySource = rules.reduce((acc: Record<string, SigmaRule[]>, rule) => {
    const source = rule.source || 'Unknown Source';
    if (!acc[source]) acc[source] = [];
    acc[source].push(rule);
    return acc;
  }, {});

  // Determine risk level based on rule level or name
  const getRiskLevel = (rule: SigmaRule) => {
    const level = rule.level?.toLowerCase() || '';
    const name = rule.rule_name?.toLowerCase() || '';
    const desc = rule.description?.toLowerCase() || '';
    
    if (level === 'critical' || level === 'high') {
      return 'high';
    }
    if (level === 'medium' || name.includes('suspicious') || desc.includes('suspicious')) {
      return 'medium';
    }
    if (level === 'low' || level === 'informational') {
      return 'low';
    }
    
    // Fallback to name/description analysis
    if (name.includes('malware') || name.includes('attack') || name.includes('exploit') ||
        desc.includes('malicious') || desc.includes('attack')) {
      return 'high';
    }
    if (name.includes('anomaly') || name.includes('suspicious')) {
      return 'medium';
    }
    return 'low';
  };

  const fetchRuleFromGitHub = async (rule: SigmaRule) => {
    setLoading(true);
    setError(null);
    setRuleContent('');

    try {
      // Parse GitHub URL to get owner, repo, and potential path
      if (rule.source?.includes('github.com')) {
        const urlParts = rule.source.replace('https://github.com/', '').split('/');
        const owner = urlParts[0];
        const repo = urlParts[1];
        
        // Try to fetch the rule content from common Sigma locations
        const possiblePaths = [
          `rules/${rule.ruleset_name}.yml`,
          `rules/${rule.ruleset_name}.yaml`,
          `sigma/${rule.ruleset_name}.yml`,
          `sigma/${rule.ruleset_name}.yaml`,
          `detections/${rule.ruleset_name}.yml`,
          `detections/${rule.ruleset_name}.yaml`,
          `${rule.ruleset_name}.yml`,
          `${rule.ruleset_name}.yaml`,
          `rules/${rule.rule_name}.yml`,
          `rules/${rule.rule_name}.yaml`,
          // Common Sigma rule directory structures
          `rules/windows/${rule.ruleset_name}.yml`,
          `rules/linux/${rule.ruleset_name}.yml`,
          `rules/network/${rule.ruleset_name}.yml`,
          `rules/cloud/${rule.ruleset_name}.yml`,
          `rules/web/${rule.ruleset_name}.yml`,
        ];

        let content = null;
        for (const path of possiblePaths) {
          try {
            const response = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${path}`, {
              headers: {
                'Accept': 'application/vnd.github.v3.raw'
              }
            });
            
            if (response.ok) {
              content = await response.text();
              break;
            }
          } catch (e) {
            // Try next path
          }
        }

        if (content) {
          // If multiple rules in file, try to extract the specific one
          if (content.includes('title: ') && rule.rule_name) {
            // Try to find the specific rule by title
            const rules = content.split(/^(?=title:)/m);
            const matchingRule = rules.find(r => 
              r.toLowerCase().includes(rule.rule_name.toLowerCase()) ||
              r.toLowerCase().includes(rule.description?.toLowerCase() || '')
            );
            if (matchingRule) {
              setRuleContent(matchingRule.trim());
            } else {
              setRuleContent(content);
            }
          } else {
            setRuleContent(content);
          }
        } else {
          // If we can't fetch the actual rule, create a placeholder
          setRuleContent(generatePlaceholderRule(rule));
        }
      } else {
        setRuleContent(generatePlaceholderRule(rule));
      }
    } catch (err) {
      setError('Failed to fetch rule from GitHub');
      setRuleContent(generatePlaceholderRule(rule));
    } finally {
      setLoading(false);
    }
  };

  const generatePlaceholderRule = (rule: SigmaRule) => {
    return `# Sigma Rule: ${rule.rule_name}
# Source: ${rule.source || 'Unknown'}
# Note: Unable to fetch actual rule content from source.

title: ${rule.rule_name}
id: ${rule.ruleset_id || 'unknown-id'}
status: ${rule.status || 'experimental'}
description: ${rule.description || 'No description available'}
author: ${rule.author || 'Unknown'}
date: ${new Date().toISOString().split('T')[0]}
references:
    - ${rule.source || 'No reference available'}
tags:
${rule.tags?.map(tag => `    - ${tag}`).join('\n') || '    - detection'}
logsource:
    category: unknown
    product: unknown
detection:
    selection:
        # Rule conditions not available
        EventID: '*'
    condition: selection
falsepositives:
    - Unknown
level: ${rule.level || 'medium'}`;
  };

  const handleViewRule = (rule: SigmaRule) => {
    setSelectedRule(rule);
    setDialogOpen(true);
    fetchRuleFromGitHub(rule);
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(ruleContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  useEffect(() => {
    if (ruleContent) {
      // Highlight the code when content changes
      Prism.highlightAll();
    }
  }, [ruleContent]);

  if (rules.length === 0) return null;

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-blue-600" />
            Sigma Rule Detections
            <Badge variant="secondary" className="ml-auto">
              {rules.length} {rules.length === 1 ? 'rule' : 'rules'}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {Object.entries(rulesBySource).map(([source, sourceRules]) => (
            <div key={source} className="space-y-2">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Github className="h-4 w-4" />
                <span className="font-medium">{source}</span>
              </div>
              <div className="space-y-2">
                {sourceRules.map((rule, idx) => {
                  const risk = getRiskLevel(rule);
                  return (
                    <div
                      key={`${rule.rule_name}-${idx}`}
                      className="flex flex-col sm:flex-row sm:items-start sm:justify-between p-3 bg-muted/50 rounded-lg border hover:bg-muted/70 transition-colors space-y-2 sm:space-y-0"
                    >
                      <div className="flex-1 min-w-0">
                        <div className="flex flex-col sm:flex-row sm:items-center gap-2">
                          <p className="font-mono text-sm font-medium break-all sm:truncate">
                            {rule.rule_name}
                          </p>
                          <div className="flex flex-wrap gap-1">
                            {risk === 'high' && (
                              <Badge variant="destructive" className="text-xs">HIGH</Badge>
                            )}
                            {risk === 'medium' && (
                              <Badge variant="outline" className="text-xs border-yellow-600 text-yellow-600">MEDIUM</Badge>
                            )}
                            {rule.level && (
                              <Badge variant="secondary" className="text-xs">{rule.level.toUpperCase()}</Badge>
                            )}
                          </div>
                        </div>
                        {rule.author && (
                          <p className="text-xs text-muted-foreground mt-1">
                            By: {rule.author}
                          </p>
                        )}
                        {rule.description && (
                          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                            {rule.description}
                          </p>
                        )}
                        {rule.tags && rule.tags.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-2">
                            {rule.tags.slice(0, 3).map((tag, i) => (
                              <Badge key={i} variant="outline" className="text-[10px] px-1 py-0">
                                {tag}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleViewRule(rule)}
                        className="sm:ml-2 self-start sm:self-auto"
                      >
                        <FileSearch className="h-4 w-4" />
                        <span className="ml-2 sm:hidden">View Rule</span>
                      </Button>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}

          {/* Warning if high-risk rules detected */}
          {rules.some(r => getRiskLevel(r) === 'high') && (
            <Alert className="border-red-200 bg-red-50 dark:bg-red-900/20">
              <AlertTriangle className="h-4 w-4 text-red-600" />
              <AlertDescription className="text-red-700 dark:text-red-300">
                High-severity Sigma rules detected. This file exhibits behavior patterns associated with security incidents or attacks.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Rule Viewer Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="w-[95vw] max-w-4xl max-h-[90vh] sm:max-h-[80vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-blue-600" />
              {selectedRule?.rule_name}
            </DialogTitle>
            <DialogDescription>
              {selectedRule?.description || 'Sigma detection rule for security monitoring'}
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            {/* Rule Metadata */}
            {selectedRule && (
              <div className="flex flex-wrap gap-2">
                {selectedRule.author && (
                  <Badge variant="outline">Author: {selectedRule.author}</Badge>
                )}
                {selectedRule.level && (
                  <Badge 
                    variant={selectedRule.level === 'critical' || selectedRule.level === 'high' ? 'destructive' : 'outline'}
                  >
                    Level: {selectedRule.level}
                  </Badge>
                )}
                {selectedRule.status && (
                  <Badge variant="outline">Status: {selectedRule.status}</Badge>
                )}
                {selectedRule.ruleset_name && (
                  <Badge variant="outline">Ruleset: {selectedRule.ruleset_name}</Badge>
                )}
                {selectedRule.source?.includes('github.com') && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => window.open(selectedRule.source, '_blank')}
                  >
                    <Github className="h-4 w-4 mr-2" />
                    View on GitHub
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="outline"
                  onClick={copyToClipboard}
                  disabled={!ruleContent || loading}
                >
                  {copied ? (
                    <>
                      <Check className="h-4 w-4 mr-2" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="h-4 w-4 mr-2" />
                      Copy Rule
                    </>
                  )}
                </Button>
              </div>
            )}

            {/* Rule Content */}
            <ScrollArea className="h-[400px] w-full rounded-lg border">
              {loading ? (
                <div className="flex items-center justify-center h-full">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : error ? (
                <Alert className="m-4">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              ) : (
                <pre className="p-4 text-sm">
                  <code className="language-sigma">{ruleContent}</code>
                </pre>
              )}
            </ScrollArea>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}