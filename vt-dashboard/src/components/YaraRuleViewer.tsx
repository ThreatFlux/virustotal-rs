import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { ExternalLink, Code, Github, AlertTriangle, Copy, Check, Loader2 } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import Prism from 'prismjs';
import 'prismjs/themes/prism-tomorrow.css';

// Define YARA syntax for PrismJS
if (typeof Prism !== 'undefined' && !Prism.languages.yara) {
  Prism.languages.yara = {
    'comment': [
      {
        pattern: /\/\*[\s\S]*?\*\//,
        greedy: true
      },
      {
        pattern: /\/\/.*/,
        greedy: true
      }
    ],
    'string': {
      pattern: /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/,
      greedy: true
    },
    'hex-string': {
      pattern: /\{[0-9A-Fa-f\s\?\[\]\(\)\|]+\}/,
      greedy: true,
      alias: 'string'
    },
    'regex': {
      pattern: /\/(?:[^\/\\\n]|\\.)+\/[ismx]*/,
      greedy: true
    },
    'keyword': /\b(?:rule|meta|strings|condition|import|include|global|private|and|or|not|any|all|of|them|for|in|entrypoint|filesize|matches|contains|startswith|endswith|at|int8|int16|int32|uint8|uint16|uint32|int8be|int16be|int32be|uint8be|uint16be|uint32be)\b/,
    'boolean': /\b(?:true|false)\b/,
    'number': /\b0x[0-9A-Fa-f]+\b|\b\d+\b/,
    'variable': /\$[a-zA-Z_][a-zA-Z0-9_]*/,
    'operator': /[=<>!]=?|[+\-*\/%]|<<|>>|&|\||\^|~/,
    'punctuation': /[{}[\];(),.:]/
  };
}

interface YaraRule {
  rule_name: string;
  author?: string;
  description?: string;
  source?: string;
  ruleset_name?: string;
  ruleset_id?: string;
}

interface YaraRuleViewerProps {
  rules: YaraRule[];
  fileHash: string;
}

export function YaraRuleViewer({ rules, fileHash }: YaraRuleViewerProps) {
  const [selectedRule, setSelectedRule] = useState<YaraRule | null>(null);
  const [ruleContent, setRuleContent] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);

  // Group rules by source
  const rulesBySource = rules.reduce((acc: Record<string, YaraRule[]>, rule) => {
    const source = rule.source || 'Unknown Source';
    if (!acc[source]) acc[source] = [];
    acc[source].push(rule);
    return acc;
  }, {});

  // Determine risk level based on rule name and description
  const getRiskLevel = (rule: YaraRule) => {
    const name = rule.rule_name?.toLowerCase() || '';
    const desc = rule.description?.toLowerCase() || '';
    
    if (name.includes('malware') || name.includes('trojan') || name.includes('virus') || 
        name.includes('backdoor') || name.includes('ransomware') || name.includes('rat') ||
        desc.includes('malicious') || desc.includes('malware')) {
      return 'high';
    }
    if (name.includes('suspicious') || name.includes('indicator') || name.includes('heuristic') ||
        desc.includes('suspicious') || desc.includes('potentially')) {
      return 'medium';
    }
    return 'low';
  };

  const fetchRuleFromGitHub = async (rule: YaraRule) => {
    setLoading(true);
    setError(null);
    setRuleContent('');

    try {
      // Parse GitHub URL to get owner, repo, and potential path
      if (rule.source?.includes('github.com')) {
        const urlParts = rule.source.replace('https://github.com/', '').split('/');
        const owner = urlParts[0];
        const repo = urlParts[1];
        
        // Try to fetch the rule content
        // First, try to find the rule in common locations
        const possiblePaths = [
          `rules/${rule.ruleset_name}.yar`,
          `rules/${rule.ruleset_name}.yara`,
          `yara/${rule.ruleset_name}.yar`,
          `yara/${rule.ruleset_name}.yara`,
          `${rule.ruleset_name}.yar`,
          `${rule.ruleset_name}.yara`,
          `rules/${rule.rule_name}.yar`,
          `rules/${rule.rule_name}.yara`,
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
          // Try to extract just the specific rule if multiple rules in file
          const rulePattern = new RegExp(`rule\\s+${rule.rule_name}\\s*\\{[^}]*\\}`, 'gs');
          const match = content.match(rulePattern);
          if (match) {
            setRuleContent(match[0]);
          } else {
            // If we can't find the specific rule, show the whole file
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

  const generatePlaceholderRule = (rule: YaraRule) => {
    return `/*
 * Rule: ${rule.rule_name}
 * Author: ${rule.author || 'Unknown'}
 * Source: ${rule.source || 'Unknown'}
 * Description: ${rule.description || 'No description available'}
 * 
 * Note: Unable to fetch actual rule content from source.
 * This is a placeholder representation.
 */

rule ${rule.rule_name}
{
    meta:
        author = "${rule.author || 'Unknown'}"
        description = "${rule.description || 'No description'}"
        source = "${rule.source || 'Unknown'}"
        
    condition:
        /* Rule conditions not available */
        any of them
}`;
  };

  const handleViewRule = (rule: YaraRule) => {
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
            <Code className="h-5 w-5 text-purple-600" />
            YARA Rule Detections
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
                          <div className="flex gap-2">
                            {risk === 'high' && (
                              <Badge variant="destructive" className="text-xs">HIGH</Badge>
                            )}
                            {risk === 'medium' && (
                              <Badge variant="outline" className="text-xs border-yellow-600 text-yellow-600">MEDIUM</Badge>
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
                      </div>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleViewRule(rule)}
                        className="sm:ml-2 self-start sm:self-auto"
                      >
                        <ExternalLink className="h-4 w-4" />
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
                High-risk YARA rules detected. This file matches patterns commonly associated with malicious behavior.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Rule Viewer Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="w-[95vw] max-w-4xl max-h-[90vh] sm:max-h-[80vh] overflow-hidden">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Code className="h-5 w-5 text-purple-600" />
              {selectedRule?.rule_name}
            </DialogTitle>
            <DialogDescription>
              {selectedRule?.description || 'YARA rule details'}
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4 overflow-hidden">
            {/* Rule Metadata */}
            {selectedRule && (
              <div className="flex flex-wrap gap-2">
                {selectedRule.author && (
                  <Badge variant="outline">Author: {selectedRule.author}</Badge>
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
            <div className="h-[600px] w-full rounded-lg border bg-muted/50 overflow-auto">
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
                <pre className="p-4 text-sm overflow-x-auto" style={{ margin: 0 }}>
                  <code className="language-yara" style={{ whiteSpace: 'pre' }}>{ruleContent}</code>
                </pre>
              )}
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}