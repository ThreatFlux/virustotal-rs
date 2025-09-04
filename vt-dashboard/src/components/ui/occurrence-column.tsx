import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from '@/components/ui/dropdown-menu';
import type { Report, OccurrenceData, OccurrenceSearchContext } from '@/types';
import { calculateOccurrenceData, getOccurrenceDescription, getOccurrencePriority } from '@/services/occurrence';
import {
  Search,
  Users,
  Shield,
  FileText,
  Clock,
  TrendingUp,
  ChevronDown,
  Loader2,
  AlertTriangle,
} from 'lucide-react';

interface OccurrenceColumnProps {
  report: Report;
  variant?: 'compact' | 'full';
  showTooltip?: boolean;
  onSearchTrigger?: (context: OccurrenceSearchContext) => void;
}

export function OccurrenceColumn({ 
  report, 
  variant = 'full', 
  showTooltip = true,
  onSearchTrigger 
}: OccurrenceColumnProps) {
  const [occurrenceData, setOccurrenceData] = useState<OccurrenceData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const loadOccurrenceData = async () => {
      setIsLoading(true);
      setError(null);
      
      try {
        const data = await calculateOccurrenceData(report);
        setOccurrenceData(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load occurrence data');
        console.error('Error loading occurrence data:', err);
      } finally {
        setIsLoading(false);
      }
    };

    loadOccurrenceData();
  }, [report.file_hash, report.report_uuid]);

  const handleSearchClick = (searchType: OccurrenceSearchContext['search_type'], metadata: { display_name: string; search_description: string }) => {
    if (!occurrenceData) return;

    const context: OccurrenceSearchContext = {
      search_type: searchType,
      base_hash: report.file_hash,
      base_name: report.meaningful_name,
      filters: {
        similarity_threshold: 0.7,
        time_range: {
          start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0], // 30 days ago
          end: new Date().toISOString().split('T')[0],
        },
        include_suspicious: true,
        min_detections: 1,
      },
      metadata,
    };

    if (onSearchTrigger) {
      onSearchTrigger(context);
    } else {
      // Navigate to search page with encoded context
      const searchParams = new URLSearchParams();
      searchParams.set('occurrence_search', encodeURIComponent(JSON.stringify(context)));
      navigate(`/search?${searchParams.toString()}`);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center w-20 h-6">
        <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error || !occurrenceData) {
    return (
      <div className="flex items-center justify-center w-20 h-6">
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger>
              <AlertTriangle className="h-3 w-3 text-muted-foreground" />
            </TooltipTrigger>
            <TooltipContent>
              <p className="text-xs">Failed to load occurrence data</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>
    );
  }

  const priority = getOccurrencePriority(occurrenceData);
  const description = getOccurrenceDescription(occurrenceData);
  
  // Determine the most important occurrence indicator to show
  const getMainIndicator = () => {
    if (occurrenceData.related_campaigns.length > 0) {
      return {
        type: 'campaigns',
        value: occurrenceData.related_campaigns.length,
        icon: <Shield className="h-3 w-3" />,
        color: 'bg-red-100 text-red-800 hover:bg-red-200',
        label: `${occurrenceData.related_campaigns.length} campaign(s)`,
      };
    }
    
    if (occurrenceData.yara_matches > 0 || occurrenceData.sigma_matches > 0) {
      const total = occurrenceData.yara_matches + occurrenceData.sigma_matches;
      return {
        type: 'rules',
        value: total,
        icon: <FileText className="h-3 w-3" />,
        color: 'bg-orange-100 text-orange-800 hover:bg-orange-200',
        label: `${total} rule match(es)`,
      };
    }
    
    if (occurrenceData.similar_files_count > 1) {
      return {
        type: 'similar',
        value: occurrenceData.similar_files_count,
        icon: <Users className="h-3 w-3" />,
        color: 'bg-blue-100 text-blue-800 hover:bg-blue-200',
        label: `${occurrenceData.similar_files_count} similar file(s)`,
      };
    }
    
    if (occurrenceData.times_submitted > 1) {
      return {
        type: 'submissions',
        value: occurrenceData.times_submitted,
        icon: <TrendingUp className="h-3 w-3" />,
        color: 'bg-green-100 text-green-800 hover:bg-green-200',
        label: `${occurrenceData.times_submitted} submission(s)`,
      };
    }

    return {
      type: 'none',
      value: 0,
      icon: <Clock className="h-3 w-3" />,
      color: 'bg-gray-100 text-gray-600',
      label: 'First seen',
    };
  };

  const mainIndicator = getMainIndicator();

  if (variant === 'compact') {
    const CompactContent = (
      <Button
        variant="ghost"
        size="sm"
        className={`h-6 px-2 text-xs ${mainIndicator.color}`}
        onClick={() => {
          if (mainIndicator.type === 'campaigns') {
            handleSearchClick('campaign_related', {
              display_name: 'Campaign Related Files',
              search_description: `Files related to campaigns: ${occurrenceData.related_campaigns.join(', ')}`,
            });
          } else if (mainIndicator.type === 'rules') {
            handleSearchClick('yara_matches', {
              display_name: 'YARA/Sigma Matches',
              search_description: `Files matching similar detection rules`,
            });
          } else if (mainIndicator.type === 'similar') {
            handleSearchClick('similar_files', {
              display_name: 'Similar Files',
              search_description: `Files similar to ${report.meaningful_name || report.file_hash}`,
            });
          }
        }}
      >
        {mainIndicator.icon}
        <span className="ml-1">{mainIndicator.value || '0'}</span>
      </Button>
    );

    if (showTooltip) {
      return (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              {CompactContent}
            </TooltipTrigger>
            <TooltipContent className="max-w-xs">
              <div className="space-y-1">
                <p className="font-semibold text-xs">{mainIndicator.label}</p>
                <p className="text-xs text-muted-foreground">{description}</p>
                <p className="text-xs text-blue-600">Click to search for similar files</p>
              </div>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      );
    }

    return CompactContent;
  }

  // Full variant with dropdown menu
  return (
    <div className="flex items-center space-x-1">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className={`h-6 px-2 text-xs ${mainIndicator.color}`}
          >
            {mainIndicator.icon}
            <span className="ml-1">{mainIndicator.value || '0'}</span>
            <ChevronDown className="h-3 w-3 ml-1" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent className="w-64" align="end">
          <DropdownMenuLabel className="text-xs">
            Occurrence Data for {report.meaningful_name || 'File'}
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          
          {occurrenceData.similar_files_count > 0 && (
            <DropdownMenuItem
              onClick={() => handleSearchClick('similar_files', {
                display_name: 'Similar Files',
                search_description: `Files similar to ${report.meaningful_name || report.file_hash}`,
              })}
              className="cursor-pointer"
            >
              <Users className="h-4 w-4 mr-2" />
              <div className="flex-1">
                <div className="text-sm">Similar Files</div>
                <div className="text-xs text-muted-foreground">{occurrenceData.similar_files_count} files found</div>
              </div>
            </DropdownMenuItem>
          )}

          {(occurrenceData.yara_matches > 0 || occurrenceData.sigma_matches > 0) && (
            <DropdownMenuItem
              onClick={() => handleSearchClick('yara_matches', {
                display_name: 'Rule Matches',
                search_description: `Files with similar YARA/Sigma rule matches`,
              })}
              className="cursor-pointer"
            >
              <FileText className="h-4 w-4 mr-2" />
              <div className="flex-1">
                <div className="text-sm">Rule Matches</div>
                <div className="text-xs text-muted-foreground">
                  {occurrenceData.yara_matches} YARA, {occurrenceData.sigma_matches} Sigma
                </div>
              </div>
            </DropdownMenuItem>
          )}

          {occurrenceData.related_campaigns.length > 0 && (
            <DropdownMenuItem
              onClick={() => handleSearchClick('campaign_related', {
                display_name: 'Campaign Related',
                search_description: `Files from campaigns: ${occurrenceData.related_campaigns.join(', ')}`,
              })}
              className="cursor-pointer"
            >
              <Shield className="h-4 w-4 mr-2" />
              <div className="flex-1">
                <div className="text-sm">Campaign Related</div>
                <div className="text-xs text-muted-foreground">
                  {occurrenceData.related_campaigns.length} campaign(s)
                </div>
              </div>
            </DropdownMenuItem>
          )}

          {occurrenceData.sandbox_analyses > 0 && (
            <DropdownMenuItem
              onClick={() => handleSearchClick('behavioral_similarity', {
                display_name: 'Behavioral Similarity',
                search_description: `Files with similar sandbox behaviors`,
              })}
              className="cursor-pointer"
            >
              <Search className="h-4 w-4 mr-2" />
              <div className="flex-1">
                <div className="text-sm">Similar Behavior</div>
                <div className="text-xs text-muted-foreground">{occurrenceData.sandbox_analyses} analyses</div>
              </div>
            </DropdownMenuItem>
          )}

          <DropdownMenuSeparator />
          
          <DropdownMenuItem disabled>
            <Clock className="h-4 w-4 mr-2" />
            <div className="flex-1">
              <div className="text-sm">Submitted {occurrenceData.times_submitted} times</div>
              <div className="text-xs text-muted-foreground">
                First: {new Date(occurrenceData.first_seen).toLocaleDateString()}
              </div>
            </div>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      {priority > 50 && (
        <Badge variant="secondary" className="h-4 text-xs px-1">
          High
        </Badge>
      )}
    </div>
  );
}

export default OccurrenceColumn;