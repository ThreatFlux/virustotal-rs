import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from '@/components/ui/table';
import { OccurrenceColumn } from '@/components/ui/occurrence-column';
import { formatDate, formatBytes, truncateHash, getVerdictBadgeVariant } from '@/lib/utils';
import { Report, OccurrenceSearchContext } from '@/types';
import { ExternalLink, FileText } from 'lucide-react';

interface RecentReportsProps {
  reports: Report[];
  isLoading?: boolean;
}

function getOverallVerdict(report: Report): string {
  const stats = report.last_analysis_stats;
  if (!stats) return 'unknown';
  
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  
  if (malicious > 0) return 'malicious';
  if (suspicious > 0) return 'suspicious';
  if (harmless > 0) return 'clean';
  if (undetected > 0) return 'undetected';
  
  return 'unknown';
}

export function RecentReports({ reports, isLoading = false }: RecentReportsProps) {
  const navigate = useNavigate();

  const handleOccurrenceSearch = (context: OccurrenceSearchContext) => {
    // Navigate to search page with occurrence context
    const searchParams = new URLSearchParams();
    searchParams.set('occurrence_search', encodeURIComponent(JSON.stringify(context)));
    navigate(`/search?${searchParams.toString()}`);
  };
  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <FileText className="h-5 w-5" />
            <span>Recent Reports</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center space-x-4">
                <div className="h-4 w-16 bg-muted animate-pulse rounded" />
                <div className="h-4 w-32 bg-muted animate-pulse rounded" />
                <div className="h-4 w-20 bg-muted animate-pulse rounded" />
                <div className="h-4 w-16 bg-muted animate-pulse rounded" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center space-x-2">
          <FileText className="h-5 w-5" />
          <span>Recent Reports</span>
        </CardTitle>
        <Button variant="outline" size="sm" asChild>
          <Link to="/reports">
            View All
            <ExternalLink className="ml-1 h-3 w-3" />
          </Link>
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-80">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-32">Hash</TableHead>
                <TableHead>File Name</TableHead>
                <TableHead className="w-20">Size</TableHead>
                <TableHead className="w-24">Verdict</TableHead>
                <TableHead className="w-24">Occurrence</TableHead>
                <TableHead className="w-32">Date</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {reports.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                    No reports found
                  </TableCell>
                </TableRow>
              ) : (
                reports.slice(0, 10).map((report) => {
                  const verdict = getOverallVerdict(report);
                  
                  return (
                    <TableRow key={report.report_uuid} className="hover:bg-muted/50">
                      <TableCell className="font-mono text-sm">
                        <Link 
                          to={`/reports/${report.report_uuid}`}
                          className="text-primary hover:underline"
                        >
                          {truncateHash(report.file_hash || report.sha256 || '', 12)}
                        </Link>
                      </TableCell>
                      <TableCell>
                        <div className="max-w-40 truncate">
                          {report.meaningful_name || report.names?.[0] || 'Unknown'}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {report.size ? formatBytes(report.size) : 'N/A'}
                      </TableCell>
                      <TableCell>
                        <Badge 
                          variant={getVerdictBadgeVariant(verdict)}
                          className="text-xs"
                        >
                          {verdict}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <OccurrenceColumn
                          report={report}
                          variant="compact"
                          onSearchTrigger={handleOccurrenceSearch}
                        />
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDate(report.index_time)}
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}