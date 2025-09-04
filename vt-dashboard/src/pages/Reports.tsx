import React, { useEffect, useState } from 'react';
import { Link, useSearchParams, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { OccurrenceColumn } from '@/components/ui/occurrence-column';
import { fetchReports, searchReports } from '@/services/elasticsearch';
import { Report, SearchFilters, OccurrenceSearchContext } from '@/types';
import { formatDate, formatBytes, truncateHash, getVerdictBadgeVariant } from '@/lib/utils';
import {
  FileText,
  Search,
  ChevronLeft,
  ChevronRight,
  Filter,
  X,
  FileSpreadsheet,
  Presentation,
  AlertTriangle,
  LayoutGrid,
  List,
  Calendar,
  HardDrive,
  FileType,
  Shield,
  Hash,
  Clock,
} from 'lucide-react';

function getOverallVerdict(report: Report): string {
  const { malicious = 0, suspicious = 0, harmless = 0, undetected = 0 } = report;
  
  if (malicious > 0) return 'malicious';
  if (suspicious > 0) return 'suspicious';
  if (harmless > 0) return 'clean';
  if (undetected > 0) return 'undetected';
  
  return 'unknown';
}

function getEmailInfo(report: Report) {
  // Check if this is an email file
  if (report.type_tag === 'outlook' || report.type_tag === 'eml' || 
      report.type_description?.toLowerCase().includes('outlook') ||
      report.type_description?.toLowerCase().includes('email')) {
    return {
      type: 'email',
      icon: '📧',
      color: 'text-indigo-600',
      hasAttachments: report.office_info ? true : false
    };
  }
  return null;
}

function getImageInfo(report: Report) {
  // Check if this is an image file
  const imageTypes = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'ico'];
  if (imageTypes.includes(report.type_tag || '')) {
    return {
      type: report.type_tag,
      icon: '🖼️',
      color: 'text-purple-600',
      hasExif: report.exiftool ? true : false
    };
  }
  return null;
}

function getPEInfo(report: Report) {
  // Check if this is a PE file (Windows executable/DLL)
  if (['peexe', 'pedll', 'pe'].includes(report.type_tag || '') ||
      report.type_description?.includes('Win32') ||
      report.type_description?.includes('PE32')) {
    return {
      type: 'pe',
      icon: '⚙️',
      color: 'text-red-600',
      hasPEInfo: report.pe_info ? true : false
    };
  }
  return null;
}

function getOfficeInfo(report: Report) {
  // Check for Office Open XML formats first (modern formats)
  if (['xlsx', 'docx', 'pptx'].includes(report.type_tag || '')) {
    const type = report.type_tag === 'xlsx' ? 'excel' : 
                 report.type_tag === 'docx' ? 'word' : 'powerpoint';
    
    return {
      type,
      isOpenXML: true,
      hasMacros: false, // Open XML files typically don't have traditional macros
      hasSecurity: false,
      icon: type === 'excel' ? '📊' : type === 'word' ? '📄' : '📊',
      color: type === 'excel' ? 'text-green-600' : 
             type === 'word' ? 'text-blue-600' : 'text-orange-600'
    };
  }
  
  if (!report.office_info) return null;
  
  // Determine document type from CLSID or other indicators (legacy formats)
  const rootEntry = report.office_info.entries?.find((entry: any) => entry.name === 'Root Entry');
  const clsid = rootEntry?.clsid_literal;
  
  let type = 'office';
  let icon = <FileText className="h-3 w-3" />;
  let color = 'text-blue-500';
  
  if (clsid?.includes('PowerPoint') || report.office_info.document_summary_info?.slide_count !== undefined) {
    type = 'powerpoint';
    icon = <Presentation className="h-3 w-3" />;
    color = 'text-orange-500';
  } else if (clsid?.includes('Excel') || report.office_info.entries?.some((e: any) => e.name === 'Workbook')) {
    type = 'excel';
    icon = <FileSpreadsheet className="h-3 w-3" />;
    color = 'text-green-500';
  } else if (clsid?.includes('Word') || report.office_info.entries?.some((e: any) => e.name?.includes('Word'))) {
    type = 'word';
    icon = <FileText className="h-3 w-3" />;
    color = 'text-blue-500';
  }
  
  // Check for security concerns
  const hasSecurity = (
    (report.office_info.macros && report.office_info.macros.length > 0) ||
    report.office_info.entries?.some((entry: any) => 
      entry.name?.includes('VBA') || 
      entry.name?.includes('Macro') ||
      entry.clsid_literal?.includes('VBA')
    )
  );
  
  return { type, icon, color, hasSecurity };
}

export function Reports() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const [reports, setReports] = useState<Report[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [fileTypeFilter, setFileTypeFilter] = useState<string>('all');
  const [verdictFilter, setVerdictFilter] = useState<string>('all');
  const [viewMode, setViewMode] = useState<'compact' | 'comfortable'>('comfortable');

  const perPage = 50;

  useEffect(() => {
    const page = parseInt(searchParams.get('page') || '1');
    const query = searchParams.get('q') || '';
    const fileType = searchParams.get('type') || 'all';
    const verdict = searchParams.get('verdict') || 'all';

    setCurrentPage(page);
    setSearchQuery(query);
    setFileTypeFilter(fileType);
    setVerdictFilter(verdict);

    loadReports(page, query, fileType, verdict);
  }, [searchParams]);

  const loadReports = async (
    page: number,
    query: string = '',
    fileType: string = 'all',
    verdict: string = 'all'
  ) => {
    setIsLoading(true);
    setError(null);

    try {
      let response;
      
      if (query || fileType !== 'all' || verdict !== 'all') {
        // Build filters for search
        const filters: SearchFilters = {};
        
        if (query) {
          filters.search_query = query;
        }
        
        if (fileType !== 'all') {
          filters.file_type = [fileType];
        }
        
        if (verdict !== 'all') {
          filters.verdict = [verdict];
        }

        response = await searchReports(filters, page, perPage);
      } else {
        response = await fetchReports(page, perPage);
      }

      if (response.success && response.data) {
        setReports(response.data.reports);
        setTotal(response.data.total);
        setTotalPages(response.data.total_pages);
      } else {
        setError(response.error || 'Failed to load reports');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load reports');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSearch = () => {
    const params = new URLSearchParams();
    params.set('page', '1');
    
    if (searchQuery) params.set('q', searchQuery);
    if (fileTypeFilter !== 'all') params.set('type', fileTypeFilter);
    if (verdictFilter !== 'all') params.set('verdict', verdictFilter);
    
    setSearchParams(params);
  };

  const handleClearFilters = () => {
    setSearchQuery('');
    setFileTypeFilter('all');
    setVerdictFilter('all');
    setSearchParams(new URLSearchParams());
  };

  const handlePageChange = (page: number) => {
    const params = new URLSearchParams(searchParams);
    params.set('page', page.toString());
    setSearchParams(params);
  };

  const handleOccurrenceSearch = (context: OccurrenceSearchContext) => {
    // Navigate to search page with occurrence context
    const searchParams = new URLSearchParams();
    searchParams.set('occurrence_search', encodeURIComponent(JSON.stringify(context)));
    navigate(`/search?${searchParams.toString()}`);
  };

  const hasFilters = searchQuery || fileTypeFilter !== 'all' || verdictFilter !== 'all';

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-foreground">Reports</h1>
        <p className="text-muted-foreground mt-1">
          Browse and search VirusTotal analysis reports
        </p>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Filter className="h-5 w-5" />
            <span>Filters</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Search</label>
              <div className="flex space-x-2">
                <Input
                  placeholder="Hash, filename, or file type..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      handleSearch();
                    }
                  }}
                />
                <Button onClick={handleSearch} size="icon">
                  <Search className="h-4 w-4" />
                </Button>
              </div>
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">File Type</label>
              <Select value={fileTypeFilter} onValueChange={setFileTypeFilter}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Types</SelectItem>
                  <SelectItem value="PE32">PE32 Executable</SelectItem>
                  <SelectItem value="PDF">PDF Document</SelectItem>
                  <SelectItem value="ZIP">ZIP Archive</SelectItem>
                  <SelectItem value="DOC">Word Document</SelectItem>
                  <SelectItem value="XLS">Excel Spreadsheet</SelectItem>
                  <SelectItem value="PPT">PowerPoint</SelectItem>
                  <SelectItem value="JS">JavaScript</SelectItem>
                  <SelectItem value="HTML">HTML Document</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Verdict</label>
              <Select value={verdictFilter} onValueChange={setVerdictFilter}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Verdicts</SelectItem>
                  <SelectItem value="malicious">Malicious</SelectItem>
                  <SelectItem value="suspicious">Suspicious</SelectItem>
                  <SelectItem value="clean">Clean</SelectItem>
                  <SelectItem value="undetected">Undetected</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Actions</label>
              <div className="flex space-x-2">
                <Button onClick={handleSearch} className="flex-1">
                  Apply Filters
                </Button>
                {hasFilters && (
                  <Button variant="outline" size="icon" onClick={handleClearFilters}>
                    <X className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <FileText className="h-5 w-5" />
              <span>Analysis Reports</span>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-sm text-muted-foreground">
                {isLoading ? 'Loading...' : `${total.toLocaleString()} total reports`}
              </div>
              <div className="flex items-center gap-1 border rounded-md p-1">
                <Button
                  variant={viewMode === 'comfortable' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setViewMode('comfortable')}
                  className="h-7 px-2"
                >
                  <LayoutGrid className="h-4 w-4 mr-1" />
                  Comfortable
                </Button>
                <Button
                  variant={viewMode === 'compact' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setViewMode('compact')}
                  className="h-7 px-2"
                >
                  <List className="h-4 w-4 mr-1" />
                  Compact
                </Button>
              </div>
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {error ? (
            <div className="p-6 text-center text-destructive">
              <p>Error: {error}</p>
              <Button variant="outline" onClick={() => loadReports(currentPage)} className="mt-2">
                Retry
              </Button>
            </div>
          ) : (
            <>
              {/* Desktop View - Comfortable or Compact based on selection */}
              <div className="hidden lg:block">
                {viewMode === 'compact' ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-40">SHA256</TableHead>
                    <TableHead>File Name</TableHead>
                    <TableHead className="w-20">Type</TableHead>
                    <TableHead className="w-20">Size</TableHead>
                    <TableHead className="w-24">Verdict</TableHead>
                    <TableHead className="w-20">Detections</TableHead>
                    <TableHead className="w-28">Occurrence</TableHead>
                    <TableHead className="w-32">Date</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {isLoading ? (
                    Array.from({ length: 10 }).map((_, i) => (
                      <TableRow key={i}>
                        <TableCell><div className="h-4 bg-muted animate-pulse rounded" /></TableCell>
                        <TableCell><div className="h-4 bg-muted animate-pulse rounded" /></TableCell>
                        <TableCell><div className="h-4 bg-muted animate-pulse rounded" /></TableCell>
                        <TableCell><div className="h-4 bg-muted animate-pulse rounded" /></TableCell>
                        <TableCell><div className="h-4 bg-muted animate-pulse rounded" /></TableCell>
                        <TableCell><div className="h-4 bg-muted animate-pulse rounded" /></TableCell>
                        <TableCell><div className="h-4 bg-muted animate-pulse rounded" /></TableCell>
                        <TableCell><div className="h-4 bg-muted animate-pulse rounded" /></TableCell>
                      </TableRow>
                    ))
                  ) : reports.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center text-muted-foreground py-8">
                        No reports found
                      </TableCell>
                    </TableRow>
                  ) : (
                    reports.map((report) => {
                      const verdict = getOverallVerdict(report);
                      const stats = report.last_analysis_stats || {};
                      const detections = (stats.malicious || 0) + (stats.suspicious || 0);
                      const totalScans = (stats.malicious || 0) + (stats.suspicious || 0) + 
                                       (stats.harmless || 0) + (stats.undetected || 0);
                      
                      return (
                        <TableRow key={report.report_uuid} className="hover:bg-muted/50">
                          <TableCell className="font-mono text-sm">
                            <Link 
                              to={`/reports/${report.report_uuid}`}
                              className="text-primary hover:underline"
                            >
                              {truncateHash(report.file_hash || report.sha256, 16)}
                            </Link>
                          </TableCell>
                          <TableCell>
                            <div className="max-w-60 truncate">
                              {report.meaningful_name || report.names?.[0] || 'Unknown'}
                            </div>
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            <div className="flex items-center gap-1">
                              {(() => {
                                // Check for PE files
                                const peInfo = getPEInfo(report);
                                if (peInfo) {
                                  return (
                                    <div className="flex items-center gap-1">
                                      <span className={peInfo.color}>{peInfo.icon}</span>
                                      {peInfo.hasPEInfo && (
                                        <Badge variant="destructive" className="text-xs h-4 px-1">PE</Badge>
                                      )}
                                    </div>
                                  );
                                }
                                
                                // Check for Email files
                                const emailInfo = getEmailInfo(report);
                                if (emailInfo) {
                                  return (
                                    <div className="flex items-center gap-1">
                                      <span className={emailInfo.color}>{emailInfo.icon}</span>
                                      {emailInfo.hasAttachments && (
                                        <Badge variant="outline" className="text-xs h-4 px-1">📎</Badge>
                                      )}
                                    </div>
                                  );
                                }
                                
                                // Check for Image files
                                const imageInfo = getImageInfo(report);
                                if (imageInfo) {
                                  return (
                                    <div className="flex items-center gap-1">
                                      <span className={imageInfo.color}>{imageInfo.icon}</span>
                                      {imageInfo.hasExif && (
                                        <Badge variant="outline" className="text-xs h-4 px-1">EXIF</Badge>
                                      )}
                                    </div>
                                  );
                                }
                                
                                // Check for Office files
                                const officeInfo = getOfficeInfo(report);
                                if (officeInfo) {
                                  return (
                                    <div className="flex items-center gap-1">
                                      <span className={officeInfo.color}>{officeInfo.icon}</span>
                                      {officeInfo.isOpenXML && (
                                        <Badge variant="outline" className="text-xs h-4 px-1">XML</Badge>
                                      )}
                                      {officeInfo.hasSecurity && (
                                        <AlertTriangle className="h-3 w-3 text-red-500" />
                                      )}
                                    </div>
                                  );
                                }
                                return null;
                              })()}
                              <span>{report.type_tag || report.type_description || 'N/A'}</span>
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
                          <TableCell className="text-sm">
                            {detections}/{totalScans}
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
                ) : (
                  /* Comfortable View - Simplified Cards */
                  <div className="p-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-3">
                      {isLoading ? (
                        Array.from({ length: 10 }).map((_, i) => (
                          <div key={i} className="border rounded-lg p-4">
                            <div className="h-32 bg-muted animate-pulse rounded" />
                          </div>
                        ))
                      ) : reports.length === 0 ? (
                        <div className="col-span-2 text-center text-muted-foreground py-8">
                          No reports found
                        </div>
                      ) : (
                        reports.map((report) => {
                          const verdict = getOverallVerdict(report);
                          const stats = report.last_analysis_stats || {};
                          const detections = (stats.malicious || 0) + (stats.suspicious || 0);
                          const totalScans = (stats.malicious || 0) + (stats.suspicious || 0) + 
                                           (stats.harmless || 0) + (stats.undetected || 0);
                          
                          // Check for rule matches and special indicators
                          const hasYaraMatch = report.crowdsourced_yara_results?.length > 0;
                          const hasSigmaMatch = report.crowdsourced_sigma_results?.length > 0;
                          const hasMacros = getOfficeInfo(report)?.hasSecurity;
                          const isPE = getPEInfo(report)?.hasPEInfo;
                          
                          return (
                            <Link
                              key={report.report_uuid}
                              to={`/reports/${report.report_uuid}`}
                              className="block"
                            >
                              <Card className="hover:shadow-md transition-all cursor-pointer border-l-4"
                                style={{
                                  borderLeftColor: detections > 10 ? '#ef4444' : 
                                                  detections > 0 ? '#f97316' : 
                                                  '#22c55e'
                                }}>
                                <CardContent className="p-4 space-y-2">
                                  {/* Line 1: File Name and Detection Ratio */}
                                  <div className="flex items-start justify-between gap-2">
                                    <h3 className="font-medium text-sm leading-tight break-all flex-1">
                                      {report.meaningful_name || report.names?.[0] || 'Unknown File'}
                                    </h3>
                                    <div className="flex items-center gap-2">
                                      {/* Special Indicators */}
                                      <div className="flex items-center gap-1">
                                        {hasYaraMatch && (
                                          <span className="text-purple-600 font-bold" title="YARA rules matched">Y</span>
                                        )}
                                        {hasSigmaMatch && (
                                          <span className="text-blue-600 font-bold" title="Sigma rules matched">Σ</span>
                                        )}
                                        {hasMacros && (
                                          <span className="text-red-600" title="Contains macros">⚠</span>
                                        )}
                                        {isPE && (
                                          <span className="text-orange-600 font-bold" title="PE executable">PE</span>
                                        )}
                                      </div>
                                      {/* Detection Ratio */}
                                      <div className="text-sm font-bold whitespace-nowrap">
                                        <span className={detections > 0 ? 'text-red-600' : 'text-green-600'}>
                                          {detections}
                                        </span>
                                        <span className="text-muted-foreground">/</span>
                                        <span className="text-foreground">{totalScans}</span>
                                      </div>
                                    </div>
                                  </div>

                                  {/* Line 2: Full Hash */}
                                  <div className="font-mono text-xs text-muted-foreground break-all">
                                    {report.sha256 || report.file_hash}
                                  </div>

                                  {/* Line 3: Type Icon, Type, Size, First Seen, Last Seen */}
                                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                                    <div className="flex items-center gap-2">
                                      {/* File Type Icon */}
                                      {(() => {
                                        const peInfo = getPEInfo(report);
                                        if (peInfo) {
                                          return <span className={peInfo.color}>{peInfo.icon}</span>;
                                        }
                                        
                                        const emailInfo = getEmailInfo(report);
                                        if (emailInfo) {
                                          return <span className={emailInfo.color}>{emailInfo.icon}</span>;
                                        }
                                        
                                        const imageInfo = getImageInfo(report);
                                        if (imageInfo) {
                                          return <span className={imageInfo.color}>{imageInfo.icon}</span>;
                                        }
                                        
                                        const officeInfo = getOfficeInfo(report);
                                        if (officeInfo) {
                                          return <span className={officeInfo.color}>{officeInfo.icon}</span>;
                                        }
                                        
                                        // Default file icon
                                        return <FileText className="h-3 w-3 text-muted-foreground" />;
                                      })()}
                                      <span>{report.type_tag || 'unknown'}</span>
                                      <span>•</span>
                                      <span>{report.size ? formatBytes(report.size) : 'N/A'}</span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                      <span title="First seen">{report.first_submission_date ? formatDate(report.first_submission_date).split(',')[0] : 'New'}</span>
                                      <span>→</span>
                                      <span title="Last seen">{report.last_submission_date ? formatDate(report.last_submission_date).split(',')[0] : formatDate(report.index_time).split(',')[0]}</span>
                                    </div>
                                  </div>

                                  {/* Line 4: Verdict Badge if malicious/suspicious */}
                                  {(verdict === 'malicious' || verdict === 'suspicious') && (
                                    <div className="flex items-center gap-2">
                                      <Badge 
                                        variant={getVerdictBadgeVariant(verdict)}
                                        className="text-xs"
                                      >
                                        {verdict}
                                      </Badge>
                                      {stats.malicious > 0 && (
                                        <span className="text-xs text-red-600">
                                          {stats.malicious} malicious detection{stats.malicious > 1 ? 's' : ''}
                                        </span>
                                      )}
                                    </div>
                                  )}
                                </CardContent>
                              </Card>
                            </Link>
                          );
                        })
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Mobile/Tablet View - Use same Comfortable cards */}
              <div className="lg:hidden">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4">
                  {isLoading ? (
                    Array.from({ length: 10 }).map((_, i) => (
                      <div key={i} className="border rounded-lg p-4">
                        <div className="h-32 bg-muted animate-pulse rounded" />
                      </div>
                    ))
                  ) : reports.length === 0 ? (
                    <div className="col-span-full text-center text-muted-foreground py-8">
                      No reports found
                    </div>
                  ) : (
                    reports.map((report) => {
                      const verdict = getOverallVerdict(report);
                      const stats = report.last_analysis_stats || {};
                      const detections = (stats.malicious || 0) + (stats.suspicious || 0);
                      const totalScans = (stats.malicious || 0) + (stats.suspicious || 0) + 
                                       (stats.harmless || 0) + (stats.undetected || 0);
                      
                      // Check for rule matches and special indicators
                      const hasYaraMatch = report.crowdsourced_yara_results?.length > 0;
                      const hasSigmaMatch = report.crowdsourced_sigma_results?.length > 0;
                      const hasMacros = getOfficeInfo(report)?.hasSecurity;
                      const isPE = getPEInfo(report)?.hasPEInfo;
                      
                      return (
                        <Link
                          key={report.report_uuid}
                          to={`/reports/${report.report_uuid}`}
                          className="block"
                        >
                          <Card className="hover:shadow-md transition-all cursor-pointer border-l-4"
                            style={{
                              borderLeftColor: detections > 10 ? '#ef4444' : 
                                              detections > 0 ? '#f97316' : 
                                              '#22c55e'
                            }}>
                            <CardContent className="p-4 space-y-2">
                              {/* Line 1: File Name and Detection Ratio */}
                              <div className="flex items-start justify-between gap-2">
                                <h3 className="font-medium text-sm leading-tight break-all flex-1">
                                  {report.meaningful_name || report.names?.[0] || 'Unknown File'}
                                </h3>
                                <div className="flex items-center gap-2">
                                  {/* Special Indicators */}
                                  <div className="flex items-center gap-1">
                                    {hasYaraMatch && (
                                      <span className="text-purple-600 font-bold" title="YARA rules matched">Y</span>
                                    )}
                                    {hasSigmaMatch && (
                                      <span className="text-blue-600 font-bold" title="Sigma rules matched">Σ</span>
                                    )}
                                    {hasMacros && (
                                      <span className="text-red-600" title="Contains macros">⚠</span>
                                    )}
                                    {isPE && (
                                      <span className="text-orange-600 font-bold" title="PE executable">PE</span>
                                    )}
                                  </div>
                                  {/* Detection Ratio */}
                                  <div className="text-sm font-bold whitespace-nowrap">
                                    <span className={detections > 0 ? 'text-red-600' : 'text-green-600'}>
                                      {detections}
                                    </span>
                                    <span className="text-muted-foreground">/</span>
                                    <span className="text-foreground">{totalScans}</span>
                                  </div>
                                </div>
                              </div>

                              {/* Line 2: Full Hash */}
                              <div className="font-mono text-xs text-muted-foreground break-all">
                                {report.sha256 || report.file_hash}
                              </div>

                              {/* Line 3: Type Icon, Type, Size, First Seen, Last Seen */}
                              <div className="flex items-center justify-between text-xs text-muted-foreground">
                                <div className="flex items-center gap-2">
                                  {/* File Type Icon */}
                                  {(() => {
                                    const peInfo = getPEInfo(report);
                                    if (peInfo) {
                                      return <span className={peInfo.color}>{peInfo.icon}</span>;
                                    }
                                    
                                    const emailInfo = getEmailInfo(report);
                                    if (emailInfo) {
                                      return <span className={emailInfo.color}>{emailInfo.icon}</span>;
                                    }
                                    
                                    const imageInfo = getImageInfo(report);
                                    if (imageInfo) {
                                      return <span className={imageInfo.color}>{imageInfo.icon}</span>;
                                    }
                                    
                                    const officeInfo = getOfficeInfo(report);
                                    if (officeInfo) {
                                      return <span className={officeInfo.color}>{officeInfo.icon}</span>;
                                    }
                                    
                                    // Default file icon
                                    return <FileText className="h-3 w-3 text-muted-foreground" />;
                                  })()}
                                  <span>{report.type_tag || 'unknown'}</span>
                                  <span>•</span>
                                  <span>{report.size ? formatBytes(report.size) : 'N/A'}</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  <span title="First seen">{report.first_submission_date ? formatDate(report.first_submission_date).split(',')[0] : 'New'}</span>
                                  <span>→</span>
                                  <span title="Last seen">{report.last_submission_date ? formatDate(report.last_submission_date).split(',')[0] : formatDate(report.index_time).split(',')[0]}</span>
                                </div>
                              </div>

                              {/* Line 4: Verdict Badge if malicious/suspicious */}
                              {(verdict === 'malicious' || verdict === 'suspicious') && (
                                <div className="flex items-center gap-2">
                                  <Badge 
                                    variant={getVerdictBadgeVariant(verdict)}
                                    className="text-xs"
                                  >
                                    {verdict}
                                  </Badge>
                                  {stats.malicious > 0 && (
                                    <span className="text-xs text-red-600">
                                      {stats.malicious} malicious detection{stats.malicious > 1 ? 's' : ''}
                                    </span>
                                  )}
                                </div>
                              )}
                            </CardContent>
                          </Card>
                        </Link>
                      );
                    })
                  )}
                </div>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex flex-col sm:flex-row items-center justify-between px-4 sm:px-6 py-4 border-t gap-4">
                  <div className="text-sm text-muted-foreground text-center sm:text-left">
                    Page {currentPage} of {totalPages}
                    <span className="hidden sm:inline"> ({total.toLocaleString()} total)</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handlePageChange(currentPage - 1)}
                      disabled={currentPage === 1 || isLoading}
                    >
                      <ChevronLeft className="h-4 w-4" />
                      Previous
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handlePageChange(currentPage + 1)}
                      disabled={currentPage === totalPages || isLoading}
                    >
                      Next
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}