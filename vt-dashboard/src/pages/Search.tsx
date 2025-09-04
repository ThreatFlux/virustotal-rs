import React, { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
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
import { searchReports } from '@/services/elasticsearch';
import { executeOccurrenceSearch } from '@/services/occurrence';
import { Report, SearchFilters, OccurrenceSearchContext, OccurrenceSearchResult } from '@/types';
import { formatDate, formatBytes, truncateHash, getVerdictBadgeVariant, formatRelativeTime } from '@/lib/utils';
import {
  Search as SearchIcon,
  Filter,
  FileText,
  Calendar,
  HardDrive,
  Shield,
  X,
  ChevronRight,
  ChevronLeft,
  ChevronDown,
  ChevronUp,
  Users,
  TrendingUp,
} from 'lucide-react';

function getOverallVerdict(report: Report): string {
  const { malicious = 0, suspicious = 0, harmless = 0, undetected = 0 } = report;
  
  if (malicious > 0) return 'malicious';
  if (suspicious > 0) return 'suspicious';
  if (harmless > 0) return 'clean';
  if (undetected > 0) return 'undetected';
  
  return 'unknown';
}

export function Search() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [searchQuery, setSearchQuery] = useState('');
  const [fileTypes, setFileTypes] = useState<string[]>([]);
  const [verdicts, setVerdicts] = useState<string[]>([]);
  const [dateRange, setDateRange] = useState({ start: '', end: '' });
  const [fileSizeRange, setFileSizeRange] = useState({ min: '', max: '' });
  const [detectionRange, setDetectionRange] = useState({ min: '', max: '' });
  
  const [results, setResults] = useState<Report[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [hasSearched, setHasSearched] = useState(false);
  
  // Occurrence search state
  const [occurrenceSearchResult, setOccurrenceSearchResult] = useState<OccurrenceSearchResult | null>(null);
  const [isOccurrenceSearch, setIsOccurrenceSearch] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const perPage = 20;

  const availableFileTypes = [
    'PE32', 'PDF', 'ZIP', 'DOC', 'XLS', 'PPT', 'JS', 'HTML', 'EXE', 'DLL',
    'JAR', 'APK', 'MSI', 'RTF', 'XML', 'JSON', 'SWF', 'IMG', 'ISO'
  ];

  const availableVerdicts = ['malicious', 'suspicious', 'clean', 'undetected'];

  // Check for search parameters in URL on mount
  useEffect(() => {
    // Handle regular search query parameter
    const queryParam = searchParams.get('q');
    if (queryParam) {
      setSearchQuery(queryParam);
      // Automatically perform search when query is provided
      handleSearch(queryParam);
    }
    
    // Handle occurrence search parameter
    const occurrenceSearchParam = searchParams.get('occurrence_search');
    if (occurrenceSearchParam) {
      try {
        const context: OccurrenceSearchContext = JSON.parse(decodeURIComponent(occurrenceSearchParam));
        handleOccurrenceSearch(context);
      } catch (error) {
        console.error('Failed to parse occurrence search context:', error);
        setError('Invalid occurrence search parameters');
      }
    }
  }, [searchParams]);

  // Detect if a query looks like a hash
  const detectHashType = (query: string): string | null => {
    const trimmed = query.trim();
    
    // Remove common hash prefixes
    const cleaned = trimmed.replace(/^(0x|#)/, '').toLowerCase();
    
    // MD5: 32 hex characters
    if (/^[a-f0-9]{32}$/.test(cleaned)) {
      return 'md5';
    }
    
    // SHA1: 40 hex characters  
    if (/^[a-f0-9]{40}$/.test(cleaned)) {
      return 'sha1';
    }
    
    // SHA256: 64 hex characters
    if (/^[a-f0-9]{64}$/.test(cleaned)) {
      return 'sha256';
    }
    
    // Partial hash (at least 8 characters, all hex)
    if (/^[a-f0-9]{8,}$/.test(cleaned) && cleaned.length >= 8) {
      return 'hash'; // Generic hash field for partial matches
    }
    
    return null;
  };

  // Parse field-specific search syntax
  const parseSearchQuery = (query: string): { filters: SearchFilters; remainingQuery: string } => {
    const fieldPattern = /(\w+):(>|<|>=|<=|=)?("[^"]+"|[^\s]+)/g;
    const extractedFilters: SearchFilters = {};
    
    // Text field mappings
    const textFieldMappings: Record<string, string> = {
      'file_name': 'file_name',
      'filename': 'file_name',
      'name': 'file_name',
      'hash': 'hash',
      'sha256': 'sha256',
      'sha1': 'sha1',
      'md5': 'md5',
      'type': 'file_type_query',
      'file_type': 'file_type_query',
      'author': 'author',
      'creator': 'creator',
      'tag': 'tag',
      'tags': 'tag',
      'magic': 'magic',
      'imphash': 'imphash',
      'ssdeep': 'ssdeep',
      'tlsh': 'tlsh',
      'application': 'application',
      'app': 'application',
      'title': 'title',
      'subject': 'subject',
      'company': 'company',
      'manager': 'manager',
      'category': 'category',
      'keywords': 'keywords',
      'comments': 'comments',
      'comment': 'comments',
      'template': 'template',
      'last_modified_by': 'last_modified_by',
      'lastmodifiedby': 'last_modified_by',
      'last_author': 'last_modified_by',
      'presentation_format': 'presentation_format',
      'scale_crop': 'scale_crop',
      'scalecrop': 'scale_crop',
      'shared_doc': 'shared_doc',
      'shareddoc': 'shared_doc',
      'shared': 'shared_doc',
      'links_up_to_date': 'links_up_to_date',
      'linksuptodate': 'links_up_to_date',
      'links_updated': 'links_up_to_date',
      'hyperlinks_changed': 'hyperlinks_changed',
      'hyperlinkschanged': 'hyperlinks_changed',
      'hyperlinks': 'hyperlinks_changed',
      // PE fields
      'signed': 'signed',
      'signature': 'signed',
      'digital_signature': 'signed',
      'signer': 'signer',
      'certificate': 'signer',
      'packer': 'packer',
      'packed': 'packer',
      'compiler': 'compiler',
      // PDF fields
      'javascript': 'javascript',
      'js': 'javascript',
      'encrypted': 'encrypted',
      'encryption': 'encrypted',
      'forms': 'forms',
      'acroform': 'forms',
      // Android fields
      'package': 'package',
      'package_name': 'package',
      'android_package': 'package',
      'permission': 'permission',
      'permissions': 'permission',
      'activity': 'activity',
      'activities': 'activity',
      // Timestamps
      'created': 'created',
      'modified': 'modified',
      'timestamp': 'timestamp',
      'compile_time': 'timestamp',
      // File properties
      'entropy': 'entropy',
      'vhash': 'vhash',
      'authentihash': 'authentihash',
      'rich_header': 'rich_header',
    };
    
    // Numeric field mappings
    const numericFieldMappings: Record<string, string> = {
      'size': 'size',
      'filesize': 'size',
      'pages': 'pages',
      'page': 'pages',
      'pagecount': 'pages',
      'page_count': 'pages',
      'num_pages': 'pages',
      'slides': 'slides',
      'slide': 'slides',
      'slidecount': 'slides',
      'slide_count': 'slides',
      'words': 'words',
      'word': 'words',
      'wordcount': 'words',
      'word_count': 'words',
      'paragraphs': 'paragraphs',
      'paragraph': 'paragraphs',
      'paragraph_count': 'paragraphs',
      'detections': 'detections',
      'detection': 'detections',
      'detection_count': 'detections',
      'malicious': 'malicious_count',
      'suspicious': 'suspicious_count',
      'revision': 'revision',
      'revisions': 'revision',
      'revision_number': 'revision',
      'streams': 'streams',
      'stream': 'streams',
      'num_streams': 'streams',
      'objects': 'objects',
      'object': 'objects',
      'num_objects': 'objects',
      'hidden_slides': 'hidden_slides',
      'notes': 'notes',
      'note_count': 'notes',
      'mm_clips': 'mm_clips',
      'clips': 'mm_clips',
      'total_edit_time': 'total_edit_time',
      'edit_time': 'total_edit_time',
      'editing_time': 'total_edit_time',
      'characters': 'characters',
      'char_count': 'characters',
      'character_count': 'characters',
      'lines': 'lines',
      'line_count': 'lines',
      'byte_count': 'byte_count',
      'code_page': 'code_page',
      'security': 'security',
      'macros': 'macros',
      'macro_count': 'macros',
      // PE numeric fields
      'entry_point': 'entry_point',
      'machine_type': 'machine_type',
      'sections': 'sections',
      'section_count': 'sections',
      'imports': 'imports',
      'import_count': 'imports',
      'exports': 'exports',
      'export_count': 'exports',
      'resources': 'resources',
      'resource_count': 'resources',
      'overlay_size': 'overlay_size',
      // PDF numeric fields
      'js_count': 'js_count',
      'javascript_count': 'js_count',
      'launch_count': 'launch_count',
      'launch_actions': 'launch_count',
      'embedded_files': 'embedded_files',
      'embed_count': 'embedded_files',
      // Android numeric fields
      'permission_count': 'permission_count',
      'activity_count': 'activity_count',
      'service_count': 'service_count',
      'receiver_count': 'receiver_count',
      // Archive fields
      'contained_files': 'contained_files',
      'archive_files': 'contained_files',
      'compression_ratio': 'compression_ratio',
      // Timestamps (as numeric for comparison)
      'days_old': 'days_old',
      'age': 'days_old',
      'times_submitted': 'times_submitted',
      'submissions': 'times_submitted',
      'reputation': 'reputation',
      'votes': 'votes',
    };
    
    let remainingQuery = query;
    let match;
    
    while ((match = fieldPattern.exec(query)) !== null) {
      const [fullMatch, field, operator, value] = match;
      const cleanValue = value.replace(/^"|"$/g, ''); // Remove quotes if present
      const fieldLower = field.toLowerCase();
      
      // Check if it's a numeric field
      if (numericFieldMappings[fieldLower]) {
        const mappedField = numericFieldMappings[fieldLower];
        if (!extractedFilters.numeric_queries) {
          extractedFilters.numeric_queries = {};
        }
        
        // Parse the numeric value and operator
        const numValue = parseInt(cleanValue);
        if (!isNaN(numValue)) {
          extractedFilters.numeric_queries[mappedField] = {
            value: numValue,
            operator: operator || '='
          };
        }
      }
      // Check if it's a text field
      else if (textFieldMappings[fieldLower]) {
        const mappedField = textFieldMappings[fieldLower];
        if (!extractedFilters.field_queries) {
          extractedFilters.field_queries = {};
        }
        extractedFilters.field_queries[mappedField] = cleanValue;
      }
      
      remainingQuery = remainingQuery.replace(fullMatch, '').trim();
    }
    
    // If no field patterns were found, check if the entire query looks like a hash or number
    if (remainingQuery === query.trim()) {
      // Check if it's a pure number (could be file size in bytes)
      if (/^\d+$/.test(remainingQuery)) {
        const numValue = parseInt(remainingQuery);
        if (!isNaN(numValue)) {
          // Add as a size search
          if (!extractedFilters.numeric_queries) {
            extractedFilters.numeric_queries = {};
          }
          extractedFilters.numeric_queries['size'] = {
            value: numValue,
            operator: '='
          };
          // Also keep as general search in case it matches other fields
          // remainingQuery stays as is for multi-field search
        }
      } else {
        // Check if it's a hash
        const hashType = detectHashType(remainingQuery);
        if (hashType) {
          // It's a hash - add it as a field query
          if (!extractedFilters.field_queries) {
            extractedFilters.field_queries = {};
          }
          
          // Clean the hash (remove prefixes)
          const cleanHash = remainingQuery.replace(/^(0x|#)/, '').toLowerCase();
          extractedFilters.field_queries[hashType] = cleanHash;
          
          // For partial hashes or generic 'hash' type, also try as general search
          if (hashType === 'hash') {
            // Keep as remaining query for multi-field search
            remainingQuery = cleanHash;
          } else {
            // Clear remaining query since we handled it as a specific hash field
            remainingQuery = '';
          }
        }
      }
    }
    
    return { filters: extractedFilters, remainingQuery };
  };

  const handleOccurrenceSearch = async (context: OccurrenceSearchContext) => {
    setIsLoading(true);
    setError(null);
    setHasSearched(true);
    setIsOccurrenceSearch(true);

    try {
      const response = await executeOccurrenceSearch(context);

      if (response.success && response.data) {
        setOccurrenceSearchResult(response.data);
        setResults(response.data.results);
        setTotal(response.data.total_found);
        setTotalPages(Math.ceil(response.data.total_found / perPage));
        setCurrentPage(1);
      } else {
        setError(response.error || 'Occurrence search failed');
        setResults([]);
        setOccurrenceSearchResult(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Occurrence search failed');
      setResults([]);
      setOccurrenceSearchResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSearch = async (queryOrPage?: string | number, pageNumber?: number) => {
    // Handle overloaded parameters
    let query: string;
    let page: number;
    
    if (typeof queryOrPage === 'string') {
      // Called with query string from URL parameter
      query = queryOrPage;
      page = pageNumber || 1;
    } else {
      // Called with page number from pagination
      query = searchQuery;
      page = queryOrPage || 1;
    }
    
    setIsLoading(true);
    setError(null);
    setHasSearched(true);
    setIsOccurrenceSearch(false);
    setOccurrenceSearchResult(null);

    try {
      const filters: SearchFilters = {};

      // Parse field-specific queries
      if (query.trim()) {
        const { filters: parsedFilters, remainingQuery } = parseSearchQuery(query.trim());
        Object.assign(filters, parsedFilters);
        
        // Add remaining query as general search if not empty
        if (remainingQuery.trim()) {
          filters.search_query = remainingQuery.trim();
        }
      }

      if (fileTypes.length > 0) {
        filters.file_type = fileTypes;
      }

      if (verdicts.length > 0) {
        filters.verdict = verdicts;
      }

      if (dateRange.start && dateRange.end) {
        filters.date_range = dateRange;
      }

      if (fileSizeRange.min || fileSizeRange.max) {
        filters.file_size_range = {
          min: fileSizeRange.min ? parseInt(fileSizeRange.min) : 0,
          max: fileSizeRange.max ? parseInt(fileSizeRange.max) : Number.MAX_SAFE_INTEGER,
        };
      }

      if (detectionRange.min || detectionRange.max) {
        filters.engine_detection_count = {
          min: detectionRange.min ? parseInt(detectionRange.min) : 0,
          max: detectionRange.max ? parseInt(detectionRange.max) : Number.MAX_SAFE_INTEGER,
        };
      }

      const response = await searchReports(filters, page, perPage);

      if (response.success && response.data) {
        setResults(response.data.reports);
        setTotal(response.data.total);
        setTotalPages(response.data.total_pages);
        setCurrentPage(page);
      } else {
        setError(response.error || 'Search failed');
        setResults([]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Search failed');
      setResults([]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearFilters = () => {
    setSearchQuery('');
    setFileTypes([]);
    setVerdicts([]);
    setDateRange({ start: '', end: '' });
    setFileSizeRange({ min: '', max: '' });
    setDetectionRange({ min: '', max: '' });
    setResults([]);
    setHasSearched(false);
    setError(null);
    setIsOccurrenceSearch(false);
    setOccurrenceSearchResult(null);
    // Clear URL parameters
    setSearchParams(new URLSearchParams());
  };

  const toggleFileType = (fileType: string) => {
    setFileTypes(prev => 
      prev.includes(fileType)
        ? prev.filter(t => t !== fileType)
        : [...prev, fileType]
    );
  };

  const toggleVerdict = (verdict: string) => {
    setVerdicts(prev => 
      prev.includes(verdict)
        ? prev.filter(v => v !== verdict)
        : [...prev, verdict]
    );
  };

  const hasFilters = searchQuery || fileTypes.length > 0 || verdicts.length > 0 || 
                    dateRange.start || dateRange.end || fileSizeRange.min || 
                    fileSizeRange.max || detectionRange.min || detectionRange.max;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-foreground">Advanced Search</h1>
        <p className="text-muted-foreground mt-1">
          Search and filter VirusTotal analysis reports with advanced criteria
        </p>
      </div>

      {/* Search Form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Filter className="h-5 w-5" />
            <span>Search Filters</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Text Search */}
          <div className="space-y-2">
            <Label className="flex items-center space-x-2">
              <SearchIcon className="h-4 w-4" />
              <span>Search Query</span>
            </Label>
            <div className="flex space-x-2">
              <Input
                placeholder='Enter search (e.g., "malware.exe" or file_name:example.exe sha256:abc123...)'
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    handleSearch();
                  }
                }}
                className="flex-1"
              />
              <Button onClick={() => handleSearch()} disabled={isLoading}>
                {isLoading ? 'Searching...' : 'Search'}
              </Button>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">
                Search by file hash, name, type, or other file attributes
              </p>
              <details className="text-xs text-muted-foreground">
                <summary className="cursor-pointer hover:text-foreground">
                  <span className="font-medium">Search Tips</span> - Click to expand search syntax help
                </summary>
                <div className="mt-2 space-y-2 pl-4">
                  <div>
                    <span className="font-medium">Text fields:</span>{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">file_name:invoice.pdf</code>,{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">md5:abc123</code>,{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">type:pdf</code>,{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">author:"John Doe"</code>
                  </div>
                  <div>
                    <span className="font-medium">Numeric fields with operators:</span>{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">pages:&gt;10</code>,{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">size:&lt;1000000</code>,{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">detections:&gt;=5</code>,{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">slides:20</code>
                  </div>
                  <div>
                    <span className="font-medium">Basic fields:</span> file_name, hash, sha256, sha1, md5, type, size, magic, tags, imphash, ssdeep, tlsh, vhash, authentihash
                  </div>
                  <div>
                    <span className="font-medium">Document fields:</span> title, subject, author, company, manager, category, keywords, comments, template, pages, slides, words, revision
                  </div>
                  <div>
                    <span className="font-medium">PE/EXE fields:</span> signed (yes/no), signer, packer, compiler, entry_point, sections, imports, exports, resources, machine_type
                  </div>
                  <div>
                    <span className="font-medium">PDF fields:</span> encrypted (yes/no), javascript (yes/no), js_count, launch_count, embedded_files, forms (yes/no)
                  </div>
                  <div>
                    <span className="font-medium">Android fields:</span> package, permission, activity, permission_count, activity_count, service_count
                  </div>
                  <div>
                    <span className="font-medium">Archive fields:</span> contained_files, compression_ratio
                  </div>
                  <div>
                    <span className="font-medium">Metadata:</span> times_submitted, reputation, created, modified, timestamp, days_old
                  </div>
                  <div>
                    <span className="font-medium">Examples:</span>{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">338302</code> (file size),{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">size:&gt;1000000</code>,{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">shared_doc:yes</code>,{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">revision:&gt;75</code>
                  </div>
                  <div>
                    <span className="font-medium">Auto-detection:</span> Plain numbers search by file size, hex strings search by hash
                  </div>
                  <div>
                    <span className="font-medium">Operators:</span> <code>&gt;</code> (greater than), <code>&lt;</code> (less than), <code>&gt;=</code> (greater or equal), <code>&lt;=</code> (less or equal), <code>=</code> or <code>:</code> (equals)
                  </div>
                  <div>
                    <span className="font-medium">Combine searches:</span>{' '}
                    <code className="px-1 py-0.5 bg-muted rounded text-xs">type:pdf pages:&gt;50 author:"John"</code>
                  </div>
                </div>
              </details>
            </div>
          </div>

          {/* Advanced Filters Toggle for Mobile */}
          <div className="lg:hidden">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="w-full flex items-center justify-between"
            >
              <span>Advanced Filters</span>
              {showAdvanced ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </Button>
          </div>

          {/* Advanced Filters - Hidden on mobile by default */}
          <div className={`grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 ${showAdvanced ? 'block lg:grid' : 'hidden lg:grid'}`}>
            {/* File Types */}
            <div className="space-y-2">
              <Label className="flex items-center space-x-2">
                <FileText className="h-4 w-4" />
                <span>File Types</span>
              </Label>
              <div className="border rounded-md p-3 max-h-40 overflow-y-auto">
                <div className="grid grid-cols-2 gap-2">
                  {availableFileTypes.map(type => (
                    <label key={type} className="flex items-center space-x-2 text-sm cursor-pointer">
                      <input
                        type="checkbox"
                        checked={fileTypes.includes(type)}
                        onChange={() => toggleFileType(type)}
                        className="rounded"
                      />
                      <span>{type}</span>
                    </label>
                  ))}
                </div>
              </div>
              {fileTypes.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {fileTypes.map(type => (
                    <Badge key={type} variant="secondary" className="text-xs">
                      {type}
                      <button 
                        onClick={() => toggleFileType(type)}
                        className="ml-1 hover:text-destructive"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            {/* Verdicts */}
            <div className="space-y-2">
              <Label className="flex items-center space-x-2">
                <Shield className="h-4 w-4" />
                <span>Detection Verdicts</span>
              </Label>
              <div className="border rounded-md p-3">
                <div className="space-y-2">
                  {availableVerdicts.map(verdict => (
                    <label key={verdict} className="flex items-center space-x-2 text-sm cursor-pointer">
                      <input
                        type="checkbox"
                        checked={verdicts.includes(verdict)}
                        onChange={() => toggleVerdict(verdict)}
                        className="rounded"
                      />
                      <span className="capitalize">{verdict}</span>
                    </label>
                  ))}
                </div>
              </div>
              {verdicts.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {verdicts.map(verdict => (
                    <Badge key={verdict} variant={getVerdictBadgeVariant(verdict)} className="text-xs">
                      {verdict}
                      <button 
                        onClick={() => toggleVerdict(verdict)}
                        className="ml-1 hover:text-destructive"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            {/* Date Range */}
            <div className="space-y-2">
              <Label className="flex items-center space-x-2">
                <Calendar className="h-4 w-4" />
                <span>Date Range</span>
              </Label>
              <div className="space-y-2">
                <Input
                  type="date"
                  placeholder="Start date"
                  value={dateRange.start}
                  onChange={(e) => setDateRange(prev => ({ ...prev, start: e.target.value }))}
                />
                <Input
                  type="date"
                  placeholder="End date"
                  value={dateRange.end}
                  onChange={(e) => setDateRange(prev => ({ ...prev, end: e.target.value }))}
                />
              </div>
            </div>

            {/* File Size Range */}
            <div className="space-y-2">
              <Label className="flex items-center space-x-2">
                <HardDrive className="h-4 w-4" />
                <span>File Size (bytes)</span>
              </Label>
              <div className="space-y-2">
                <Input
                  type="number"
                  placeholder="Minimum size"
                  value={fileSizeRange.min}
                  onChange={(e) => setFileSizeRange(prev => ({ ...prev, min: e.target.value }))}
                />
                <Input
                  type="number"
                  placeholder="Maximum size"
                  value={fileSizeRange.max}
                  onChange={(e) => setFileSizeRange(prev => ({ ...prev, max: e.target.value }))}
                />
              </div>
            </div>

            {/* Detection Count Range */}
            <div className="space-y-2">
              <Label className="flex items-center space-x-2">
                <Shield className="h-4 w-4" />
                <span>Detection Count</span>
              </Label>
              <div className="space-y-2">
                <Input
                  type="number"
                  placeholder="Minimum detections"
                  value={detectionRange.min}
                  onChange={(e) => setDetectionRange(prev => ({ ...prev, min: e.target.value }))}
                />
                <Input
                  type="number"
                  placeholder="Maximum detections"
                  value={detectionRange.max}
                  onChange={(e) => setDetectionRange(prev => ({ ...prev, max: e.target.value }))}
                />
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-between pt-4 border-t">
            <div className="flex items-center space-x-2">
              <Button onClick={() => handleSearch()} disabled={isLoading}>
                {isLoading ? 'Searching...' : 'Apply Search'}
              </Button>
              {hasFilters && (
                <Button variant="outline" onClick={handleClearFilters}>
                  <X className="h-4 w-4 mr-2" />
                  Clear All
                </Button>
              )}
            </div>
            {hasSearched && (
              <div className="text-sm text-muted-foreground">
                {total.toLocaleString()} results found
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      {hasSearched && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                {isOccurrenceSearch ? (
                  <>
                    {occurrenceSearchResult?.context.search_type === 'similar_files' && <Users className="h-5 w-5" />}
                    {occurrenceSearchResult?.context.search_type === 'yara_matches' && <Shield className="h-5 w-5" />}
                    {occurrenceSearchResult?.context.search_type === 'campaign_related' && <TrendingUp className="h-5 w-5" />}
                    {!['similar_files', 'yara_matches', 'campaign_related'].includes(occurrenceSearchResult?.context.search_type || '') && <FileText className="h-5 w-5" />}
                    <span>{occurrenceSearchResult?.context.metadata.display_name || 'Occurrence Search Results'}</span>
                  </>
                ) : (
                  <>
                    <FileText className="h-5 w-5" />
                    <span>Search Results</span>
                  </>
                )}
              </div>
              {total > 0 && (
                <div className="text-sm text-muted-foreground">
                  {total.toLocaleString()} results
                </div>
              )}
            </CardTitle>
            {isOccurrenceSearch && occurrenceSearchResult && (
              <div className="text-sm text-muted-foreground mt-2 p-3 bg-blue-50 border-l-4 border-blue-200 rounded">
                <p className="font-medium">Occurrence Search:</p>
                <p>{occurrenceSearchResult.context.metadata.search_description}</p>
                {occurrenceSearchResult.context.base_name && (
                  <p className="mt-1">Base file: <span className="font-mono text-xs">{occurrenceSearchResult.context.base_name}</span></p>
                )}
              </div>
            )}
          </CardHeader>
          <CardContent className="p-0">
            {error ? (
              <div className="p-6 text-center text-destructive">
                <p>Search Error: {error}</p>
                <Button variant="outline" onClick={() => handleSearch()} className="mt-2">
                  Retry Search
                </Button>
              </div>
            ) : results.length === 0 && !isLoading ? (
              <div className="p-6 text-center text-muted-foreground">
                {hasSearched ? 'No results found for your search criteria' : 'Enter search criteria and click "Apply Search"'}
              </div>
            ) : (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-32">File Hash</TableHead>
                      <TableHead className="w-48">File Name</TableHead>
                      <TableHead className="w-36">Type</TableHead>
                      <TableHead className="w-20">Size</TableHead>
                      <TableHead className="w-24">Verdict</TableHead>
                      <TableHead className="w-32">Detection Rate</TableHead>
                      <TableHead className="w-28">Related</TableHead>
                      <TableHead className="w-24">Last Seen</TableHead>
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
                    ) : (
                      results.map((report) => {
                        const verdict = getOverallVerdict(report);
                        const detections = (report.malicious || 0) + (report.suspicious || 0);
                        const totalScans = (report.malicious || 0) + (report.suspicious || 0) + 
                                         (report.harmless || 0) + (report.undetected || 0);
                        
                        // Get meaningful file name
                        const fileName = report.meaningful_name || report.names?.[0] || 
                                       report.file_name || report.sha256?.substring(0, 8) + '...';
                        
                        // Get file type with more detail
                        const fileType = report.type_description || report.type_tag || 
                                       report.magic?.split(',')[0] || 'Binary';
                        
                        // Format file size better
                        const fileSize = report.size || report.file_size;
                        
                        return (
                          <TableRow key={report.report_uuid} className="hover:bg-muted/50">
                            <TableCell>
                              <div className="space-y-1">
                                <Link 
                                  to={`/reports/${report.report_uuid}`}
                                  className="font-mono text-xs text-primary hover:underline block truncate"
                                  title={report.sha256}
                                >
                                  {truncateHash(report.sha256 || report.file_hash, 12)}
                                </Link>
                                {report.md5 && (
                                  <div className="text-xs text-muted-foreground font-mono" title={`MD5: ${report.md5}`}>
                                    MD5: {truncateHash(report.md5, 8)}
                                  </div>
                                )}
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="space-y-1">
                                <div className="font-medium text-sm truncate max-w-48" title={fileName}>
                                  {fileName}
                                </div>
                                {report.names && report.names.length > 1 && (
                                  <div className="text-xs text-muted-foreground">
                                    +{report.names.length - 1} more names
                                  </div>
                                )}
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="space-y-1">
                                <div className="text-sm truncate max-w-32" title={fileType}>
                                  {fileType}
                                </div>
                                {report.tags && report.tags.length > 0 && (
                                  <div className="flex flex-wrap gap-1">
                                    {report.tags.slice(0, 2).map((tag: string, idx: number) => (
                                      <Badge key={idx} variant="outline" className="text-xs">
                                        {tag}
                                      </Badge>
                                    ))}
                                    {report.tags.length > 2 && (
                                      <span className="text-xs text-muted-foreground">+{report.tags.length - 2}</span>
                                    )}
                                  </div>
                                )}
                              </div>
                            </TableCell>
                            <TableCell className="text-sm">
                              {fileSize ? formatBytes(fileSize) : '-'}
                            </TableCell>
                            <TableCell>
                              <div className="space-y-1">
                                <Badge 
                                  variant={getVerdictBadgeVariant(verdict)}
                                  className="text-xs"
                                >
                                  {verdict}
                                </Badge>
                                {totalScans > 0 && (
                                  <div className="text-xs text-muted-foreground">
                                    {detections > 0 ? `${detections}/${totalScans}` : 'Clean'}
                                  </div>
                                )}
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                {detections > 0 && (
                                  <div className="flex items-center gap-1">
                                    <div className="w-16 bg-muted rounded-full h-1.5">
                                      <div 
                                        className="bg-red-600 h-1.5 rounded-full transition-all"
                                        style={{ width: `${Math.min(100, (detections / totalScans) * 100)}%` }}
                                      />
                                    </div>
                                    <span className="text-xs font-medium">
                                      {Math.round((detections / totalScans) * 100)}%
                                    </span>
                                  </div>
                                )}
                                {detections === 0 && totalScans > 0 && (
                                  <span className="text-xs text-green-600 font-medium">Clean</span>
                                )}
                                {totalScans === 0 && (
                                  <span className="text-xs text-muted-foreground">No data</span>
                                )}
                              </div>
                            </TableCell>
                            <TableCell>
                              <OccurrenceColumn
                                report={report}
                                variant="compact"
                                onSearchTrigger={handleOccurrenceSearch}
                              />
                            </TableCell>
                            <TableCell>
                              <div className="text-xs text-muted-foreground">
                                {report.last_analysis_date ? (
                                  <div title={`Analyzed: ${formatDate(report.last_analysis_date)}`}>
                                    {formatRelativeTime(report.last_analysis_date)}
                                  </div>
                                ) : report.created_at ? (
                                  <div title={formatDate(report.created_at)}>
                                    {formatRelativeTime(report.created_at)}
                                  </div>
                                ) : (
                                  '-'
                                )}
                              </div>
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>

                {/* Pagination */}
                {totalPages > 1 && (
                  <div className="flex items-center justify-between px-6 py-4 border-t">
                    <div className="text-sm text-muted-foreground">
                      Page {currentPage} of {totalPages} ({total.toLocaleString()} total)
                    </div>
                    <div className="flex items-center space-x-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleSearch(currentPage - 1)}
                        disabled={currentPage === 1 || isLoading}
                      >
                        <ChevronLeft className="h-4 w-4" />
                        Previous
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleSearch(currentPage + 1)}
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
      )}
    </div>
  );
}