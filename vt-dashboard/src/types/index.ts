// Base VirusTotal Report Interface
export interface Report {
  report_uuid: string;
  file_hash: string;  // Main hash identifier
  sha256?: string;
  sha1?: string;
  md5?: string;
  size?: number;  // File size in bytes
  meaningful_name?: string;  // Primary display name
  names?: string[];  // All known names
  type_tag?: string;  // File type tag (e.g., 'peexe', 'pdf')
  type_description?: string;  // Human-readable type
  type_extension?: string;
  first_submission_date?: string;
  last_submission_date?: string;
  last_analysis_date?: string;
  times_submitted?: number;
  reputation?: number;
  last_analysis_stats?: {
    'confirmed-timeout'?: number;
    'failure'?: number;
    'harmless'?: number;
    'malicious'?: number;
    'suspicious'?: number;
    'timeout'?: number;
    'type-unsupported'?: number;
    'undetected'?: number;
  };
  total_votes?: {
    harmless?: number;
    malicious?: number;
  };
  magic?: string;
  ssdeep?: string;
  tlsh?: string;
  vhash?: string;
  authentihash?: string;
  imphash?: string;
  index_time: string;  // When indexed
  creation_date?: string;
  // Special analysis fields
  pe_info?: any;
  androguard?: any;
  pdf_info?: any;
  office_info?: any;
  bundle_info?: any;
  exiftool?: any;
  detectiteasy?: any;
  trid?: any;
  [key: string]: any;  // Allow for additional fields
}

// Analysis Results Interface
export interface AnalysisResult {
  report_uuid: string;
  file_hash: string;
  engine_name: string;
  engine_version?: string;
  engine_update?: string;
  category: string;
  result?: string;
  method?: string;
  index_time: string;
}

// Sandbox Verdict Interface
export interface SandboxVerdict {
  report_uuid: string;
  file_hash: string;
  sandbox_name: string;
  verdict?: {
    category?: string;
    confidence?: number;
    malware_classification?: string[];
    malware_names?: string[];
  };
  index_time: string;
}

// Behavioral Event Interface
export interface BehavioralEvent {
  process_info?: any;
  process_path?: string;
  command_line?: string;
  process_id?: string;
  parent_process?: string;
  file_info?: any;
  target_file?: string;
  file_creation_time?: string;
  network_info?: any;
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;
  registry_info?: any;
  registry_key?: string;
  registry_value?: string;
  loaded_image?: string;
  signature_status?: string;
  signed?: boolean;
}

// Sandbox Behavior Interface
export interface SandboxBehavior {
  report_uuid: string;
  file_hash: string;
  index_time: string;
  analysis_type: string;
  rule_id?: string;
  rule_title?: string;
  rule_description?: string;
  severity?: string;
  rule_author?: string;
  rule_source?: string;
  event_count?: number;
  behavioral_events?: BehavioralEvent[];
  raw_sigma_result?: any;
}

// Behavioral Analysis Summary
export interface BehavioralAnalysis {
  total_behaviors: number;
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  behavior_categories: {
    process_activity: number;
    file_operations: number;
    network_activity: number;
    registry_operations: number;
    dll_loading: number;
  };
  top_processes: Array<{
    process_path: string;
    count: number;
    command_lines: string[];
  }>;
  network_connections: Array<{
    destination_ip: string;
    destination_port: number;
    protocol: string;
    count: number;
  }>;
  file_operations: Array<{
    target_file: string;
    operation_type: string;
    count: number;
  }>;
  registry_operations: Array<{
    registry_key: string;
    operation_type: string;
    count: number;
  }>;
  behavioral_timeline: Array<{
    timestamp: string;
    event_type: string;
    description: string;
    severity: string;
  }>;
}

// Crowdsourced Data Interface
export interface CrowdsourcedData {
  report_uuid: string;
  file_hash: string;
  source: string;
  data_type?: string;
  data?: any;
  positives?: number;
  total?: number;
  rule_name?: string;
  author?: string;
  ruleset_name?: string;
  ruleset_id?: string;
  match_count?: number;
  index_time: string;
}

// Relationships Interface
export interface Relationship {
  report_uuid: string;
  file_hash: string;
  relation_type: string;
  target_id: string;
  target_type?: string;
  context?: string;
  index_time: string;
}

// Search and Filter Interfaces
export interface SearchFilters {
  file_type?: string[];
  verdict?: string[];
  date_range?: {
    start: string;
    end: string;
  };
  file_size_range?: {
    min: number;
    max: number;
  };
  engine_detection_count?: {
    min: number;
    max: number;
  };
  sandbox_names?: string[];
  yara_rules?: string[];
  search_query?: string;
  field_queries?: Record<string, string>; // For field-specific searches like file_name:example.exe
  numeric_queries?: Record<string, {
    value: number;
    operator: string; // '>', '<', '>=', '<=', '='
  }>; // For numeric searches like pages:>10 or size:<1000000
}

export interface SearchResult {
  reports: Report[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

// Dashboard Statistics Interface
export interface DashboardStats {
  total_reports: number;
  reports_today: number;
  malicious_files: number;
  clean_files: number;
  suspicious_files: number;
  undetected_files: number;
  top_file_types: Array<{
    type: string;
    count: number;
  }>;
  detection_trends: Array<{
    date: string;
    malicious: number;
    suspicious: number;
    clean: number;
    undetected: number;
  }>;
  top_engines: Array<{
    engine: string;
    detections: number;
  }>;
  file_size_distribution: Array<{
    range: string;
    count: number;
  }>;
}

// Chart Data Interfaces
export interface ChartData {
  name: string;
  value: number;
  color?: string;
}

export interface TimeSeriesData {
  date: string;
  [key: string]: string | number;
}

// API Response Interfaces
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface ElasticsearchHit<T> {
  _index: string;
  _type?: string;
  _id: string;
  _score: number;
  _source: T;
}

export interface ElasticsearchResponse<T> {
  took: number;
  timed_out: boolean;
  _shards: {
    total: number;
    successful: number;
    skipped: number;
    failed: number;
  };
  hits: {
    total: {
      value: number;
      relation: string;
    };
    max_score: number;
    hits: ElasticsearchHit<T>[];
  };
  aggregations?: Record<string, any>;
}

// UI Component Props Interfaces
export interface TableColumn<T> {
  key: keyof T | string;
  header: string;
  render?: (value: any, row: T) => React.ReactNode;
  sortable?: boolean;
  width?: string;
}

export interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  showFirstLast?: boolean;
  showPrevNext?: boolean;
}

export interface LoadingState {
  isLoading: boolean;
  error?: string | null;
}

// Theme Interface
export interface Theme {
  mode: 'light' | 'dark';
  colors: {
    primary: string;
    secondary: string;
    background: string;
    foreground: string;
    malicious: string;
    suspicious: string;
    clean: string;
    undetected: string;
  };
}

// Navigation Interface
export interface NavItem {
  name: string;
  href: string;
  icon?: React.ComponentType<any>;
  current?: boolean;
  children?: NavItem[];
}

// File Analysis Details
export interface FileAnalysis {
  report: Report;
  analysis_results: AnalysisResult[];
  sandbox_verdicts: SandboxVerdict[];
  sandbox_behaviors: SandboxBehavior[];
  behavioral_analysis: BehavioralAnalysis;
  crowdsourced_data: CrowdsourcedData[];
  relationships: Relationship[];
  risk_score: {
    score: number;
    level: 'Low' | 'Medium' | 'High' | 'Critical';
  };
}

// Occurrence Data Interfaces for searchable columns
export interface OccurrenceData {
  file_hash: string;
  report_uuid: string;
  similar_files_count: number;
  times_submitted: number;
  first_seen: string;
  last_seen: string;
  yara_matches: number;
  sigma_matches: number;
  sandbox_analyses: number;
  crowdsourced_detections: number;
  related_campaigns: string[];
  similar_names: string[];
  common_engines: string[];
  family_classification?: string;
  threat_category?: string;
}

export interface OccurrenceSearchContext {
  search_type: 'similar_files' | 'same_family' | 'yara_matches' | 'sigma_matches' | 'campaign_related' | 'engine_pattern' | 'behavioral_similarity';
  base_hash: string;
  base_name?: string;
  filters: {
    similarity_threshold?: number;
    time_range?: { start: string; end: string };
    verdict_filter?: VerdictType[];
    include_suspicious?: boolean;
    min_detections?: number;
  };
  metadata: {
    display_name: string;
    expected_count?: number;
    search_description: string;
  };
}

export interface OccurrenceSearchResult {
  context: OccurrenceSearchContext;
  results: Report[];
  total_found: number;
  search_executed_at: string;
  related_indicators: {
    hashes: string[];
    file_names: string[];
    yara_rules: string[];
    campaigns: string[];
  };
}

// Export types for external use
export type VerdictType = 'malicious' | 'suspicious' | 'clean' | 'harmless' | 'undetected';
export type FileType = 'PE32' | 'PDF' | 'ZIP' | 'DOC' | 'XLS' | 'PPT' | 'JS' | 'HTML' | 'Unknown';
export type EngineCategory = 'type-unsupported' | 'timeout' | 'confirmed-timeout' | 'failure' | 'malicious' | 'suspicious' | 'undetected' | 'harmless';
export type OccurrenceSearchType = OccurrenceSearchContext['search_type'];