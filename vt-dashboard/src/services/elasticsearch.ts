import type {
  Report,
  AnalysisResult,
  SandboxVerdict,
  SandboxBehavior,
  BehavioralAnalysis,
  CrowdsourcedData,
  Relationship,
  SearchFilters,
  SearchResult,
  DashboardStats,
  ElasticsearchResponse,
  ApiResponse,
  FileAnalysis,
} from '@/types';

const ES_BASE_URL = '/api/elasticsearch';

// Elasticsearch query builder helpers
const buildDateRangeQuery = (dateRange?: { start: string; end: string }) => {
  if (!dateRange) return null;
  return {
    range: {
      index_time: {
        gte: dateRange.start,
        lte: dateRange.end,
      },
    },
  };
};

const buildTermsQuery = (field: string, values: string[]) => {
  if (!values.length) return null;
  return {
    terms: {
      [field]: values,
    },
  };
};

const buildRangeQuery = (field: string, range: { min: number; max: number }) => {
  return {
    range: {
      [field]: {
        gte: range.min,
        lte: range.max,
      },
    },
  };
};

// Generic Elasticsearch request function
export async function esRequest<T>(endpoint: string, body?: any): Promise<T> {
  try {
    const response = await fetch(`${ES_BASE_URL}${endpoint}`, {
      method: body ? 'POST' : 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      throw new Error(`Elasticsearch request failed: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Elasticsearch request error:', error);
    throw error;
  }
}

// Report services
export async function fetchReports(page: number = 1, perPage: number = 20): Promise<ApiResponse<SearchResult>> {
  try {
    const from = (page - 1) * perPage;
    const query = {
      query: {
        match_all: {},
      },
      sort: [
        {
          index_time: { order: 'desc' },
        },
      ],
      from,
      size: perPage,
    };

    const response = await esRequest<ElasticsearchResponse<Report>>('/vt_reports/_search', query);
    
    const reports = response.hits.hits.map(hit => hit._source);
    const total = response.hits.total.value;
    const totalPages = Math.ceil(total / perPage);

    return {
      success: true,
      data: {
        reports,
        total,
        page,
        per_page: perPage,
        total_pages: totalPages,
      },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch reports',
    };
  }
}

export async function fetchReportById(reportUuid: string): Promise<ApiResponse<Report>> {
  try {
    const query = {
      query: {
        term: {
          report_uuid: reportUuid,
        },
      },
    };

    const response = await esRequest<ElasticsearchResponse<Report>>('/vt_reports/_search', query);
    
    if (response.hits.hits.length === 0) {
      return {
        success: false,
        error: 'Report not found',
      };
    }

    return {
      success: true,
      data: response.hits.hits[0]._source,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch report',
    };
  }
}

export async function fetchAnalysisResults(reportUuid: string): Promise<ApiResponse<AnalysisResult[]>> {
  try {
    const query = {
      query: {
        term: {
          report_uuid: reportUuid,
        },
      },
      size: 1000,
    };

    const response = await esRequest<ElasticsearchResponse<AnalysisResult>>('/vt_analysis_results/_search', query);
    
    return {
      success: true,
      data: response.hits.hits.map(hit => hit._source),
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch analysis results',
    };
  }
}

export async function fetchSandboxVerdicts(reportUuid: string): Promise<ApiResponse<SandboxVerdict[]>> {
  try {
    const query = {
      query: {
        term: {
          report_uuid: reportUuid,
        },
      },
      size: 100,
    };

    const response = await esRequest<ElasticsearchResponse<SandboxVerdict>>('/vt_sandbox_verdicts/_search', query);
    
    return {
      success: true,
      data: response.hits.hits.map(hit => hit._source),
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch sandbox verdicts',
    };
  }
}

export async function fetchSandboxBehaviors(reportUuid: string): Promise<ApiResponse<SandboxBehavior[]>> {
  try {
    const query = {
      query: {
        term: {
          report_uuid: reportUuid,
        },
      },
      size: 1000,
      sort: [
        {
          severity: { order: 'desc' },
        },
        {
          event_count: { order: 'desc' },
        },
      ],
    };

    const response = await esRequest<ElasticsearchResponse<SandboxBehavior>>('/vt_sandbox_behaviors/_search', query);
    
    return {
      success: true,
      data: response.hits.hits.map(hit => hit._source),
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch sandbox behaviors',
    };
  }
}

function analyzeBehavioralData(behaviors: SandboxBehavior[]): BehavioralAnalysis {
  const severityBreakdown = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  const behaviorCategories = {
    process_activity: 0,
    file_operations: 0,
    network_activity: 0,
    registry_operations: 0,
    dll_loading: 0,
  };

  const processMap = new Map<string, { count: number; command_lines: string[] }>();
  const networkMap = new Map<string, { destination_port: number; protocol: string; count: number }>();
  const fileMap = new Map<string, { operation_type: string; count: number }>();
  const registryMap = new Map<string, { operation_type: string; count: number }>();
  const timeline: Array<{ timestamp: string; event_type: string; description: string; severity: string }> = [];

  behaviors.forEach(behavior => {
    // Count severity levels
    const severity = behavior.severity?.toLowerCase() || 'info';
    if (severity in severityBreakdown) {
      severityBreakdown[severity as keyof typeof severityBreakdown]++;
    } else {
      severityBreakdown.info++;
    }

    // Process behavioral events
    behavior.behavioral_events?.forEach(event => {
      // Categorize behaviors
      if (event.process_path || event.command_line) {
        behaviorCategories.process_activity++;
        
        if (event.process_path) {
          const existing = processMap.get(event.process_path) || { count: 0, command_lines: [] };
          existing.count++;
          if (event.command_line && !existing.command_lines.includes(event.command_line)) {
            existing.command_lines.push(event.command_line);
          }
          processMap.set(event.process_path, existing);
        }
      }

      if (event.target_file) {
        behaviorCategories.file_operations++;
        const key = event.target_file;
        const existing = fileMap.get(key) || { operation_type: 'file_access', count: 0 };
        existing.count++;
        fileMap.set(key, existing);
      }

      if (event.destination_ip || event.destination_port) {
        behaviorCategories.network_activity++;
        if (event.destination_ip) {
          const key = event.destination_ip;
          const existing = networkMap.get(key) || {
            destination_port: event.destination_port || 0,
            protocol: event.protocol || 'unknown',
            count: 0,
          };
          existing.count++;
          networkMap.set(key, existing);
        }
      }

      if (event.registry_key) {
        behaviorCategories.registry_operations++;
        const existing = registryMap.get(event.registry_key) || { operation_type: 'registry_access', count: 0 };
        existing.count++;
        registryMap.set(event.registry_key, existing);
      }

      if (event.loaded_image) {
        behaviorCategories.dll_loading++;
      }
    });

    // Add to timeline
    timeline.push({
      timestamp: behavior.index_time,
      event_type: behavior.analysis_type,
      description: behavior.rule_title || behavior.rule_description || 'Behavioral event detected',
      severity: behavior.severity || 'info',
    });
  });

  return {
    total_behaviors: behaviors.length,
    severity_breakdown: severityBreakdown,
    behavior_categories: behaviorCategories,
    top_processes: Array.from(processMap.entries())
      .map(([process_path, data]) => ({ process_path, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    network_connections: Array.from(networkMap.entries())
      .map(([destination_ip, data]) => ({ destination_ip, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    file_operations: Array.from(fileMap.entries())
      .map(([target_file, data]) => ({ target_file, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    registry_operations: Array.from(registryMap.entries())
      .map(([registry_key, data]) => ({ registry_key, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    behavioral_timeline: timeline.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).slice(0, 50),
  };
}

export async function fetchCrowdsourcedData(reportUuid: string): Promise<ApiResponse<CrowdsourcedData[]>> {
  try {
    const query = {
      query: {
        term: {
          report_uuid: reportUuid,
        },
      },
      size: 1000,
    };

    const response = await esRequest<ElasticsearchResponse<CrowdsourcedData>>('/vt_crowdsourced_data/_search', query);
    
    return {
      success: true,
      data: response.hits.hits.map(hit => hit._source),
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch crowdsourced data',
    };
  }
}

export async function fetchRelationships(reportUuid: string): Promise<ApiResponse<Relationship[]>> {
  try {
    const query = {
      query: {
        term: {
          report_uuid: reportUuid,
        },
      },
      size: 1000,
    };

    const response = await esRequest<ElasticsearchResponse<Relationship>>('/vt_relationships/_search', query);
    
    return {
      success: true,
      data: response.hits.hits.map(hit => hit._source),
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch relationships',
    };
  }
}

// Combined file analysis data
export async function fetchFileAnalysis(reportUuid: string): Promise<ApiResponse<FileAnalysis>> {
  try {
    const [reportResult, analysisResult, sandboxResult, behaviorResult, crowdsourcedResult, relationshipsResult] = await Promise.all([
      fetchReportById(reportUuid),
      fetchAnalysisResults(reportUuid),
      fetchSandboxVerdicts(reportUuid),
      fetchSandboxBehaviors(reportUuid),
      fetchCrowdsourcedData(reportUuid),
      fetchRelationships(reportUuid),
    ]);

    if (!reportResult.success || !reportResult.data) {
      return {
        success: false,
        error: reportResult.error || 'Report not found',
      };
    }

    const analysis_results = analysisResult.data || [];
    const sandbox_behaviors = behaviorResult.data || [];
    const behavioral_analysis = analyzeBehavioralData(sandbox_behaviors);
    
    const total = analysis_results.length;
    const malicious = analysis_results.filter(r => r.category.toLowerCase() === 'malicious').length;
    const suspicious = analysis_results.filter(r => r.category.toLowerCase() === 'suspicious').length;
    
    let score = 0;
    if (total > 0) {
      score = Math.round(((malicious * 2 + suspicious) / total) * 100);
    }
    
    // Factor in behavioral analysis for risk score
    const criticalBehaviors = behavioral_analysis.severity_breakdown.critical;
    const highBehaviors = behavioral_analysis.severity_breakdown.high;
    if (criticalBehaviors > 0) {
      score = Math.min(100, score + (criticalBehaviors * 10));
    }
    if (highBehaviors > 0) {
      score = Math.min(100, score + (highBehaviors * 5));
    }
    
    let level: 'Low' | 'Medium' | 'High' | 'Critical';
    if (score >= 80 || criticalBehaviors > 2) level = 'Critical';
    else if (score >= 50 || highBehaviors > 3) level = 'High';
    else if (score >= 20 || behavioral_analysis.total_behaviors > 5) level = 'Medium';
    else level = 'Low';

    return {
      success: true,
      data: {
        report: reportResult.data,
        analysis_results,
        sandbox_verdicts: sandboxResult.data || [],
        sandbox_behaviors,
        behavioral_analysis,
        crowdsourced_data: crowdsourcedResult.data || [],
        relationships: relationshipsResult.data || [],
        risk_score: {
          score,
          level,
        },
      },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch file analysis',
    };
  }
}

// Search with filters
export async function searchReports(filters: SearchFilters, page: number = 1, perPage: number = 20): Promise<ApiResponse<SearchResult>> {
  try {
    const from = (page - 1) * perPage;
    const mustQueries: any[] = [];

    // Build query based on filters
    if (filters.file_type?.length) {
      const fileTypeQuery = buildTermsQuery('file_type', filters.file_type);
      if (fileTypeQuery) mustQueries.push(fileTypeQuery);
    }

    if (filters.date_range) {
      const dateQuery = buildDateRangeQuery(filters.date_range);
      if (dateQuery) mustQueries.push(dateQuery);
    }

    if (filters.file_size_range) {
      mustQueries.push(buildRangeQuery('size', filters.file_size_range));
    }

    // Handle field-specific queries
    if (filters.field_queries) {
      Object.entries(filters.field_queries).forEach(([field, value]) => {
        // Map frontend field names to Elasticsearch field names
        const fieldMappings: Record<string, string> = {
          'file_name': 'meaningful_name',
          'hash': 'hash', // Special handling for generic hash searches
          'sha256': 'sha256',
          'sha1': 'sha1',
          'md5': 'md5',
          'file_type_query': 'type_description',
          'file_size': 'size',
          'author': 'office_info.summary_info.author',
          'creator': 'office_info.summary_info.author',
          'tag': 'tags',
          'magic': 'magic',
          'imphash': 'imphash',
          'ssdeep': 'ssdeep',
          'tlsh': 'tlsh',
          'application': 'office_info.summary_info.application_name',
          'title': 'office_info.summary_info.title',
          'subject': 'office_info.summary_info.subject',
          'company': 'office_info.summary_info.company',
          'manager': 'office_info.summary_info.manager',
          'category': 'office_info.summary_info.category',
          'keywords': 'office_info.summary_info.keywords',
          'comments': 'office_info.summary_info.comments',
          'template': 'office_info.summary_info.template',
          'last_modified_by': 'office_info.summary_info.last_author',
          'presentation_format': 'office_info.document_summary_info.presentation_format',
          'scale_crop': 'office_info.document_summary_info.scale_crop',
          'shared_doc': 'office_info.document_summary_info.shared_doc',
          'links_up_to_date': 'office_info.document_summary_info.links_up_to_date',
          'hyperlinks_changed': 'office_info.document_summary_info.hyperlinks_changed',
          // PE fields
          'signed': 'pe_info.signature_info',
          'signer': 'pe_info.signature_info.subject',
          'packer': 'pe_info.packers',
          'compiler': 'pe_info.compiler_product_versions',
          // PDF fields
          'javascript': 'pdf_info.js',
          'encrypted': 'pdf_info.encrypted',
          'forms': 'pdf_info.acroform',
          // Android fields
          'package': 'androguard.package_name',
          'permission': 'androguard.permissions',
          'activity': 'androguard.activities',
          // Timestamps and file properties
          'created': 'first_submission_date',
          'modified': 'last_modification_date',
          'timestamp': 'pe_info.timestamp',
          'entropy': 'pe_info.sections.entropy',
          'vhash': 'vhash',
          'authentihash': 'authentihash',
          'rich_header': 'pe_info.rich_header_hash',
        };
        
        const esField = fieldMappings[field] || field;
        
        // Special handling for generic hash field - search across all hash types
        if (esField === 'hash') {
          mustQueries.push({
            bool: {
              should: [
                { wildcard: { 'sha256': `*${value.toLowerCase()}*` } },
                { wildcard: { 'sha1': `*${value.toLowerCase()}*` } },
                { wildcard: { 'md5': `*${value.toLowerCase()}*` } },
                { prefix: { 'sha256': value.toLowerCase() } },
                { prefix: { 'sha1': value.toLowerCase() } },
                { prefix: { 'md5': value.toLowerCase() } },
                { term: { 'sha256': value.toLowerCase() } },
                { term: { 'sha1': value.toLowerCase() } },
                { term: { 'md5': value.toLowerCase() } },
              ],
              minimum_should_match: 1
            }
          });
        }
        // Use wildcard for file names and text fields
        else if (['meaningful_name', 'type_description', 'magic', 
             'office_info.summary_info.application_name', 
             'office_info.summary_info.title',
             'office_info.summary_info.subject',
             'office_info.summary_info.company',
             'office_info.summary_info.manager',
             'office_info.summary_info.category',
             'office_info.summary_info.keywords',
             'office_info.summary_info.comments',
             'office_info.summary_info.template',
             'office_info.summary_info.last_author',
             'office_info.document_summary_info.presentation_format'].includes(esField)) {
          mustQueries.push({
            wildcard: {
              [esField]: `*${value.toLowerCase()}*`
            }
          });
        } else if (esField === 'tags') {
          // For tags, use term query
          mustQueries.push({
            term: {
              [esField]: value
            }
          });
        } else if (['office_info.document_summary_info.scale_crop',
                    'office_info.document_summary_info.shared_doc',
                    'office_info.document_summary_info.links_up_to_date',
                    'office_info.document_summary_info.hyperlinks_changed',
                    'pdf_info.encrypted',
                    'pdf_info.acroform',
                    'pe_info.signature_info'].includes(esField)) {
          // For boolean/yes/no fields - handle multiple formats
          let boolValue: boolean;
          const lowerValue = value.toLowerCase();
          if (lowerValue === 'yes' || lowerValue === 'true' || lowerValue === '1') {
            boolValue = true;
          } else if (lowerValue === 'no' || lowerValue === 'false' || lowerValue === '0') {
            boolValue = false;
          } else {
            // Try to parse as a boolean string
            boolValue = value.toLowerCase() === 'yes' || value.toLowerCase() === 'true';
          }
          mustQueries.push({
            term: {
              [esField]: boolValue
            }
          });
        } else {
          // For hashes and exact matches
          mustQueries.push({
            term: {
              [esField]: value.toLowerCase()
            }
          });
        }
      });
    }
    
    // Handle numeric queries with operators
    if (filters.numeric_queries) {
      Object.entries(filters.numeric_queries).forEach(([field, query]) => {
        // Map frontend field names to Elasticsearch field names
        const numericFieldMappings: Record<string, string> = {
          'size': 'size',
          'pages': 'pdf_info.num_pages',
          'slides': 'office_info.document_summary_info.slide_count',
          'words': 'office_info.summary_info.word_count',
          'paragraphs': 'office_info.document_summary_info.paragraph_count',
          'detections': 'malicious',
          'malicious_count': 'malicious',
          'suspicious_count': 'suspicious',
          'revision': 'office_info.summary_info.revision_number',
          'streams': 'pdf_info.num_streams',
          'objects': 'pdf_info.num_objects',
          'hidden_slides': 'office_info.document_summary_info.hidden_slides',
          'notes': 'office_info.document_summary_info.note_count',
          'mm_clips': 'office_info.document_summary_info.mm_clips',
          'total_edit_time': 'office_info.summary_info.total_edit_time',
          'characters': 'office_info.summary_info.character_count',
          'lines': 'office_info.document_summary_info.line_count',
          'byte_count': 'office_info.document_summary_info.byte_count',
          'code_page': 'office_info.document_summary_info.code_page',
          'security': 'office_info.summary_info.security',
          'macros': 'office_info.macros.length',
          // PE numeric fields
          'entry_point': 'pe_info.entry_point',
          'machine_type': 'pe_info.machine_type',
          'sections': 'pe_info.sections.length',
          'imports': 'pe_info.import_list.length',
          'exports': 'pe_info.exports.length',
          'resources': 'pe_info.resources.length',
          'overlay_size': 'pe_info.overlay.size',
          // PDF numeric fields
          'js_count': 'pdf_info.num_js',
          'launch_count': 'pdf_info.num_launch',
          'embedded_files': 'pdf_info.embedded_files',
          // Android numeric fields
          'permission_count': 'androguard.permissions.length',
          'activity_count': 'androguard.activities.length',
          'service_count': 'androguard.services.length',
          'receiver_count': 'androguard.receivers.length',
          // Archive fields
          'contained_files': 'bundle_info.num_children',
          'compression_ratio': 'bundle_info.compression_ratio',
          // Other numeric fields
          'days_old': 'age_days',
          'times_submitted': 'times_submitted',
          'reputation': 'reputation',
          'votes': 'total_votes.malicious',
        };
        
        const esField = numericFieldMappings[field] || field;
        const { value, operator } = query;
        
        // Build range query based on operator
        let rangeQuery: any = {};
        switch (operator) {
          case '>':
            rangeQuery = { range: { [esField]: { gt: value } } };
            break;
          case '>=':
            rangeQuery = { range: { [esField]: { gte: value } } };
            break;
          case '<':
            rangeQuery = { range: { [esField]: { lt: value } } };
            break;
          case '<=':
            rangeQuery = { range: { [esField]: { lte: value } } };
            break;
          case '=':
          default:
            rangeQuery = { term: { [esField]: value } };
            break;
        }
        
        mustQueries.push(rangeQuery);
      });
    }
    
    // Handle general search query
    if (filters.search_query) {
      const searchQuery = filters.search_query.toLowerCase();
      
      // Check if it looks like a hash (for partial hash searches)
      const isHashLike = /^[a-f0-9]{8,}$/.test(searchQuery.replace(/^(0x|#)/, ''));
      
      if (isHashLike) {
        // For hash-like queries, search specifically in hash fields with wildcards
        mustQueries.push({
          bool: {
            should: [
              { wildcard: { 'sha256': `*${searchQuery}*` } },
              { wildcard: { 'sha1': `*${searchQuery}*` } },
              { wildcard: { 'md5': `*${searchQuery}*` } },
              { prefix: { 'sha256': searchQuery } },
              { prefix: { 'sha1': searchQuery } },
              { prefix: { 'md5': searchQuery } },
            ],
            minimum_should_match: 1
          }
        });
      } else {
        // For general text searches, use multi_match across multiple fields
        mustQueries.push({
          multi_match: {
            query: filters.search_query,
            fields: [
              'sha256^3',              // Higher boost for exact hash matches
              'sha1^3', 
              'md5^3',
              'meaningful_name^2',     // High boost for file names
              'names^2',              // Also search all known names
              'type_tag',
              'type_description', 
              'magic',
              'imphash',
              'ssdeep',
              'tlsh',
              'vhash',
              'authentihash',
              'tags'
            ],
            type: 'best_fields',
            fuzziness: 'AUTO',
          },
        });
      }
    }

    const query = {
      query: {
        bool: {
          must: mustQueries.length > 0 ? mustQueries : [{ match_all: {} }],
        },
      },
      sort: [
        {
          index_time: { order: 'desc' },
        },
      ],
      from,
      size: perPage,
    };

    const response = await esRequest<ElasticsearchResponse<Report>>('/vt_reports/_search', query);
    
    const reports = response.hits.hits.map(hit => hit._source);
    const total = response.hits.total.value;
    const totalPages = Math.ceil(total / perPage);

    return {
      success: true,
      data: {
        reports,
        total,
        page,
        per_page: perPage,
        total_pages: totalPages,
      },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to search reports',
    };
  }
}

// Dashboard statistics
export async function getDashboardStats(): Promise<ApiResponse<DashboardStats>> {
  try {
    const today = new Date().toISOString().split('T')[0];
    
    // Main stats query
    const statsQuery = {
      size: 0,
      aggs: {
        total_reports: {
          value_count: {
            field: 'report_uuid.keyword',
          },
        },
        reports_today: {
          filter: {
            range: {
              index_time: {
                gte: today,
                lt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().split('T')[0],
              },
            },
          },
        },
        file_types: {
          terms: {
            field: 'type_tag.keyword',
            size: 10,
          },
        },
        malicious_count: {
          filter: {
            range: {
              'last_analysis_stats.malicious': {
                gt: 0,
              },
            },
          },
        },
        clean_count: {
          filter: {
            range: {
              'last_analysis_stats.harmless': {
                gt: 0,
              },
            },
          },
        },
        suspicious_count: {
          filter: {
            range: {
              'last_analysis_stats.suspicious': {
                gt: 0,
              },
            },
          },
        },
        undetected_count: {
          filter: {
            range: {
              'last_analysis_stats.undetected': {
                gt: 0,
              },
            },
          },
        },
        daily_trends: {
          date_histogram: {
            field: 'index_time',
            calendar_interval: 'day',
            format: 'yyyy-MM-dd',
            order: {
              _key: 'desc',
            },
            min_doc_count: 0,
          },
          aggs: {
            malicious: {
              filter: {
                range: {
                  'last_analysis_stats.malicious': {
                    gt: 0,
                  },
                },
              },
            },
            suspicious: {
              filter: {
                range: {
                  'last_analysis_stats.suspicious': {
                    gt: 0,
                  },
                },
              },
            },
            clean: {
              filter: {
                range: {
                  'last_analysis_stats.harmless': {
                    gt: 0,
                  },
                },
              },
            },
            undetected: {
              filter: {
                range: {
                  'last_analysis_stats.undetected': {
                    gt: 0,
                  },
                },
              },
            },
          },
        },
      },
    };

    const [statsResponse, enginesResponse] = await Promise.all([
      esRequest<any>('/vt_reports/_search', statsQuery),
      esRequest<any>('/vt_analysis_results/_search', {
        size: 0,
        aggs: {
          top_engines: {
            terms: {
              field: 'engine_name',
              size: 10,
            },
            aggs: {
              detections: {
                filter: {
                  terms: {
                    category: ['malicious', 'suspicious'],
                  },
                },
              },
            },
          },
        },
      }),
    ]);

    const aggs = statsResponse.aggregations;

    return {
      success: true,
      data: {
        total_reports: aggs.total_reports.value || 0,
        reports_today: aggs.reports_today.doc_count || 0,
        malicious_files: aggs.malicious_count.doc_count || 0,
        clean_files: aggs.clean_count.doc_count || 0,
        suspicious_files: aggs.suspicious_count.doc_count || 0,
        undetected_files: aggs.undetected_count.doc_count || 0,
        top_file_types: aggs.file_types.buckets?.map((bucket: any) => ({
          type: bucket.key,
          count: bucket.doc_count,
        })) || [],
        detection_trends: aggs.daily_trends.buckets?.slice(0, 30).reverse().map((bucket: any) => ({
          date: bucket.key_as_string,
          malicious: bucket.malicious.doc_count,
          suspicious: bucket.suspicious.doc_count,
          clean: bucket.clean.doc_count,
          undetected: bucket.undetected.doc_count,
        })) || [],
        top_engines: enginesResponse.aggregations?.top_engines.buckets?.map((bucket: any) => ({
          engine: bucket.key,
          detections: bucket.detections.doc_count,
        })) || [],
        file_size_distribution: [], // Could be implemented with range aggregation
      },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to fetch dashboard stats',
    };
  }
}

// Advanced search functions for occurrence-based queries

export async function searchSimilarFilesByHash(fileHash: string, limit: number = 20): Promise<ApiResponse<Report[]>> {
  try {
    const query = {
      query: {
        bool: {
          should: [
            { fuzzy: { 'meaningful_name': { value: fileHash.slice(0, 8), fuzziness: 'AUTO' } } },
            { term: { 'type_tag.keyword': 'pe' } },
            { range: { 'size': { gte: 1000, lte: 10000000 } } }
          ],
          must_not: [
            { term: { 'file_hash.keyword': fileHash } }
          ],
          minimum_should_match: 1
        }
      },
      size: limit,
      sort: [{ '_score': { order: 'desc' } }]
    };

    const response = await esRequest<ElasticsearchResponse<Report>>('/vt_reports/_search', query);
    
    return {
      success: true,
      data: response.hits.hits.map(hit => hit._source),
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to search similar files',
    };
  }
}

export async function searchFilesByYaraRuleMatches(reportUuid: string, limit: number = 20): Promise<ApiResponse<Report[]>> {
  try {
    // First, get the YARA rules that matched this report
    const crowdsourcedQuery = {
      query: {
        bool: {
          must: [
            { term: { report_uuid: reportUuid } },
            { wildcard: { 'source': '*yara*' } }
          ]
        }
      },
      size: 50
    };

    const crowdsourcedResponse = await esRequest<ElasticsearchResponse<CrowdsourcedData>>('/vt_crowdsourced_data/_search', crowdsourcedQuery);
    
    if (!crowdsourcedResponse.hits.hits.length) {
      return { success: true, data: [] };
    }

    // Extract rule names
    const ruleNames = crowdsourcedResponse.hits.hits
      .map(hit => hit._source.rule_name)
      .filter(name => name)
      .slice(0, 10);

    if (!ruleNames.length) {
      return { success: true, data: [] };
    }

    // Find other reports that match these rules
    const reportsQuery = {
      query: {
        bool: {
          must: [
            {
              nested: {
                path: 'crowdsourced_data',
                query: {
                  bool: {
                    should: ruleNames.map(ruleName => ({
                      term: { 'crowdsourced_data.rule_name.keyword': ruleName }
                    }))
                  }
                }
              }
            }
          ],
          must_not: [
            { term: { report_uuid: reportUuid } }
          ]
        }
      },
      size: limit
    };

    const reportsResponse = await esRequest<ElasticsearchResponse<Report>>('/vt_reports/_search', reportsQuery);
    
    return {
      success: true,
      data: reportsResponse.hits.hits.map(hit => hit._source),
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to search YARA rule matches',
    };
  }
}

export async function searchFilesByCampaign(reportUuid: string, limit: number = 20): Promise<ApiResponse<Report[]>> {
  try {
    // First, get campaign relationships for this report
    const relationshipsQuery = {
      query: {
        bool: {
          must: [
            { term: { report_uuid: reportUuid } },
            { terms: { 'relation_type.keyword': ['campaign', 'family'] } }
          ]
        }
      },
      size: 10
    };

    const relationshipsResponse = await esRequest<ElasticsearchResponse<Relationship>>('/vt_relationships/_search', relationshipsQuery);
    
    if (!relationshipsResponse.hits.hits.length) {
      return { success: true, data: [] };
    }

    // Extract campaign/family identifiers
    const campaignIds = relationshipsResponse.hits.hits
      .map(hit => hit._source.target_id)
      .filter(id => id);

    if (!campaignIds.length) {
      return { success: true, data: [] };
    }

    // Find other reports in the same campaigns/families
    const reportsQuery = {
      query: {
        bool: {
          must: [
            {
              nested: {
                path: 'relationships',
                query: {
                  bool: {
                    should: campaignIds.map(id => ({
                      term: { 'relationships.target_id.keyword': id }
                    }))
                  }
                }
              }
            }
          ],
          must_not: [
            { term: { report_uuid: reportUuid } }
          ]
        }
      },
      size: limit
    };

    const reportsResponse = await esRequest<ElasticsearchResponse<Report>>('/vt_reports/_search', reportsQuery);
    
    return {
      success: true,
      data: reportsResponse.hits.hits.map(hit => hit._source),
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to search campaign-related files',
    };
  }
}