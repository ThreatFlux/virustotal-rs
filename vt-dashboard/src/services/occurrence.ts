import type {
  Report,
  OccurrenceData,
  OccurrenceSearchContext,
  OccurrenceSearchResult,
  CrowdsourcedData,
  SandboxBehavior,
  Relationship,
  ApiResponse,
  ElasticsearchResponse,
} from '@/types';
import { 
  esRequest,
  searchSimilarFilesByHash,
  searchFilesByYaraRuleMatches,
  searchFilesByCampaign
} from './elasticsearch';

/**
 * Service for managing occurrence data and similarity searches
 * Provides methods to find similar files, YARA matches, behavioral patterns, etc.
 */

// Cache for occurrence data to avoid repeated expensive queries
const occurrenceCache = new Map<string, { data: OccurrenceData; timestamp: number }>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Calculate occurrence data for a given report
 * Aggregates data from multiple sources: submissions, YARA/Sigma matches, relationships, etc.
 */
export async function calculateOccurrenceData(report: Report): Promise<OccurrenceData> {
  const cacheKey = report.file_hash;
  const cached = occurrenceCache.get(cacheKey);
  
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }

  try {
    // Fetch related data in parallel
    const [similarFiles, crowdsourcedData, relationships, sandboxBehaviors] = await Promise.all([
      findSimilarFilesByHash(report.file_hash),
      fetchCrowdsourcedMatches(report.report_uuid),
      fetchFileRelationships(report.report_uuid),
      fetchSandboxBehaviorMatches(report.file_hash),
    ]);

    // Extract YARA and Sigma matches from crowdsourced data
    const yaraMatches = crowdsourcedData.filter(d => 
      d.source?.toLowerCase().includes('yara') || d.data_type?.toLowerCase().includes('yara')
    ).length;

    const sigmaMatches = crowdsourcedData.filter(d => 
      d.source?.toLowerCase().includes('sigma') || d.data_type?.toLowerCase().includes('sigma')  
    ).length;

    // Get related campaigns from relationships
    const campaigns = relationships
      .filter(r => r.relation_type === 'campaign' || r.relation_type === 'family')
      .map(r => r.target_id)
      .filter((v, i, a) => a.indexOf(v) === i); // unique values

    // Extract similar names from relationships or similar files
    const similarNames = relationships
      .filter(r => r.relation_type === 'similar_file')
      .map(r => r.context || '')
      .filter(name => name && name !== report.meaningful_name)
      .slice(0, 10); // limit to 10

    // Get common detection engines from analysis results (would need to fetch separately in real implementation)
    const commonEngines: string[] = []; // Placeholder - would aggregate from analysis results

    const occurrenceData: OccurrenceData = {
      file_hash: report.file_hash,
      report_uuid: report.report_uuid,
      similar_files_count: similarFiles.length,
      times_submitted: report.times_submitted || 1,
      first_seen: report.first_submission_date || report.index_time,
      last_seen: report.last_submission_date || report.index_time,
      yara_matches: yaraMatches,
      sigma_matches: sigmaMatches,
      sandbox_analyses: sandboxBehaviors.length,
      crowdsourced_detections: crowdsourcedData.length,
      related_campaigns: campaigns,
      similar_names: similarNames,
      common_engines: commonEngines,
      family_classification: extractFamilyClassification(relationships, crowdsourcedData),
      threat_category: extractThreatCategory(report, relationships),
    };

    // Cache the result
    occurrenceCache.set(cacheKey, { data: occurrenceData, timestamp: Date.now() });
    
    return occurrenceData;
  } catch (error) {
    console.error('Error calculating occurrence data:', error);
    // Return basic data if calculation fails
    return {
      file_hash: report.file_hash,
      report_uuid: report.report_uuid,
      similar_files_count: 0,
      times_submitted: report.times_submitted || 1,
      first_seen: report.first_submission_date || report.index_time,
      last_seen: report.last_submission_date || report.index_time,
      yara_matches: 0,
      sigma_matches: 0,
      sandbox_analyses: 0,
      crowdsourced_detections: 0,
      related_campaigns: [],
      similar_names: [],
      common_engines: [],
    };
  }
}

/**
 * Execute an occurrence-based search
 */
export async function executeOccurrenceSearch(context: OccurrenceSearchContext): Promise<ApiResponse<OccurrenceSearchResult>> {
  try {
    let results: Report[] = [];
    const relatedIndicators = {
      hashes: [] as string[],
      file_names: [] as string[],
      yara_rules: [] as string[],
      campaigns: [] as string[],
    };

    switch (context.search_type) {
      case 'similar_files':
        results = await searchSimilarFiles(context);
        break;
      case 'same_family':
        results = await searchSameFamily(context);
        break;
      case 'yara_matches':
        results = await searchYaraMatches(context);
        break;
      case 'sigma_matches':
        results = await searchSigmaMatches(context);
        break;
      case 'campaign_related':
        results = await searchCampaignRelated(context);
        break;
      case 'engine_pattern':
        results = await searchEnginePattern(context);
        break;
      case 'behavioral_similarity':
        results = await searchBehavioralSimilarity(context);
        break;
      default:
        throw new Error(`Unsupported search type: ${context.search_type}`);
    }

    // Extract related indicators from results
    results.forEach(report => {
      if (report.file_hash) relatedIndicators.hashes.push(report.file_hash);
      if (report.meaningful_name) relatedIndicators.file_names.push(report.meaningful_name);
    });

    return {
      success: true,
      data: {
        context,
        results,
        total_found: results.length,
        search_executed_at: new Date().toISOString(),
        related_indicators: relatedIndicators,
      },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Occurrence search failed',
    };
  }
}

// Helper functions for different search types

async function findSimilarFilesByHash(fileHash: string): Promise<Report[]> {
  try {
    const query = {
      query: {
        bool: {
          should: [
            { term: { sha256: fileHash } },
            { term: { sha1: fileHash } },
            { term: { md5: fileHash } },
            { term: { 'file_hash.keyword': fileHash } },
          ],
          minimum_should_match: 1,
        },
      },
      size: 50,
    };

    const response = await esRequest<ElasticsearchResponse<Report>>('/vt_reports/_search', query);
    return response.hits.hits.map(hit => hit._source);
  } catch (error) {
    console.error('Error finding similar files:', error);
    return [];
  }
}

async function fetchCrowdsourcedMatches(reportUuid: string): Promise<CrowdsourcedData[]> {
  try {
    const query = {
      query: {
        term: { report_uuid: reportUuid },
      },
      size: 100,
    };

    const response = await esRequest<ElasticsearchResponse<CrowdsourcedData>>('/vt_crowdsourced_data/_search', query);
    return response.hits.hits.map(hit => hit._source);
  } catch (error) {
    console.error('Error fetching crowdsourced matches:', error);
    return [];
  }
}

async function fetchFileRelationships(reportUuid: string): Promise<Relationship[]> {
  try {
    const query = {
      query: {
        term: { report_uuid: reportUuid },
      },
      size: 100,
    };

    const response = await esRequest<ElasticsearchResponse<Relationship>>('/vt_relationships/_search', query);
    return response.hits.hits.map(hit => hit._source);
  } catch (error) {
    console.error('Error fetching relationships:', error);
    return [];
  }
}

async function fetchSandboxBehaviorMatches(fileHash: string): Promise<SandboxBehavior[]> {
  try {
    const query = {
      query: {
        term: { file_hash: fileHash },
      },
      size: 100,
    };

    const response = await esRequest<ElasticsearchResponse<SandboxBehavior>>('/vt_sandbox_behaviors/_search', query);
    return response.hits.hits.map(hit => hit._source);
  } catch (error) {
    console.error('Error fetching sandbox behaviors:', error);
    return [];
  }
}

async function searchSimilarFiles(context: OccurrenceSearchContext): Promise<Report[]> {
  try {
    const response = await searchSimilarFilesByHash(context.base_hash, 20);
    return response.success ? response.data || [] : [];
  } catch (error) {
    console.error('Error searching similar files:', error);
    return [];
  }
}

async function searchSameFamily(context: OccurrenceSearchContext): Promise<Report[]> {
  // Implementation would search for files with same malware family classification
  return [];
}

async function searchYaraMatches(context: OccurrenceSearchContext): Promise<Report[]> {
  try {
    // We need to find a report UUID first - use context.base_hash to find the report
    const reportQuery = {
      query: { term: { 'file_hash.keyword': context.base_hash } },
      size: 1
    };
    
    const reportResponse = await esRequest<ElasticsearchResponse<Report>>('/vt_reports/_search', reportQuery);
    
    if (!reportResponse.hits.hits.length) return [];
    
    const reportUuid = reportResponse.hits.hits[0]._source.report_uuid;
    const response = await searchFilesByYaraRuleMatches(reportUuid, 20);
    return response.success ? response.data || [] : [];
  } catch (error) {
    console.error('Error searching YARA matches:', error);
    return [];
  }
}

async function searchSigmaMatches(context: OccurrenceSearchContext): Promise<Report[]> {
  // Implementation would search for files with same Sigma rule matches
  return [];
}

async function searchCampaignRelated(context: OccurrenceSearchContext): Promise<Report[]> {
  try {
    // We need to find a report UUID first - use context.base_hash to find the report
    const reportQuery = {
      query: { term: { 'file_hash.keyword': context.base_hash } },
      size: 1
    };
    
    const reportResponse = await esRequest<ElasticsearchResponse<Report>>('/vt_reports/_search', reportQuery);
    
    if (!reportResponse.hits.hits.length) return [];
    
    const reportUuid = reportResponse.hits.hits[0]._source.report_uuid;
    const response = await searchFilesByCampaign(reportUuid, 20);
    return response.success ? response.data || [] : [];
  } catch (error) {
    console.error('Error searching campaign-related files:', error);
    return [];
  }
}

async function searchEnginePattern(context: OccurrenceSearchContext): Promise<Report[]> {
  // Implementation would search for files with similar detection patterns
  return [];
}

async function searchBehavioralSimilarity(context: OccurrenceSearchContext): Promise<Report[]> {
  // Implementation would search for files with similar sandbox behaviors
  return [];
}

function extractFamilyClassification(relationships: Relationship[], crowdsourced: CrowdsourcedData[]): string | undefined {
  // Look for family classification in relationships or crowdsourced data
  const familyRelation = relationships.find(r => r.relation_type === 'family');
  if (familyRelation) {
    return familyRelation.target_id;
  }

  // Check crowdsourced data for family information
  const familyData = crowdsourced.find(d => 
    d.data_type?.toLowerCase().includes('family') || 
    d.rule_name?.toLowerCase().includes('family')
  );
  
  return familyData?.rule_name;
}

function extractThreatCategory(report: Report, relationships: Relationship[]): string | undefined {
  // Extract threat category from report or relationships
  const threatRelation = relationships.find(r => r.relation_type === 'threat_category');
  if (threatRelation) {
    return threatRelation.target_id;
  }

  // Infer from file type or other indicators
  if (report.type_tag?.includes('exe') || report.type_tag?.includes('pe')) {
    return 'Executable';
  } else if (report.type_tag?.includes('pdf')) {
    return 'Document';
  } else if (report.type_tag?.includes('zip') || report.type_tag?.includes('rar')) {
    return 'Archive';
  }

  return undefined;
}

/**
 * Get a human-readable description for occurrence data
 */
export function getOccurrenceDescription(data: OccurrenceData): string {
  const parts = [];
  
  if (data.similar_files_count > 0) {
    parts.push(`${data.similar_files_count} similar files`);
  }
  
  if (data.yara_matches > 0) {
    parts.push(`${data.yara_matches} YARA matches`);
  }
  
  if (data.sigma_matches > 0) {
    parts.push(`${data.sigma_matches} Sigma matches`);
  }
  
  if (data.sandbox_analyses > 0) {
    parts.push(`${data.sandbox_analyses} sandbox runs`);
  }

  if (data.related_campaigns.length > 0) {
    parts.push(`${data.related_campaigns.length} campaigns`);
  }

  if (parts.length === 0) {
    return 'No related data';
  }

  return parts.join(', ');
}

/**
 * Get occurrence display priority score (higher = more important to show)
 */
export function getOccurrencePriority(data: OccurrenceData): number {
  let score = 0;
  
  score += Math.min(data.similar_files_count, 10) * 2;
  score += data.yara_matches * 5;
  score += data.sigma_matches * 5;
  score += data.sandbox_analyses * 3;
  score += data.related_campaigns.length * 10;
  score += Math.min(data.times_submitted, 100);
  
  return score;
}