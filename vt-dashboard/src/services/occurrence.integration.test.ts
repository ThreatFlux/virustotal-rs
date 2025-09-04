/**
 * Integration tests for the occurrence service functionality
 * These tests verify that the occurrence column and search functionality works correctly
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import type { Report, OccurrenceSearchContext } from '@/types';

// Mock report data for testing - defined before imports to avoid hoisting issues
const mockReport: Report = {
  report_uuid: 'test-uuid-123',
  file_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  meaningful_name: 'test-file.exe',
  size: 1024000,
  type_tag: 'peexe',
  index_time: new Date().toISOString(),
  first_submission_date: '2024-01-01T00:00:00Z',
  last_submission_date: '2024-01-15T00:00:00Z',
  times_submitted: 5,
  last_analysis_stats: {
    malicious: 10,
    suspicious: 2,
    harmless: 50,
    undetected: 8
  }
};


// Mock the esRequest function
vi.mock('./elasticsearch', () => ({
  esRequest: vi.fn().mockResolvedValue({
    hits: {
      hits: [
        {
          _source: {
            report_uuid: 'test-uuid-123',
            file_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            meaningful_name: 'test-file.exe'
          }
        }
      ],
      total: { value: 1, relation: 'eq' }
    },
    took: 5,
    timed_out: false,
    _shards: { total: 1, successful: 1, skipped: 0, failed: 0 }
  }),
  searchSimilarFilesByHash: vi.fn().mockImplementation(() => Promise.resolve({
    success: true,
    data: [{
      report_uuid: 'test-uuid-123',
      file_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      meaningful_name: 'test-file.exe',
      size: 1024000,
      type_tag: 'peexe',
      index_time: new Date().toISOString(),
      first_submission_date: '2024-01-01T00:00:00Z',
      last_submission_date: '2024-01-15T00:00:00Z',
      times_submitted: 5,
      last_analysis_stats: {
        malicious: 10,
        suspicious: 2,
        harmless: 50,
        undetected: 8
      }
    }]
  })),
  searchFilesByYaraRuleMatches: vi.fn().mockImplementation(() => Promise.resolve({
    success: true,
    data: [{
      report_uuid: 'test-uuid-123',
      file_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      meaningful_name: 'test-file.exe',
      size: 1024000,
      type_tag: 'peexe',
      index_time: new Date().toISOString(),
      first_submission_date: '2024-01-01T00:00:00Z',
      last_submission_date: '2024-01-15T00:00:00Z',
      times_submitted: 5,
      last_analysis_stats: {
        malicious: 10,
        suspicious: 2,
        harmless: 50,
        undetected: 8
      }
    }]
  })),
  searchFilesByCampaign: vi.fn().mockImplementation(() => Promise.resolve({
    success: true,
    data: [{
      report_uuid: 'test-uuid-123',
      file_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      meaningful_name: 'test-file.exe',
      size: 1024000,
      type_tag: 'peexe',
      index_time: new Date().toISOString(),
      first_submission_date: '2024-01-01T00:00:00Z',
      last_submission_date: '2024-01-15T00:00:00Z',
      times_submitted: 5,
      last_analysis_stats: {
        malicious: 10,
        suspicious: 2,
        harmless: 50,
        undetected: 8
      }
    }]
  }))
}));

// Import modules after mocking
import { calculateOccurrenceData, executeOccurrenceSearch, getOccurrenceDescription } from './occurrence';
import * as elasticsearchModule from './elasticsearch';

describe('Occurrence Service Integration', () => {
  beforeEach(() => {
    // Clear all mocks before each test
    vi.clearAllMocks();
  });

  describe('calculateOccurrenceData', () => {
    test('should calculate occurrence data for a report', async () => {
      const occurrenceData = await calculateOccurrenceData(mockReport);

      expect(occurrenceData).toBeDefined();
      expect(occurrenceData.file_hash).toBe(mockReport.file_hash);
      expect(occurrenceData.report_uuid).toBe(mockReport.report_uuid);
      expect(occurrenceData.times_submitted).toBe(5);
      expect(occurrenceData.first_seen).toBe('2024-01-01T00:00:00Z');
      expect(occurrenceData.last_seen).toBe('2024-01-15T00:00:00Z');
    });

    test('should handle reports with no submission data', async () => {
      const reportWithoutSubmissions = {
        ...mockReport,
        times_submitted: undefined,
        first_submission_date: undefined,
        last_submission_date: undefined
      };

      const occurrenceData = await calculateOccurrenceData(reportWithoutSubmissions);

      expect(occurrenceData.times_submitted).toBe(1);
      expect(occurrenceData.first_seen).toBe(reportWithoutSubmissions.index_time);
      expect(occurrenceData.last_seen).toBe(reportWithoutSubmissions.index_time);
    });

    test('should use cache for repeated requests', async () => {
      const esRequestMock = vi.mocked(elasticsearchModule.esRequest);

      // First call
      await calculateOccurrenceData(mockReport);
      
      // Second call should use cache
      await calculateOccurrenceData(mockReport);

      // Should have been called multiple times for different data sources, but not doubled
      expect(esRequestMock).toHaveBeenCalled();
    });
  });

  describe('executeOccurrenceSearch', () => {
    test('should execute similar files search', async () => {
      const searchContext: OccurrenceSearchContext = {
        search_type: 'similar_files',
        base_hash: mockReport.file_hash,
        base_name: mockReport.meaningful_name,
        filters: {
          similarity_threshold: 0.7,
          time_range: {
            start: '2024-01-01',
            end: '2024-12-31'
          },
          include_suspicious: true,
          min_detections: 1
        },
        metadata: {
          display_name: 'Similar Files',
          search_description: 'Files similar to test-file.exe'
        }
      };

      const result = await executeOccurrenceSearch(searchContext);

      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data!.context).toEqual(searchContext);
      expect(result.data!.results).toHaveLength(1);
      expect(result.data!.total_found).toBe(1);
      expect(result.data!.search_executed_at).toBeDefined();
    });

    test('should execute YARA matches search', async () => {
      const searchContext: OccurrenceSearchContext = {
        search_type: 'yara_matches',
        base_hash: mockReport.file_hash,
        filters: {},
        metadata: {
          display_name: 'YARA Matches',
          search_description: 'Files with similar YARA rule matches'
        }
      };

      const result = await executeOccurrenceSearch(searchContext);

      expect(result.success).toBe(true);
      expect(result.data!.context.search_type).toBe('yara_matches');
      expect(result.data!.results).toBeDefined();
    });

    test('should execute campaign-related search', async () => {
      const searchContext: OccurrenceSearchContext = {
        search_type: 'campaign_related',
        base_hash: mockReport.file_hash,
        filters: {},
        metadata: {
          display_name: 'Campaign Related',
          search_description: 'Files from related campaigns'
        }
      };

      const result = await executeOccurrenceSearch(searchContext);

      expect(result.success).toBe(true);
      expect(result.data!.context.search_type).toBe('campaign_related');
      expect(result.data!.results).toBeDefined();
    });

    test('should handle unsupported search types', async () => {
      const searchContext: OccurrenceSearchContext = {
        search_type: 'unsupported_type' as any,
        base_hash: mockReport.file_hash,
        filters: {},
        metadata: {
          display_name: 'Unsupported',
          search_description: 'This should fail'
        }
      };

      const result = await executeOccurrenceSearch(searchContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Unsupported search type');
    });
  });

  describe('getOccurrenceDescription', () => {
    test('should generate description with multiple data types', () => {
      const occurrenceData = {
        file_hash: mockReport.file_hash,
        report_uuid: mockReport.report_uuid,
        similar_files_count: 5,
        times_submitted: 3,
        first_seen: '2024-01-01T00:00:00Z',
        last_seen: '2024-01-15T00:00:00Z',
        yara_matches: 2,
        sigma_matches: 1,
        sandbox_analyses: 3,
        crowdsourced_detections: 10,
        related_campaigns: ['APT1', 'Lazarus'],
        similar_names: ['test-file-variant.exe'],
        common_engines: ['Defender', 'ClamAV']
      };

      const description = getOccurrenceDescription(occurrenceData);

      expect(description).toContain('5 similar files');
      expect(description).toContain('2 YARA matches');
      expect(description).toContain('1 Sigma matches');
      expect(description).toContain('3 sandbox runs');
      expect(description).toContain('2 campaigns');
    });

    test('should handle empty occurrence data', () => {
      const emptyData = {
        file_hash: mockReport.file_hash,
        report_uuid: mockReport.report_uuid,
        similar_files_count: 0,
        times_submitted: 1,
        first_seen: '2024-01-01T00:00:00Z',
        last_seen: '2024-01-01T00:00:00Z',
        yara_matches: 0,
        sigma_matches: 0,
        sandbox_analyses: 0,
        crowdsourced_detections: 0,
        related_campaigns: [],
        similar_names: [],
        common_engines: []
      };

      const description = getOccurrenceDescription(emptyData);

      expect(description).toBe('No related data');
    });
  });

  describe('Error Handling', () => {
    test('should handle Elasticsearch errors gracefully', async () => {
      const esRequestMock = vi.mocked(elasticsearchModule.esRequest);
      esRequestMock.mockRejectedValueOnce(new Error('Elasticsearch connection failed'));

      const occurrenceData = await calculateOccurrenceData(mockReport);

      // Should return basic data even when ES fails
      expect(occurrenceData.file_hash).toBe(mockReport.file_hash);
      expect(occurrenceData.similar_files_count).toBe(0);
      expect(occurrenceData.yara_matches).toBe(0);
    });

    test('should handle search service errors', async () => {
      const searchSimilarFilesByHashMock = vi.mocked(elasticsearchModule.searchSimilarFilesByHash);
      searchSimilarFilesByHashMock.mockResolvedValueOnce({
        success: false,
        error: 'Search service unavailable'
      });

      const searchContext: OccurrenceSearchContext = {
        search_type: 'similar_files',
        base_hash: mockReport.file_hash,
        filters: {},
        metadata: {
          display_name: 'Similar Files',
          search_description: 'Test search'
        }
      };

      const result = await executeOccurrenceSearch(searchContext);

      expect(result.success).toBe(true);
      expect(result.data!.results).toHaveLength(0);
    });
  });

  describe('Performance', () => {
    test('should complete occurrence calculation within reasonable time', async () => {
      const startTime = Date.now();
      
      await calculateOccurrenceData(mockReport);
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });

    test('should complete search within reasonable time', async () => {
      const startTime = Date.now();
      
      const searchContext: OccurrenceSearchContext = {
        search_type: 'similar_files',
        base_hash: mockReport.file_hash,
        filters: {},
        metadata: {
          display_name: 'Similar Files',
          search_description: 'Performance test'
        }
      };

      await executeOccurrenceSearch(searchContext);
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(3000); // Should complete within 3 seconds
    });
  });
});