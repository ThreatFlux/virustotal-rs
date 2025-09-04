import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  fetchReports,
  fetchReportById,
  fetchAnalysisResults,
  getDashboardStats,
} from './elasticsearch';

// Mock fetch globally
global.fetch = vi.fn();

describe('Elasticsearch Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('fetchReports', () => {
    it('should fetch reports successfully', async () => {
      const mockResponse = {
        hits: {
          hits: [
            {
              _source: {
                report_uuid: 'test-uuid-1',
                file_hash: 'abc123',
                meaningful_name: 'test.exe',
                type_tag: 'peexe',
                size: 1024,
                last_analysis_stats: {
                  malicious: 5,
                  suspicious: 2,
                  harmless: 50,
                  undetected: 10
                }
              }
            }
          ],
          total: { value: 369 }
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await fetchReports(1, 20);

      expect(result.success).toBe(true);
      expect(result.data?.reports).toHaveLength(1);
      expect(result.data?.total).toBe(369);
      expect(result.data?.reports[0].file_hash).toBe('abc123');
    });

    it('should handle fetch errors gracefully', async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error'
      });

      const result = await fetchReports(1, 20);

      expect(result.success).toBe(false);
      expect(result.error).toContain('500');
    });
  });

  describe('fetchReportById', () => {
    it('should fetch a specific report by UUID', async () => {
      const mockResponse = {
        hits: {
          hits: [
            {
              _source: {
                report_uuid: 'test-uuid-1',
                file_hash: 'abc123',
                meaningful_name: 'malware.exe',
                type_tag: 'peexe',
                size: 2048
              }
            }
          ]
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await fetchReportById('test-uuid-1');

      expect(result.success).toBe(true);
      expect(result.data?.report_uuid).toBe('test-uuid-1');
      expect(result.data?.file_hash).toBe('abc123');
    });

    it('should return error when report not found', async () => {
      const mockResponse = {
        hits: {
          hits: []
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await fetchReportById('non-existent');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Report not found');
    });
  });

  describe('fetchAnalysisResults', () => {
    it('should fetch analysis results for a report', async () => {
      const mockResponse = {
        hits: {
          hits: [
            {
              _source: {
                report_uuid: 'test-uuid-1',
                engine_name: 'Kaspersky',
                category: 'malicious',
                result: 'Trojan.Win32.Generic'
              }
            },
            {
              _source: {
                report_uuid: 'test-uuid-1',
                engine_name: 'McAfee',
                category: 'malicious',
                result: 'GenericTrojan'
              }
            }
          ]
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await fetchAnalysisResults('test-uuid-1');

      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(2);
      expect(result.data?.[0].engine_name).toBe('Kaspersky');
      expect(result.data?.[1].engine_name).toBe('McAfee');
    });
  });

  describe('getDashboardStats', () => {
    it('should fetch dashboard statistics', async () => {
      const mockStatsResponse = {
        aggregations: {
          total_reports: { value: 369 },
          reports_today: { doc_count: 15 },
          file_types: {
            buckets: [
              { key: 'peexe', doc_count: 200 },
              { key: 'pdf', doc_count: 100 },
              { key: 'doc', doc_count: 69 }
            ]
          },
          malicious_count: { doc_count: 150 },
          clean_count: { doc_count: 180 },
          suspicious_count: { doc_count: 20 },
          undetected_count: { doc_count: 19 },
          daily_trends: {
            buckets: []
          }
        }
      };

      const mockEnginesResponse = {
        aggregations: {
          top_engines: {
            buckets: [
              { key: 'Kaspersky', malicious: { doc_count: 100 } },
              { key: 'McAfee', malicious: { doc_count: 95 } }
            ]
          }
        }
      };

      (global.fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => mockStatsResponse
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => mockEnginesResponse
        });

      const result = await getDashboardStats();

      expect(result.success).toBe(true);
      expect(result.data?.total_reports).toBe(369);
      expect(result.data?.reports_today).toBe(15);
      expect(result.data?.malicious_files).toBe(150);
      expect(result.data?.clean_files).toBe(180);
      expect(result.data?.file_types).toHaveLength(3);
      expect(result.data?.file_types[0].name).toBe('peexe');
    });
  });
});