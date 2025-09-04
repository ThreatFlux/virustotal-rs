import { describe, it, expect } from 'vitest';
import {
  fetchReports,
  fetchReportById,
  fetchAnalysisResults,
  getDashboardStats,
  searchReports,
} from './elasticsearch';

/**
 * Integration tests that validate against real Elasticsearch data
 * These tests require Elasticsearch to be running on localhost:9200
 * with VirusTotal data indexed
 */
describe('Elasticsearch Integration Tests', () => {
  const EXPECTED_TOTAL_REPORTS = 369;
  const EXPECTED_ANALYSIS_RESULTS = 28474;
  
  describe('Real Data Validation', () => {
    it('should fetch exactly 369 reports from vt_reports index', async () => {
      const result = await fetchReports(1, 100);
      
      expect(result.success).toBe(true);
      expect(result.data?.total).toBe(EXPECTED_TOTAL_REPORTS);
      expect(result.data?.reports).toBeDefined();
      expect(result.data?.reports.length).toBeLessThanOrEqual(100);
    });

    it('should have all required fields in report data', async () => {
      const result = await fetchReports(1, 1);
      
      expect(result.success).toBe(true);
      const report = result.data?.reports[0];
      
      // Validate essential fields exist
      expect(report).toHaveProperty('report_uuid');
      expect(report).toHaveProperty('file_hash');
      expect(report).toHaveProperty('index_time');
      expect(report).toHaveProperty('last_analysis_stats');
      
      // Validate last_analysis_stats structure
      const stats = report?.last_analysis_stats;
      expect(stats).toHaveProperty('malicious');
      expect(stats).toHaveProperty('suspicious');
      expect(stats).toHaveProperty('harmless');
      expect(stats).toHaveProperty('undetected');
    });

    it('should fetch analysis results for a report', async () => {
      // First get a report to get its UUID
      const reportResult = await fetchReports(1, 1);
      const reportUuid = reportResult.data?.reports[0]?.report_uuid;
      
      if (reportUuid) {
        const analysisResult = await fetchAnalysisResults(reportUuid);
        
        expect(analysisResult.success).toBe(true);
        expect(Array.isArray(analysisResult.data)).toBe(true);
        
        // Each analysis result should have required fields
        if (analysisResult.data && analysisResult.data.length > 0) {
          const firstResult = analysisResult.data[0];
          expect(firstResult).toHaveProperty('report_uuid');
          expect(firstResult).toHaveProperty('engine_name');
          expect(firstResult).toHaveProperty('category');
          expect(firstResult.report_uuid).toBe(reportUuid);
        }
      }
    });

    it('should get accurate dashboard statistics', async () => {
      const result = await getDashboardStats();
      
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      
      // Validate stats match expected data
      expect(result.data?.total_reports).toBe(EXPECTED_TOTAL_REPORTS);
      
      // Validate file types aggregation
      expect(result.data?.file_types).toBeDefined();
      expect(Array.isArray(result.data?.file_types)).toBe(true);
      
      // Each file type should have name and value
      result.data?.file_types.forEach(fileType => {
        expect(fileType).toHaveProperty('name');
        expect(fileType).toHaveProperty('value');
        expect(typeof fileType.value).toBe('number');
      });
      
      // Validate malicious/clean/suspicious counts
      expect(typeof result.data?.malicious_files).toBe('number');
      expect(typeof result.data?.clean_files).toBe('number');
      expect(typeof result.data?.suspicious_files).toBe('number');
    });

    it('should search reports with filters', async () => {
      const filters = {
        file_type: ['peexe', 'pdf'],
        search_query: ''
      };
      
      const result = await searchReports(filters, 1, 20);
      
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.reports).toBeDefined();
      expect(Array.isArray(result.data?.reports)).toBe(true);
    });

    it('should handle pagination correctly', async () => {
      // Fetch first page
      const page1 = await fetchReports(1, 10);
      expect(page1.success).toBe(true);
      expect(page1.data?.reports.length).toBe(10);
      
      // Fetch second page
      const page2 = await fetchReports(2, 10);
      expect(page2.success).toBe(true);
      expect(page2.data?.reports.length).toBe(10);
      
      // Ensure different data
      const firstPageIds = page1.data?.reports.map(r => r.report_uuid);
      const secondPageIds = page2.data?.reports.map(r => r.report_uuid);
      
      const intersection = firstPageIds?.filter(id => 
        secondPageIds?.includes(id)
      );
      expect(intersection?.length).toBe(0); // No overlap between pages
    });

    it('should validate special fields in reports', async () => {
      const result = await fetchReports(1, 10);
      const reports = result.data?.reports || [];
      
      reports.forEach(report => {
        // Check for special analysis fields that might exist
        if (report.pe_info) {
          expect(typeof report.pe_info).toBe('object');
        }
        if (report.androguard) {
          expect(typeof report.androguard).toBe('object');
        }
        if (report.pdf_info) {
          expect(typeof report.pdf_info).toBe('object');
        }
        if (report.exiftool) {
          expect(typeof report.exiftool).toBe('object');
        }
        
        // Validate similarity hashes if present
        if (report.vhash) {
          expect(typeof report.vhash).toBe('string');
        }
        if (report.tlsh) {
          expect(typeof report.tlsh).toBe('string');
        }
        if (report.ssdeep) {
          expect(typeof report.ssdeep).toBe('string');
        }
      });
    });

    it('should validate date fields are properly formatted', async () => {
      const result = await fetchReports(1, 5);
      const reports = result.data?.reports || [];
      
      reports.forEach(report => {
        // Check index_time is a valid ISO date
        if (report.index_time) {
          const date = new Date(report.index_time);
          expect(date.toString()).not.toBe('Invalid Date');
          expect(report.index_time).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
        }
        
        // Check other date fields if present
        if (report.first_submission_date) {
          const date = new Date(report.first_submission_date);
          expect(date.toString()).not.toBe('Invalid Date');
        }
      });
    });

    it('should validate report UUID linking across indexes', async () => {
      // Get a report
      const reportResult = await fetchReports(1, 1);
      const report = reportResult.data?.reports[0];
      const reportUuid = report?.report_uuid;
      
      expect(reportUuid).toBeDefined();
      expect(typeof reportUuid).toBe('string');
      expect(reportUuid?.length).toBeGreaterThan(0);
      
      // Fetch related data using the same UUID
      if (reportUuid) {
        const analysisResults = await fetchAnalysisResults(reportUuid);
        
        // If there are analysis results, they should all have the same UUID
        if (analysisResults.data && analysisResults.data.length > 0) {
          analysisResults.data.forEach(result => {
            expect(result.report_uuid).toBe(reportUuid);
          });
        }
      }
    });
  });

  describe('Error Handling', () => {
    it('should handle non-existent report gracefully', async () => {
      const result = await fetchReportById('non-existent-uuid-12345');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('Report not found');
    });

    it('should handle invalid page numbers', async () => {
      const result = await fetchReports(9999, 20);
      
      expect(result.success).toBe(true);
      expect(result.data?.reports.length).toBe(0);
      expect(result.data?.total).toBe(EXPECTED_TOTAL_REPORTS);
    });
  });
});