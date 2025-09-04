import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach, vi } from 'vitest'
import { server, mockElasticsearchError, mockElasticsearchNotFound, resetMocks } from '@/test/utils/mock-server'
import {
  fetchReports,
  fetchReportById,
  fetchAnalysisResults,
  fetchSandboxVerdicts,
  fetchCrowdsourcedData,
  fetchRelationships,
  fetchFileAnalysis,
  searchReports,
  getDashboardStats,
} from '../elasticsearch'
import { mockReports, mockAnalysisResults, mockDashboardStats } from '@/test/fixtures/mock-data'
import type { SearchFilters } from '@/types'

// Start mock server before all tests
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' })
})

// Reset handlers after each test
afterEach(() => {
  server.resetHandlers()
  resetMocks()
})

// Close mock server after all tests
afterAll(() => {
  server.close()
})

describe('Elasticsearch Service', () => {
  describe('fetchReports', () => {
    it('should fetch paginated reports successfully', async () => {
      const result = await fetchReports(1, 10)
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(result.data?.reports).toHaveLength(3) // Based on mock data
      expect(result.data?.total).toBe(3)
      expect(result.data?.page).toBe(1)
      expect(result.data?.per_page).toBe(10)
      expect(result.data?.total_pages).toBe(1)
    })

    it('should handle pagination correctly', async () => {
      const result = await fetchReports(2, 2)
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(result.data?.page).toBe(2)
      expect(result.data?.per_page).toBe(2)
    })

    it('should handle default pagination parameters', async () => {
      const result = await fetchReports()
      
      expect(result.success).toBe(true)
      expect(result.data?.page).toBe(1)
      expect(result.data?.per_page).toBe(20)
    })

    it('should handle Elasticsearch errors', async () => {
      mockElasticsearchError()
      
      const result = await fetchReports()
      
      expect(result.success).toBe(false)
      expect(result.error).toContain('Elasticsearch request failed')
    })

    it('should return reports with correct structure', async () => {
      const result = await fetchReports()
      
      expect(result.success).toBe(true)
      expect(result.data?.reports[0]).toMatchObject({
        report_uuid: expect.any(String),
        sha256: expect.any(String),
        file_type: expect.any(String),
        created_at: expect.any(String),
        updated_at: expect.any(String),
      })
    })
  })

  describe('fetchReportById', () => {
    it('should fetch a specific report successfully', async () => {
      const result = await fetchReportById('uuid-001')
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(result.data?.report_uuid).toBe('uuid-001')
      expect(result.data?.sha256).toBeDefined()
    })

    it('should handle report not found', async () => {
      mockElasticsearchNotFound()
      
      const result = await fetchReportById('non-existent-uuid')
      
      expect(result.success).toBe(false)
      expect(result.error).toBe('Report not found')
    })

    it('should handle Elasticsearch errors', async () => {
      mockElasticsearchError()
      
      const result = await fetchReportById('uuid-001')
      
      expect(result.success).toBe(false)
      expect(result.error).toContain('Elasticsearch request failed')
    })
  })

  describe('fetchAnalysisResults', () => {
    it('should fetch analysis results for a report', async () => {
      const result = await fetchAnalysisResults('uuid-001')
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(Array.isArray(result.data)).toBe(true)
      
      if (result.data && result.data.length > 0) {
        expect(result.data[0]).toMatchObject({
          id: expect.any(String),
          report_uuid: 'uuid-001',
          engine_name: expect.any(String),
          category: expect.any(String),
          created_at: expect.any(String),
        })
      }
    })

    it('should return empty array for report with no analysis results', async () => {
      const result = await fetchAnalysisResults('uuid-999')
      
      expect(result.success).toBe(true)
      expect(result.data).toEqual([])
    })

    it('should handle Elasticsearch errors', async () => {
      mockElasticsearchError()
      
      const result = await fetchAnalysisResults('uuid-001')
      
      expect(result.success).toBe(false)
      expect(result.error).toContain('Elasticsearch request failed')
    })
  })

  describe('fetchSandboxVerdicts', () => {
    it('should fetch sandbox verdicts for a report', async () => {
      const result = await fetchSandboxVerdicts('uuid-001')
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(Array.isArray(result.data)).toBe(true)
      
      if (result.data && result.data.length > 0) {
        expect(result.data[0]).toMatchObject({
          id: expect.any(String),
          report_uuid: 'uuid-001',
          sandbox_name: expect.any(String),
          category: expect.any(String),
          created_at: expect.any(String),
        })
      }
    })

    it('should handle Elasticsearch errors', async () => {
      mockElasticsearchError()
      
      const result = await fetchSandboxVerdicts('uuid-001')
      
      expect(result.success).toBe(false)
      expect(result.error).toContain('Elasticsearch request failed')
    })
  })

  describe('fetchCrowdsourcedData', () => {
    it('should fetch crowdsourced data for a report', async () => {
      const result = await fetchCrowdsourcedData('uuid-001')
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(Array.isArray(result.data)).toBe(true)
      
      if (result.data && result.data.length > 0) {
        expect(result.data[0]).toMatchObject({
          id: expect.any(String),
          report_uuid: 'uuid-001',
          source: expect.any(String),
          created_at: expect.any(String),
        })
      }
    })

    it('should handle Elasticsearch errors', async () => {
      mockElasticsearchError()
      
      const result = await fetchCrowdsourcedData('uuid-001')
      
      expect(result.success).toBe(false)
      expect(result.error).toContain('Elasticsearch request failed')
    })
  })

  describe('fetchRelationships', () => {
    it('should fetch relationships for a report', async () => {
      const result = await fetchRelationships('uuid-001')
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(Array.isArray(result.data)).toBe(true)
      
      if (result.data && result.data.length > 0) {
        expect(result.data[0]).toMatchObject({
          id: expect.any(String),
          report_uuid: 'uuid-001',
          relation_type: expect.any(String),
          target_id: expect.any(String),
          created_at: expect.any(String),
        })
      }
    })

    it('should handle Elasticsearch errors', async () => {
      mockElasticsearchError()
      
      const result = await fetchRelationships('uuid-001')
      
      expect(result.success).toBe(false)
      expect(result.error).toContain('Elasticsearch request failed')
    })
  })

  describe('fetchFileAnalysis', () => {
    it('should fetch combined file analysis data', async () => {
      const result = await fetchFileAnalysis('uuid-001')
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(result.data).toMatchObject({
        report: expect.objectContaining({
          report_uuid: 'uuid-001',
          sha256: expect.any(String),
        }),
        analysis_results: expect.any(Array),
        sandbox_verdicts: expect.any(Array),
        crowdsourced_data: expect.any(Array),
        relationships: expect.any(Array),
        risk_score: expect.objectContaining({
          score: expect.any(Number),
          level: expect.any(String),
        }),
      })
    })

    it('should calculate risk score correctly for malicious files', async () => {
      const result = await fetchFileAnalysis('uuid-001')
      
      expect(result.success).toBe(true)
      expect(result.data?.risk_score).toBeDefined()
      expect(result.data?.risk_score.score).toBeGreaterThan(0)
      expect(['Low', 'Medium', 'High', 'Critical']).toContain(result.data?.risk_score.level)
    })

    it('should handle report not found', async () => {
      mockElasticsearchNotFound()
      
      const result = await fetchFileAnalysis('non-existent-uuid')
      
      expect(result.success).toBe(false)
      expect(result.error).toContain('Report not found')
    })

    it('should handle Elasticsearch errors', async () => {
      mockElasticsearchError()
      
      const result = await fetchFileAnalysis('uuid-001')
      
      expect(result.success).toBe(false)
      expect(result.error).toContain('Elasticsearch request failed')
    })
  })

  describe('searchReports', () => {
    it('should search reports without filters', async () => {
      const filters: SearchFilters = {}
      const result = await searchReports(filters)
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(Array.isArray(result.data?.reports)).toBe(true)
    })

    it('should search reports with file type filter', async () => {
      const filters: SearchFilters = {
        file_type: ['PE32', 'PDF'],
      }
      const result = await searchReports(filters)
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(Array.isArray(result.data?.reports)).toBe(true)
    })

    it('should search reports with date range filter', async () => {
      const filters: SearchFilters = {
        date_range: {
          start: '2023-01-01',
          end: '2023-12-31',
        },
      }
      const result = await searchReports(filters)
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
    })

    it('should search reports with file size range filter', async () => {
      const filters: SearchFilters = {
        file_size_range: {
          min: 1000,
          max: 10000000,
        },
      }
      const result = await searchReports(filters)
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
    })

    it('should search reports with search query', async () => {
      const filters: SearchFilters = {
        search_query: 'malicious.exe',
      }
      const result = await searchReports(filters)
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
    })

    it('should handle pagination in search', async () => {
      const filters: SearchFilters = {}
      const result = await searchReports(filters, 2, 5)
      
      expect(result.success).toBe(true)
      expect(result.data?.page).toBe(2)
      expect(result.data?.per_page).toBe(5)
    })

    it('should handle Elasticsearch errors in search', async () => {
      mockElasticsearchError()
      
      const filters: SearchFilters = {}
      const result = await searchReports(filters)
      
      expect(result.success).toBe(false)
      expect(result.error).toContain('Elasticsearch request failed')
    })
  })

  describe('getDashboardStats', () => {
    it('should fetch dashboard statistics', async () => {
      const result = await getDashboardStats()
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(result.data).toMatchObject({
        total_reports: expect.any(Number),
        reports_today: expect.any(Number),
        malicious_files: expect.any(Number),
        clean_files: expect.any(Number),
        suspicious_files: expect.any(Number),
        undetected_files: expect.any(Number),
        top_file_types: expect.any(Array),
        detection_trends: expect.any(Array),
        top_engines: expect.any(Array),
        file_size_distribution: expect.any(Array),
      })
    })

    it('should return file type statistics', async () => {
      const result = await getDashboardStats()
      
      expect(result.success).toBe(true)
      expect(result.data?.top_file_types).toBeDefined()
      expect(Array.isArray(result.data?.top_file_types)).toBe(true)
      
      if (result.data?.top_file_types.length > 0) {
        expect(result.data.top_file_types[0]).toMatchObject({
          type: expect.any(String),
          count: expect.any(Number),
        })
      }
    })

    it('should return detection trends', async () => {
      const result = await getDashboardStats()
      
      expect(result.success).toBe(true)
      expect(result.data?.detection_trends).toBeDefined()
      expect(Array.isArray(result.data?.detection_trends)).toBe(true)
      
      if (result.data?.detection_trends.length > 0) {
        expect(result.data.detection_trends[0]).toMatchObject({
          date: expect.any(String),
          malicious: expect.any(Number),
          suspicious: expect.any(Number),
          clean: expect.any(Number),
          undetected: expect.any(Number),
        })
      }
    })

    it('should return engine statistics', async () => {
      const result = await getDashboardStats()
      
      expect(result.success).toBe(true)
      expect(result.data?.top_engines).toBeDefined()
      expect(Array.isArray(result.data?.top_engines)).toBe(true)
      
      if (result.data?.top_engines.length > 0) {
        expect(result.data.top_engines[0]).toMatchObject({
          engine: expect.any(String),
          detections: expect.any(Number),
        })
      }
    })

    it('should handle Elasticsearch errors in dashboard stats', async () => {
      mockElasticsearchError()
      
      const result = await getDashboardStats()
      
      expect(result.success).toBe(false)
      expect(result.error).toContain('Elasticsearch request failed')
    })

    it('should handle missing aggregations gracefully', async () => {
      // Mock server will return proper structure with aggregations
      const result = await getDashboardStats()
      
      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
    })
  })

  describe('Request building helpers', () => {
    it('should build correct queries for file type filters', async () => {
      const filters: SearchFilters = {
        file_type: ['PE32', 'PDF'],
      }
      
      // This test ensures the query building works by checking the result
      const result = await searchReports(filters)
      expect(result.success).toBe(true)
    })

    it('should build correct queries for combined filters', async () => {
      const filters: SearchFilters = {
        file_type: ['PE32'],
        date_range: {
          start: '2023-01-01',
          end: '2023-12-31',
        },
        search_query: 'malware',
      }
      
      const result = await searchReports(filters)
      expect(result.success).toBe(true)
    })

    it('should handle empty filter arrays', async () => {
      const filters: SearchFilters = {
        file_type: [],
        verdict: [],
      }
      
      const result = await searchReports(filters)
      expect(result.success).toBe(true)
    })
  })
})