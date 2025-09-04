import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { 
  mockReports, 
  mockAnalysisResults, 
  mockSandboxVerdicts, 
  mockCrowdsourcedData, 
  mockRelationships,
  mockDashboardStats 
} from '../fixtures/mock-data'
import type { 
  Report, 
  AnalysisResult, 
  SandboxVerdict, 
  CrowdsourcedData, 
  Relationship,
  DashboardStats,
  SearchResult
} from '@/types'

// Mock Elasticsearch responses
const createElasticsearchResponse = <T>(data: T[], total?: number) => ({
  took: 1,
  timed_out: false,
  _shards: {
    total: 1,
    successful: 1,
    skipped: 0,
    failed: 0,
  },
  hits: {
    total: {
      value: total || data.length,
      relation: 'eq',
    },
    max_score: 1.0,
    hits: data.map((item, index) => ({
      _index: 'mock-index',
      _id: `mock-id-${index}`,
      _score: 1.0,
      _source: item,
    })),
  },
})

// Mock handlers
export const handlers = [
  // Reports endpoints
  http.post('/api/elasticsearch/vt_reports/_search', async ({ request }) => {
    const body = await request.json() as any
    
    // Handle dashboard stats aggregation queries
    if (body.size === 0 && body.aggs) {
      const mockStatsAggResponse = {
        ...createElasticsearchResponse([]),
        aggregations: {
          total_reports: { value: mockDashboardStats.total_reports },
          reports_today: { doc_count: mockDashboardStats.reports_today },
          malicious_count: { doc_count: mockDashboardStats.malicious_files },
          clean_count: { doc_count: mockDashboardStats.clean_files },
          suspicious_count: { doc_count: mockDashboardStats.suspicious_files },
          undetected_count: { doc_count: mockDashboardStats.undetected_files },
          file_types: {
            buckets: mockDashboardStats.top_file_types.map(ft => ({
              key: ft.type,
              doc_count: ft.count,
            })),
          },
          daily_trends: {
            buckets: mockDashboardStats.detection_trends.map(trend => ({
              key_as_string: trend.date,
              doc_count: trend.malicious + trend.suspicious + trend.clean + trend.undetected,
              malicious: { doc_count: trend.malicious },
              suspicious: { doc_count: trend.suspicious },
              clean: { doc_count: trend.clean },
              undetected: { doc_count: trend.undetected },
            })),
          },
        },
      }
      return HttpResponse.json(mockStatsAggResponse)
    }
    
    const size = body.size || 20
    const from = body.from || 0
    
    // Handle search queries
    if (body.query?.bool?.must) {
      const filtered = mockReports.filter((report) => {
        // Simple search implementation for tests
        const mustQueries = body.query.bool.must
        return mustQueries.every((query: any) => {
          if (query.term?.report_uuid) {
            return report.report_uuid === query.term.report_uuid
          }
          if (query.multi_match) {
            const searchQuery = query.multi_match.query.toLowerCase()
            return (
              report.sha256?.toLowerCase().includes(searchQuery) ||
              report.file_name?.toLowerCase().includes(searchQuery) ||
              report.file_type?.toLowerCase().includes(searchQuery)
            )
          }
          if (query.terms) {
            const field = Object.keys(query.terms)[0]
            const values = query.terms[field]
            return values.includes((report as any)[field])
          }
          return true
        })
      })
      
      const paginatedReports = filtered.slice(from, from + size)
      return HttpResponse.json(createElasticsearchResponse(paginatedReports, filtered.length))
    }
    
    // Default pagination
    const paginatedReports = mockReports.slice(from, from + size)
    return HttpResponse.json(createElasticsearchResponse(paginatedReports, mockReports.length))
  }),

  // Analysis results endpoint
  http.post('/api/elasticsearch/vt_analysis_results/_search', async ({ request }) => {
    const body = await request.json() as any
    
    if (body.query?.term?.report_uuid) {
      const reportUuid = body.query.term.report_uuid
      const filtered = mockAnalysisResults.filter(result => result.report_uuid === reportUuid)
      return HttpResponse.json(createElasticsearchResponse(filtered))
    }
    
    // Handle aggregation queries for dashboard stats
    if (body.size === 0 && body.aggs) {
      const mockAggResponse = {
        ...createElasticsearchResponse([]),
        aggregations: {
          top_engines: {
            buckets: [
              { key: 'Microsoft', doc_count: 150, detections: { doc_count: 45 } },
              { key: 'Kaspersky', doc_count: 140, detections: { doc_count: 42 } },
              { key: 'BitDefender', doc_count: 135, detections: { doc_count: 38 } },
            ],
          },
        },
      }
      return HttpResponse.json(mockAggResponse)
    }
    
    return HttpResponse.json(createElasticsearchResponse(mockAnalysisResults))
  }),

  // Sandbox verdicts endpoint
  http.post('/api/elasticsearch/vt_sandbox_verdicts/_search', async ({ request }) => {
    const body = await request.json() as any
    
    if (body.query?.term?.report_uuid) {
      const reportUuid = body.query.term.report_uuid
      const filtered = mockSandboxVerdicts.filter(verdict => verdict.report_uuid === reportUuid)
      return HttpResponse.json(createElasticsearchResponse(filtered))
    }
    
    return HttpResponse.json(createElasticsearchResponse(mockSandboxVerdicts))
  }),

  // Crowdsourced data endpoint
  http.post('/api/elasticsearch/vt_crowdsourced_data/_search', async ({ request }) => {
    const body = await request.json() as any
    
    if (body.query?.term?.report_uuid) {
      const reportUuid = body.query.term.report_uuid
      const filtered = mockCrowdsourcedData.filter(data => data.report_uuid === reportUuid)
      return HttpResponse.json(createElasticsearchResponse(filtered))
    }
    
    return HttpResponse.json(createElasticsearchResponse(mockCrowdsourcedData))
  }),

  // Relationships endpoint
  http.post('/api/elasticsearch/vt_relationships/_search', async ({ request }) => {
    const body = await request.json() as any
    
    if (body.query?.term?.report_uuid) {
      const reportUuid = body.query.term.report_uuid
      const filtered = mockRelationships.filter(rel => rel.report_uuid === reportUuid)
      return HttpResponse.json(createElasticsearchResponse(filtered))
    }
    
    return HttpResponse.json(createElasticsearchResponse(mockRelationships))
  }),

]

// Create mock server
export const server = setupServer(...handlers)

// Test utilities for MSW
export const mockElasticsearchError = () => {
  server.use(
    http.post('/api/elasticsearch/*', () => {
      return HttpResponse.json(
        { error: { type: 'connection_exception', reason: 'Connection failed' } },
        { status: 500 }
      )
    })
  )
}

export const mockElasticsearchNotFound = () => {
  server.use(
    http.post('/api/elasticsearch/vt_reports/_search', () => {
      return HttpResponse.json(createElasticsearchResponse([]))
    })
  )
}

export const resetMocks = () => {
  server.resetHandlers()
}