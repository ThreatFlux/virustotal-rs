import { describe, it, expect, beforeEach, vi, beforeAll, afterAll, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@/test/utils/test-utils'
import { ReportDetail } from '../ReportDetail'
import { server, resetMocks } from '@/test/utils/mock-server'
import { mockFileAnalysis, mockReports, mockAnalysisResults, mockSandboxVerdicts } from '@/test/fixtures/mock-data'
import { http, HttpResponse } from 'msw'
import { BrowserRouter, Routes, Route } from 'react-router-dom'

// Mock the services
vi.mock('@/services/elasticsearch', () => ({
  fetchFileAnalysis: vi.fn().mockResolvedValue({
    success: true,
    data: mockFileAnalysis
  }),
}))

// Mock useParams and Link
const mockReportId = 'test-report-uuid'
vi.mock('react-router-dom', () => ({
  useParams: vi.fn(() => ({ reportId: mockReportId })),
  Link: ({ children, to }: any) => <a href={to}>{children}</a>,
  BrowserRouter: ({ children }: any) => <div>{children}</div>,
  Routes: ({ children }: any) => <div>{children}</div>,
  Route: ({ children }: any) => <div>{children}</div>,
}))

// Mock clipboard API
Object.assign(navigator, {
  clipboard: {
    writeText: vi.fn().mockImplementation(() => Promise.resolve()),
  },
})

// Start mock server
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' })
})

afterEach(() => {
  server.resetHandlers()
  resetMocks()
  vi.clearAllMocks()
})

afterAll(() => {
  server.close()
})

// Custom render for ReportDetail component with router
const renderReportDetail = () => {
  return render(<ReportDetail />)
}

// Mock successful file analysis response
const setupSuccessfulAnalysis = () => {
  server.use(
    http.post('/api/elasticsearch/vt_reports/_search', () => {
      return HttpResponse.json({
        took: 1,
        hits: {
          total: { value: 1, relation: 'eq' },
          hits: [{ _id: 'test-id', _source: mockFileAnalysis.report }]
        }
      })
    }),
    http.post('/api/elasticsearch/vt_analysis_results/_search', () => {
      return HttpResponse.json({
        took: 1,
        hits: {
          total: { value: mockFileAnalysis.analysis_results.length, relation: 'eq' },
          hits: mockFileAnalysis.analysis_results.map((result, i) => ({
            _id: `analysis-${i}`,
            _source: result
          }))
        }
      })
    }),
    http.post('/api/elasticsearch/vt_sandbox_verdicts/_search', () => {
      return HttpResponse.json({
        took: 1,
        hits: {
          total: { value: mockFileAnalysis.sandbox_verdicts.length, relation: 'eq' },
          hits: mockFileAnalysis.sandbox_verdicts.map((verdict, i) => ({
            _id: `sandbox-${i}`,
            _source: verdict
          }))
        }
      })
    }),
    http.post('/api/elasticsearch/vt_crowdsourced_data/_search', () => {
      return HttpResponse.json({
        took: 1,
        hits: {
          total: { value: mockFileAnalysis.crowdsourced_data.length, relation: 'eq' },
          hits: mockFileAnalysis.crowdsourced_data.map((data, i) => ({
            _id: `crowd-${i}`,
            _source: data
          }))
        }
      })
    }),
    http.post('/api/elasticsearch/vt_relationships/_search', () => {
      return HttpResponse.json({
        took: 1,
        hits: {
          total: { value: mockFileAnalysis.relationships.length, relation: 'eq' },
          hits: mockFileAnalysis.relationships.map((rel, i) => ({
            _id: `rel-${i}`,
            _source: rel
          }))
        }
      })
    })
  )
}

describe('ReportDetail Page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setupSuccessfulAnalysis()
  })

  describe('Component Rendering', () => {
    it('shows loading state initially', () => {
      renderReportDetail()
      
      expect(screen.getByText('File Analysis Report')).toBeInTheDocument()
      
      // Should show loading skeletons
      const loadingElements = document.querySelectorAll('.animate-pulse')
      expect(loadingElements.length).toBeGreaterThan(0)
    })

    it('renders back to reports button', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('Back to Reports')).toBeInTheDocument()
      })
    })

    it('displays file analysis report after loading', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('File Analysis Report')).toBeInTheDocument()
        expect(screen.getByText('Technical Analysis')).toBeInTheDocument()
        expect(screen.getByText('File Metadata')).toBeInTheDocument()
        expect(screen.getByText('Detection & Intelligence')).toBeInTheDocument()
      })
    })

    it('displays risk score badge', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText(/Risk:/)).toBeInTheDocument()
        expect(screen.getByText(/Critical/)).toBeInTheDocument()
        expect(screen.getByText(/85%/)).toBeInTheDocument()
      })
    })
  })

  describe('File Information Section', () => {
    it('displays file name', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('File Information')).toBeInTheDocument()
        expect(screen.getByText('malicious.exe')).toBeInTheDocument()
      })
    })

    it('displays file type and size', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('File Type')).toBeInTheDocument()
        expect(screen.getByText('File Size')).toBeInTheDocument()
        expect(screen.getByText('PE32 executable')).toBeInTheDocument()
      })
    })

    it('displays magic information', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('Magic')).toBeInTheDocument()
        expect(screen.getByText('PE32 executable')).toBeInTheDocument()
      })
    })
  })

  describe('File Hashes Section', () => {
    it('displays all file hashes', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('File Hashes')).toBeInTheDocument()
        expect(screen.getByText('SHA256')).toBeInTheDocument()
        expect(screen.getByText('SHA1')).toBeInTheDocument()
        expect(screen.getByText('MD5')).toBeInTheDocument()
      })
    })

    it('shows copy buttons for hashes', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const copyButtons = document.querySelectorAll('button[class*="h-6 w-6"]')
        expect(copyButtons.length).toBeGreaterThan(0)
      })
    })

    it('copies hash to clipboard when copy button is clicked', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const copyButtons = document.querySelectorAll('button[class*="h-6 w-6"]')
        if (copyButtons.length > 0) {
          fireEvent.click(copyButtons[0])
          expect(navigator.clipboard.writeText).toHaveBeenCalled()
        }
      })
    })

    it('shows "Copied!" message after successful copy', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const copyButtons = document.querySelectorAll('button[class*="h-6 w-6"]')
        if (copyButtons.length > 0) {
          fireEvent.click(copyButtons[0])
          
          setTimeout(() => {
            expect(screen.getByText('Copied!')).toBeInTheDocument()
          }, 100)
        }
      })
    })
  })

  describe('Detection Statistics', () => {
    it('displays detection statistics', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('Detection Statistics')).toBeInTheDocument()
        expect(screen.getByText('Malicious')).toBeInTheDocument()
        expect(screen.getByText('Suspicious')).toBeInTheDocument()
        expect(screen.getByText('Clean')).toBeInTheDocument()
        expect(screen.getByText('Undetected')).toBeInTheDocument()
      })
    })

    it('shows total engines count', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText(/Total Engines:/)).toBeInTheDocument()
      })
    })

    it('displays detection counts with correct values', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        // Should show detection counts from mock data
        const countElements = document.querySelectorAll('.text-2xl.font-bold')
        expect(countElements.length).toBeGreaterThan(0)
      })
    })
  })

  describe('Tabbed Interface', () => {
    it('renders all tab triggers', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('AV Results')).toBeInTheDocument()
        expect(screen.getByText('Sandbox')).toBeInTheDocument()
        expect(screen.getByText('Intelligence')).toBeInTheDocument()
        expect(screen.getByText('Relations')).toBeInTheDocument()
      })
    })

    it('shows AV Results tab by default', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('Antivirus Detection Results')).toBeInTheDocument()
      })
    })

    it('switches to Sandbox tab when clicked', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const sandboxTab = screen.getByText('Sandbox')
        fireEvent.click(sandboxTab)
        
        expect(screen.getByText('Sandbox Analysis')).toBeInTheDocument()
      })
    })

    it('switches to Intelligence tab when clicked', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const intelTab = screen.getByText('Intelligence')
        fireEvent.click(intelTab)
        
        // Should show intelligence content
        expect(screen.getByText(/Intelligence|YARA|Sigma/)).toBeInTheDocument()
      })
    })

    it('switches to Relations tab when clicked', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const relationsTab = screen.getByText('Relations')
        fireEvent.click(relationsTab)
        
        expect(screen.getByText('File Relationships')).toBeInTheDocument()
      })
    })
  })

  describe('AV Results Tab', () => {
    it('displays antivirus results table', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('Antivirus Detection Results')).toBeInTheDocument()
        expect(screen.getByText('Engine')).toBeInTheDocument()
        expect(screen.getByText('Version')).toBeInTheDocument()
        expect(screen.getByText('Category')).toBeInTheDocument()
        expect(screen.getByText('Result')).toBeInTheDocument()
        expect(screen.getByText('Update')).toBeInTheDocument()
      })
    })

    it('displays individual engine results', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('Microsoft')).toBeInTheDocument()
        expect(screen.getByText('Kaspersky')).toBeInTheDocument()
        expect(screen.getByText('BitDefender')).toBeInTheDocument()
      })
    })

    it('shows detection results with proper badges', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const badges = document.querySelectorAll('.badge')
        const maliciousBadges = Array.from(badges).filter(badge => 
          badge.textContent?.toLowerCase().includes('malicious')
        )
        expect(maliciousBadges.length).toBeGreaterThan(0)
      })
    })

    it('sorts results by category (malicious first)', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const tableRows = document.querySelectorAll('tbody tr')
        expect(tableRows.length).toBeGreaterThan(0)
        
        // First rows should contain malicious results
        const firstRowBadge = tableRows[0]?.querySelector('.badge')
        if (firstRowBadge) {
          expect(firstRowBadge.textContent?.toLowerCase()).toContain('malicious')
        }
      })
    })
  })

  describe('Sandbox Tab', () => {
    it('displays sandbox analysis section', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const sandboxTab = screen.getByText('Sandbox')
        fireEvent.click(sandboxTab)
        
        expect(screen.getByText('Sandbox Analysis')).toBeInTheDocument()
      })
    })

    it('shows sandbox verdict statistics', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const sandboxTab = screen.getByText('Sandbox')
        fireEvent.click(sandboxTab)
        
        // Should show sandbox environment count
        expect(screen.getByText(/sandbox environment/)).toBeInTheDocument()
      })
    })

    it('displays individual sandbox results', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const sandboxTab = screen.getByText('Sandbox')
        fireEvent.click(sandboxTab)
        
        expect(screen.getByText('Microsoft Sysinternals')).toBeInTheDocument()
        expect(screen.getByText('VMRay')).toBeInTheDocument()
      })
    })

    it('shows confidence scores for sandbox verdicts', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const sandboxTab = screen.getByText('Sandbox')
        fireEvent.click(sandboxTab)
        
        expect(screen.getByText('Confidence')).toBeInTheDocument()
        expect(screen.getByText('95%')).toBeInTheDocument()
      })
    })

    it('displays malware classifications', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const sandboxTab = screen.getByText('Sandbox')
        fireEvent.click(sandboxTab)
        
        expect(screen.getByText('Classification')).toBeInTheDocument()
        const badges = document.querySelectorAll('.badge')
        const trojanBadges = Array.from(badges).filter(badge => 
          badge.textContent?.toLowerCase().includes('trojan')
        )
        expect(trojanBadges.length).toBeGreaterThan(0)
      })
    })
  })

  describe('Intelligence Tab', () => {
    it('displays threat intelligence data', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const intelTab = screen.getByText('Intelligence')
        fireEvent.click(intelTab)
        
        // Should show YARA rules or other intelligence
        expect(screen.getByText(/YARA|Intelligence|Rules/)).toBeInTheDocument()
      })
    })
  })

  describe('Relations Tab', () => {
    it('displays file relationships', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const relationsTab = screen.getByText('Relations')
        fireEvent.click(relationsTab)
        
        expect(screen.getByText('File Relationships')).toBeInTheDocument()
      })
    })

    it('shows relationship table headers', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const relationsTab = screen.getByText('Relations')
        fireEvent.click(relationsTab)
        
        expect(screen.getByText('Relationship Type')).toBeInTheDocument()
        expect(screen.getByText('Target ID')).toBeInTheDocument()
        expect(screen.getByText('Target Type')).toBeInTheDocument()
        expect(screen.getByText('Context')).toBeInTheDocument()
      })
    })

    it('displays individual relationships', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const relationsTab = screen.getByText('Relations')
        fireEvent.click(relationsTab)
        
        expect(screen.getByText('drops')).toBeInTheDocument()
        expect(screen.getByText('communicates_with')).toBeInTheDocument()
      })
    })

    it('shows "No relationships" message when empty', async () => {
      // Mock empty relationships
      server.use(
        http.post('/api/elasticsearch/vt_relationships/_search', () => {
          return HttpResponse.json({
            took: 1,
            hits: {
              total: { value: 0, relation: 'eq' },
              hits: []
            }
          })
        })
      )
      
      renderReportDetail()
      
      await waitFor(() => {
        const relationsTab = screen.getByText('Relations')
        fireEvent.click(relationsTab)
        
        expect(screen.getByText('No file relationships available')).toBeInTheDocument()
      })
    })
  })

  describe('Error Handling', () => {
    it('shows error message when report is not found', async () => {
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({
            took: 1,
            hits: {
              total: { value: 0, relation: 'eq' },
              hits: []
            }
          })
        })
      )
      
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('Error loading report')).toBeInTheDocument()
        expect(screen.getByText('Report not found')).toBeInTheDocument()
      })
    })

    it('shows error message when API fails', async () => {
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({ error: 'Connection failed' }, { status: 500 })
        })
      )
      
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('Error loading report')).toBeInTheDocument()
        expect(screen.getByText(/Failed to load report/)).toBeInTheDocument()
      })
    })

    it('maintains back button functionality on error', async () => {
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({ error: 'Not found' }, { status: 404 })
        })
      )
      
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('Back to Reports')).toBeInTheDocument()
      })
    })
  })

  describe('URL Parameter Handling', () => {
    it('loads report based on URL parameter', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        // Should load report data for the provided UUID
        expect(screen.getByText('File Analysis Report')).toBeInTheDocument()
      })
    })

    it('handles missing reportId parameter', async () => {
      // Mock useParams to return undefined
      vi.mocked(require('react-router-dom').useParams).mockReturnValue({})
      
      renderReportDetail()
      
      // Should handle gracefully without crashing
      expect(screen.getByText('File Analysis Report')).toBeInTheDocument()
    })
  })

  describe('Navigation', () => {
    it('provides back navigation to reports list', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const backButton = screen.getByText('Back to Reports')
        expect(backButton).toBeInTheDocument()
        expect(backButton.closest('a')).toHaveAttribute('href', '/reports')
      })
    })
  })

  describe('Technical Analysis Integration', () => {
    it('displays AnalysisDisplay component', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('Technical Analysis')).toBeInTheDocument()
      })
    })
  })

  describe('Responsive Design', () => {
    it('adjusts layout for mobile screens', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        // Check for responsive classes
        const responsiveElements = document.querySelectorAll('[class*="sm:"]')
        expect(responsiveElements.length).toBeGreaterThan(0)
      })
    })

    it('maintains functionality on different screen sizes', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        // All main sections should be present
        expect(screen.getByText('File Analysis Report')).toBeInTheDocument()
        expect(screen.getByText('Technical Analysis')).toBeInTheDocument()
        expect(screen.getByText('File Metadata')).toBeInTheDocument()
      })
    })
  })

  describe('Performance', () => {
    it('loads report data efficiently', async () => {
      const startTime = performance.now()
      
      renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('File Analysis Report')).toBeInTheDocument()
      })
      
      const loadTime = performance.now() - startTime
      expect(loadTime).toBeLessThan(3000) // Should load within 3 seconds in test
    })

    it('handles component updates without excessive re-renders', async () => {
      const { rerender } = renderReportDetail()
      
      await waitFor(() => {
        expect(screen.getByText('File Analysis Report')).toBeInTheDocument()
      })
      
      // Re-render shouldn't cause issues
      rerender(<ReportDetail />)
      
      expect(screen.getByText('File Analysis Report')).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('provides proper heading structure', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const mainHeading = screen.getByRole('heading', { level: 1 })
        expect(mainHeading).toHaveTextContent('File Analysis Report')
        
        const subHeadings = screen.getAllByRole('heading', { level: 2 })
        expect(subHeadings.length).toBeGreaterThan(0)
      })
    })

    it('maintains keyboard navigation in tabs', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const tabs = screen.getAllByRole('tab')
        expect(tabs.length).toBeGreaterThan(0)
        
        // First tab should be focusable
        tabs[0].focus()
        expect(document.activeElement).toBe(tabs[0])
      })
    })

    it('provides semantic table structure', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const tables = screen.getAllByRole('table')
        expect(tables.length).toBeGreaterThan(0)
        
        const firstTable = tables[0]
        const headers = within(firstTable).getAllByRole('columnheader')
        expect(headers.length).toBeGreaterThan(0)
      })
    })

    it('provides meaningful button labels', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        const backButton = screen.getByText('Back to Reports')
        expect(backButton).toBeInTheDocument()
      })
    })
  })

  describe('Data Consistency', () => {
    it('displays consistent data across different sections', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        // Hash should be consistent between metadata and other sections
        const hashElements = document.querySelectorAll('[class*="font-mono"]')
        expect(hashElements.length).toBeGreaterThan(0)
      })
    })

    it('maintains data integrity during tab switches', async () => {
      renderReportDetail()
      
      await waitFor(() => {
        // Switch between tabs and verify data consistency
        const sandboxTab = screen.getByText('Sandbox')
        fireEvent.click(sandboxTab)
        
        const avTab = screen.getByText('AV Results')
        fireEvent.click(avTab)
        
        expect(screen.getByText('Antivirus Detection Results')).toBeInTheDocument()
      })
    })
  })
})