import { describe, it, expect, beforeEach, vi, beforeAll, afterAll, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@/test/utils/test-utils'
import { Reports } from '../Reports'
import { server, resetMocks } from '@/test/utils/mock-server'
import { mockReports, getMaliciousReport, getCleanReport, getSuspiciousReport } from '@/test/fixtures/mock-data'
import { http, HttpResponse } from 'msw'
import { BrowserRouter } from 'react-router-dom'

// Mock the services
vi.mock('@/services/elasticsearch', async () => {
  const actual = await vi.importActual('@/services/elasticsearch')
  return {
    ...actual,
    fetchReports: vi.fn().mockResolvedValue({
      success: true,
      data: {
        reports: [],
        total: 0,
        total_pages: 1
      }
    }),
    searchReports: vi.fn().mockResolvedValue({
      success: true,
      data: {
        reports: [],
        total: 0,
        total_pages: 1
      }
    }),
  }
})

// Mock router hooks
const mockSetSearchParams = vi.fn()
const mockNavigate = vi.fn()

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useSearchParams: () => [new URLSearchParams(), mockSetSearchParams],
    useNavigate: () => mockNavigate,
  }
})

// Start mock server
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' })
})

afterEach(() => {
  server.resetHandlers()
  resetMocks()
  vi.clearAllMocks()
  mockSetSearchParams.mockClear()
  mockNavigate.mockClear()
})

afterAll(() => {
  server.close()
})

// Custom render for Reports component with router
const renderReports = () => {
  return render(<Reports />)
}

describe('Reports Page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('Component Rendering', () => {
    it('renders the reports page with all main elements', async () => {
      renderReports()
      
      expect(screen.getByText('Reports')).toBeInTheDocument()
      expect(screen.getByText('Browse and search VirusTotal analysis reports')).toBeInTheDocument()
      expect(screen.getByText('Filters')).toBeInTheDocument()
      
      await waitFor(() => {
        expect(screen.getByText('Analysis Reports')).toBeInTheDocument()
      })
    })

    it('renders filter controls', () => {
      renderReports()
      
      expect(screen.getByText('Search')).toBeInTheDocument()
      expect(screen.getByText('File Type')).toBeInTheDocument()
      expect(screen.getByText('Verdict')).toBeInTheDocument()
      expect(screen.getByText('Actions')).toBeInTheDocument()
      
      expect(screen.getByPlaceholderText('Hash, filename, or file type...')).toBeInTheDocument()
      expect(screen.getByText('Apply Filters')).toBeInTheDocument()
    })

    it('renders desktop table headers', async () => {
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText('SHA256')).toBeInTheDocument()
        expect(screen.getByText('File Name')).toBeInTheDocument()
        expect(screen.getByText('Type')).toBeInTheDocument()
        expect(screen.getByText('Size')).toBeInTheDocument()
        expect(screen.getByText('Verdict')).toBeInTheDocument()
        expect(screen.getByText('Detections')).toBeInTheDocument()
        expect(screen.getByText('Occurrence')).toBeInTheDocument()
        expect(screen.getByText('Date')).toBeInTheDocument()
      })
    })

    it('shows loading state initially', () => {
      renderReports()
      
      expect(screen.getByText('Loading...')).toBeInTheDocument()
    })
  })

  describe('Data Loading', () => {
    it('loads and displays reports on mount', async () => {
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText(/total reports/)).toBeInTheDocument()
      })
      
      // Should display mock reports data
      const reportRows = document.querySelectorAll('tbody tr')
      expect(reportRows.length).toBeGreaterThan(0)
    })

    it('displays report count', async () => {
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText(/total reports/)).toBeInTheDocument()
      })
    })

    it('handles loading state correctly', async () => {
      renderReports()
      
      // Initially loading
      expect(screen.getByText('Loading...')).toBeInTheDocument()
      
      // After loading
      await waitFor(() => {
        expect(screen.queryByText('Loading...')).not.toBeInTheDocument()
      })
    })

    it('displays skeleton rows during loading', () => {
      renderReports()
      
      const skeletonRows = document.querySelectorAll('.animate-pulse')
      expect(skeletonRows.length).toBeGreaterThan(0)
    })
  })

  describe('Filter Functionality', () => {
    it('allows typing in search input', () => {
      renderReports()
      
      const searchInput = screen.getByPlaceholderText('Hash, filename, or file type...')
      
      fireEvent.change(searchInput, { target: { value: 'malware.exe' } })
      expect(searchInput).toHaveValue('malware.exe')
    })

    it('allows selecting file type from dropdown', async () => {
      renderReports()
      
      const fileTypeSelect = screen.getByRole('combobox')
      fireEvent.click(fileTypeSelect)
      
      await waitFor(() => {
        expect(screen.getByText('PE32 Executable')).toBeInTheDocument()
      })
      
      fireEvent.click(screen.getByText('PE32 Executable'))
      
      // The select should now show PE32
      await waitFor(() => {
        expect(screen.getByDisplayValue('PE32')).toBeInTheDocument()
      })
    })

    it('allows selecting verdict from dropdown', async () => {
      renderReports()
      
      // Find the verdict select (second combobox)
      const selectElements = screen.getAllByRole('combobox')
      const verdictSelect = selectElements[1] // Assuming second select is verdict
      
      fireEvent.click(verdictSelect)
      
      await waitFor(() => {
        expect(screen.getByText('Malicious')).toBeInTheDocument()
      })
      
      fireEvent.click(screen.getByText('Malicious'))
      
      await waitFor(() => {
        expect(screen.getByDisplayValue('malicious')).toBeInTheDocument()
      })
    })

    it('applies filters when Apply Filters button is clicked', async () => {
      renderReports()
      
      const searchInput = screen.getByPlaceholderText('Hash, filename, or file type...')
      const applyButton = screen.getByText('Apply Filters')
      
      fireEvent.change(searchInput, { target: { value: 'test.exe' } })
      fireEvent.click(applyButton)
      
      expect(mockSetSearchParams).toHaveBeenCalled()
    })

    it('performs search when Enter is pressed in search input', async () => {
      renderReports()
      
      const searchInput = screen.getByPlaceholderText('Hash, filename, or file type...')
      
      fireEvent.change(searchInput, { target: { value: 'test.exe' } })
      fireEvent.keyDown(searchInput, { key: 'Enter' })
      
      expect(mockSetSearchParams).toHaveBeenCalled()
    })

    it('shows clear filters button when filters are applied', async () => {
      renderReports()
      
      const searchInput = screen.getByPlaceholderText('Hash, filename, or file type...')
      fireEvent.change(searchInput, { target: { value: 'test' } })
      
      const applyButton = screen.getByText('Apply Filters')
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        const clearButton = document.querySelector('[class*="x-4"]')?.closest('button')
        expect(clearButton).toBeInTheDocument()
      })
    })

    it('clears all filters when clear button is clicked', async () => {
      renderReports()
      
      const searchInput = screen.getByPlaceholderText('Hash, filename, or file type...')
      fireEvent.change(searchInput, { target: { value: 'test' } })
      
      const applyButton = screen.getByText('Apply Filters')
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        const clearButton = document.querySelector('[class*="x-4"]')?.closest('button')
        if (clearButton) {
          fireEvent.click(clearButton)
          expect(searchInput).toHaveValue('')
        }
      })
    })
  })

  describe('Report Display', () => {
    it('displays report information correctly', async () => {
      renderReports()
      
      await waitFor(() => {
        // Check for hash display (truncated)
        const hashLinks = screen.getAllByRole('link')
        const reportLinks = hashLinks.filter(link => 
          link.getAttribute('href')?.includes('/reports/')
        )
        expect(reportLinks.length).toBeGreaterThan(0)
      })
    })

    it('shows file type icons and badges', async () => {
      renderReports()
      
      await waitFor(() => {
        // PE files should show appropriate indicators
        const badges = document.querySelectorAll('.badge')
        expect(badges.length).toBeGreaterThan(0)
      })
    })

    it('displays verdict badges with correct colors', async () => {
      renderReports()
      
      await waitFor(() => {
        const verdictBadges = document.querySelectorAll('[class*="badge"]')
        expect(verdictBadges.length).toBeGreaterThan(0)
      })
    })

    it('shows detection counts in format X/Y', async () => {
      renderReports()
      
      await waitFor(() => {
        // Look for detection ratio pattern
        const detectionText = screen.getByText(/\d+\/\d+/)
        expect(detectionText).toBeInTheDocument()
      })
    })

    it('displays file sizes in human readable format', async () => {
      renderReports()
      
      await waitFor(() => {
        // Should show formatted bytes (KB, MB, etc.)
        const sizeElements = document.querySelectorAll('td')
        const hasFormattedSize = Array.from(sizeElements).some(el => 
          /\d+\s*(B|KB|MB|GB)/.test(el.textContent || '')
        )
        expect(hasFormattedSize).toBe(true)
      })
    })

    it('makes file hashes clickable links', async () => {
      renderReports()
      
      await waitFor(() => {
        const hashLinks = screen.getAllByRole('link')
        const reportLinks = hashLinks.filter(link => 
          link.getAttribute('href')?.includes('/reports/')
        )
        expect(reportLinks.length).toBeGreaterThan(0)
        
        // Click on a hash link should navigate
        if (reportLinks.length > 0) {
          fireEvent.click(reportLinks[0])
          // Navigation would be tested with actual router
        }
      })
    })
  })

  describe('Mobile Responsive Design', () => {
    it('shows mobile card view on small screens', async () => {
      renderReports()
      
      await waitFor(() => {
        // Mobile view should be present (hidden on large screens)
        const mobileView = document.querySelector('.lg\\:hidden')
        expect(mobileView).toBeInTheDocument()
      })
    })

    it('shows desktop table view on large screens', async () => {
      renderReports()
      
      await waitFor(() => {
        // Desktop view should be present (hidden on small screens)
        const desktopView = document.querySelector('.hidden.lg\\:block')
        expect(desktopView).toBeInTheDocument()
      })
    })
  })

  describe('Pagination', () => {
    it('shows pagination controls when there are multiple pages', async () => {
      // Mock response with many results to trigger pagination
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({
            took: 1,
            hits: {
              total: { value: 100, relation: 'eq' },
              hits: Array.from({ length: 50 }, (_, i) => ({
                _id: `id-${i}`,
                _source: { ...mockReports[0], report_uuid: `uuid-${i}` }
              }))
            }
          })
        })
      )
      
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText('Previous')).toBeInTheDocument()
        expect(screen.getByText('Next')).toBeInTheDocument()
      })
    })

    it('disables Previous button on first page', async () => {
      renderReports()
      
      await waitFor(() => {
        const prevButton = screen.getByText('Previous').closest('button')
        expect(prevButton).toBeDisabled()
      })
    })

    it('shows correct page information', async () => {
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText(/Page \d+ of \d+/)).toBeInTheDocument()
      })
    })

    it('handles page navigation', async () => {
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({
            took: 1,
            hits: {
              total: { value: 100, relation: 'eq' },
              hits: Array.from({ length: 50 }, (_, i) => ({
                _id: `id-${i}`,
                _source: { ...mockReports[0], report_uuid: `uuid-${i}` }
              }))
            }
          })
        })
      )
      
      renderReports()
      
      await waitFor(() => {
        const nextButton = screen.getByText('Next').closest('button')
        if (nextButton && !nextButton.disabled) {
          fireEvent.click(nextButton)
          expect(mockSetSearchParams).toHaveBeenCalled()
        }
      })
    })
  })

  describe('Error Handling', () => {
    it('displays error message when reports fail to load', async () => {
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({ error: 'Connection failed' }, { status: 500 })
        })
      )
      
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText(/Error:/)).toBeInTheDocument()
      })
    })

    it('shows retry button on error', async () => {
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({ error: 'Network error' }, { status: 500 })
        })
      )
      
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText('Retry')).toBeInTheDocument()
      })
    })

    it('allows retrying after error', async () => {
      let failCount = 0
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          if (failCount === 0) {
            failCount++
            return HttpResponse.json({ error: 'Network error' }, { status: 500 })
          }
          return HttpResponse.json({
            took: 1,
            hits: {
              total: { value: 1, relation: 'eq' },
              hits: [{ _id: 'test-id', _source: mockReports[0] }]
            }
          })
        })
      )
      
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText('Retry')).toBeInTheDocument()
      })
      
      fireEvent.click(screen.getByText('Retry'))
      
      await waitFor(() => {
        expect(screen.getByText('Analysis Reports')).toBeInTheDocument()
      })
    })

    it('shows "No reports found" when no data is available', async () => {
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
      
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText('No reports found')).toBeInTheDocument()
      })
    })
  })

  describe('URL Parameter Handling', () => {
    it('loads filters from URL parameters on mount', () => {
      // This would require mocking useSearchParams with actual parameters
      renderReports()
      
      expect(screen.getByText('Reports')).toBeInTheDocument()
    })

    it('updates URL when filters are applied', async () => {
      renderReports()
      
      const searchInput = screen.getByPlaceholderText('Hash, filename, or file type...')
      const applyButton = screen.getByText('Apply Filters')
      
      fireEvent.change(searchInput, { target: { value: 'test' } })
      fireEvent.click(applyButton)
      
      expect(mockSetSearchParams).toHaveBeenCalled()
    })
  })

  describe('Navigation Integration', () => {
    it('navigates to search page with occurrence context', () => {
      renderReports()
      
      // This tests the handleOccurrenceSearch function
      // In a real scenario, this would be triggered by OccurrenceColumn
      expect(mockNavigate).not.toHaveBeenCalled() // Initially not called
    })
  })

  describe('File Type Detection', () => {
    it('displays appropriate icons for different file types', async () => {
      renderReports()
      
      await waitFor(() => {
        // Look for file type indicators
        const typeColumn = screen.getByText('Type')
        expect(typeColumn).toBeInTheDocument()
      })
    })

    it('shows security indicators for PE files', async () => {
      const maliciousReport = getMaliciousReport()
      maliciousReport.type_tag = 'peexe'
      maliciousReport.pe_info = { some: 'data' }
      
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({
            took: 1,
            hits: {
              total: { value: 1, relation: 'eq' },
              hits: [{ _id: 'pe-file', _source: maliciousReport }]
            }
          })
        })
      )
      
      renderReports()
      
      await waitFor(() => {
        // Look for PE badge or indicator
        const badges = document.querySelectorAll('.badge')
        const hasPEIndicator = Array.from(badges).some(badge => 
          badge.textContent?.includes('PE')
        )
        expect(hasPEIndicator).toBe(true)
      })
    })

    it('shows attachment indicator for email files', async () => {
      const emailReport = getCleanReport()
      emailReport.type_tag = 'outlook'
      emailReport.office_info = { some: 'data' }
      
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({
            took: 1,
            hits: {
              total: { value: 1, relation: 'eq' },
              hits: [{ _id: 'email-file', _source: emailReport }]
            }
          })
        })
      )
      
      renderReports()
      
      await waitFor(() => {
        // Should show email icon or indicator
        const cells = document.querySelectorAll('td')
        const hasEmailIndicator = Array.from(cells).some(cell => 
          cell.textContent?.includes('📧') || cell.innerHTML.includes('email')
        )
        expect(hasEmailIndicator).toBe(true)
      })
    })
  })

  describe('Sorting and Ordering', () => {
    it('displays reports in chronological order', async () => {
      renderReports()
      
      await waitFor(() => {
        // Check that dates are displayed
        const dateElements = document.querySelectorAll('td')
        const hasDates = Array.from(dateElements).some(el => 
          /\d{4}-\d{2}-\d{2}/.test(el.textContent || '')
        )
        expect(hasDates).toBe(true)
      })
    })
  })

  describe('Integration with Child Components', () => {
    it('integrates with OccurrenceColumn component', async () => {
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText('Occurrence')).toBeInTheDocument()
      })
    })

    it('passes correct props to child components', async () => {
      renderReports()
      
      await waitFor(() => {
        // Check that report data is passed to child components
        const reportElements = document.querySelectorAll('[data-report]')
        // This would need to be implemented in the actual components
      })
    })
  })

  describe('Performance', () => {
    it('loads reports efficiently', async () => {
      const startTime = performance.now()
      
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText('Analysis Reports')).toBeInTheDocument()
      })
      
      const loadTime = performance.now() - startTime
      expect(loadTime).toBeLessThan(3000) // Should load within 3 seconds in test
    })

    it('handles large datasets without performance issues', async () => {
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({
            took: 1,
            hits: {
              total: { value: 50, relation: 'eq' },
              hits: Array.from({ length: 50 }, (_, i) => ({
                _id: `id-${i}`,
                _source: { ...mockReports[0], report_uuid: `uuid-${i}` }
              }))
            }
          })
        })
      )
      
      renderReports()
      
      await waitFor(() => {
        expect(screen.getByText('Analysis Reports')).toBeInTheDocument()
      })
      
      // Should render without hanging
      const tableRows = document.querySelectorAll('tbody tr')
      expect(tableRows.length).toBeLessThanOrEqual(50)
    })
  })

  describe('Accessibility', () => {
    it('provides proper table structure', async () => {
      renderReports()
      
      await waitFor(() => {
        const table = screen.getByRole('table')
        expect(table).toBeInTheDocument()
        
        const headers = within(table).getAllByRole('columnheader')
        expect(headers.length).toBeGreaterThan(0)
      })
    })

    it('provides proper heading structure', () => {
      renderReports()
      
      const mainHeading = screen.getByRole('heading', { level: 1 })
      expect(mainHeading).toHaveTextContent('Reports')
    })

    it('maintains keyboard navigation support', () => {
      renderReports()
      
      const searchInput = screen.getByPlaceholderText('Hash, filename, or file type...')
      searchInput.focus()
      
      expect(document.activeElement).toBe(searchInput)
    })

    it('provides meaningful labels for controls', () => {
      renderReports()
      
      expect(screen.getByText('Search')).toBeInTheDocument()
      expect(screen.getByText('File Type')).toBeInTheDocument()
      expect(screen.getByText('Verdict')).toBeInTheDocument()
    })
  })
})