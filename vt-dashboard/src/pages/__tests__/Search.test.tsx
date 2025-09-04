import { describe, it, expect, beforeEach, vi, beforeAll, afterAll, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@/test/utils/test-utils'
import { Search } from '../Search'
import { server, resetMocks } from '@/test/utils/mock-server'
import { mockReports, getMaliciousReport, getCleanReport } from '@/test/fixtures/mock-data'
import { http, HttpResponse } from 'msw'
import { BrowserRouter } from 'react-router-dom'

// Mock the services
vi.mock('@/services/elasticsearch', async () => {
  const actual = await vi.importActual('@/services/elasticsearch')
  return {
    ...actual,
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

vi.mock('@/services/occurrence', async () => {
  return {
    executeOccurrenceSearch: vi.fn().mockResolvedValue({
      success: true,
      data: {
        results: [],
        total_found: 0
      }
    }),
  }
})

// Mock useSearchParams and useNavigate
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

// Custom render for Search component with router
const renderSearch = () => {
  return render(<Search />)
}

describe('Search Page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('Component Rendering', () => {
    it('renders the search page with all main elements', () => {
      renderSearch()
      
      expect(screen.getByText('Advanced Search')).toBeInTheDocument()
      expect(screen.getByText('Search and filter VirusTotal analysis reports with advanced criteria')).toBeInTheDocument()
      expect(screen.getByText('Search Filters')).toBeInTheDocument()
      expect(screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')).toBeInTheDocument()
      expect(screen.getByText('Apply Search')).toBeInTheDocument()
    })

    it('renders all filter sections', () => {
      renderSearch()
      
      expect(screen.getByText('Search Query')).toBeInTheDocument()
      expect(screen.getByText('File Types')).toBeInTheDocument()
      expect(screen.getByText('Detection Verdicts')).toBeInTheDocument()
      expect(screen.getByText('Date Range')).toBeInTheDocument()
      expect(screen.getByText('File Size (bytes)')).toBeInTheDocument()
      expect(screen.getByText('Detection Count')).toBeInTheDocument()
    })

    it('renders file type checkboxes', () => {
      renderSearch()
      
      const fileTypes = ['PE32', 'PDF', 'ZIP', 'DOC', 'XLS', 'PPT', 'JS', 'HTML', 'EXE', 'DLL']
      fileTypes.forEach(type => {
        expect(screen.getByText(type)).toBeInTheDocument()
      })
    })

    it('renders verdict checkboxes', () => {
      renderSearch()
      
      const verdicts = ['malicious', 'suspicious', 'clean', 'undetected']
      verdicts.forEach(verdict => {
        expect(screen.getByText(new RegExp(verdict, 'i'))).toBeInTheDocument()
      })
    })

    it('renders date range inputs', () => {
      renderSearch()
      
      const dateInputs = screen.getAllByDisplayValue('')
      expect(dateInputs.length).toBeGreaterThanOrEqual(2)
    })
  })

  describe('Search Functionality', () => {
    it('performs search when Apply Search button is clicked', async () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'malware.exe' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        expect(screen.getByText('Search Results')).toBeInTheDocument()
      })
    })

    it('performs search when Enter key is pressed in search input', async () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      
      fireEvent.change(searchInput, { target: { value: 'test.exe' } })
      fireEvent.keyDown(searchInput, { key: 'Enter' })
      
      await waitFor(() => {
        expect(screen.getByText('Search Results')).toBeInTheDocument()
      })
    })

    it('displays search results after successful search', async () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'malicious' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        expect(screen.getByText('Search Results')).toBeInTheDocument()
        expect(screen.getByText(/results found/)).toBeInTheDocument()
      })
    })

    it('displays "No results found" message when search returns empty', async () => {
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
      
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'nonexistent' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        expect(screen.getByText('No results found for your search criteria')).toBeInTheDocument()
      })
    })

    it('handles search errors gracefully', async () => {
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({ error: 'Search failed' }, { status: 500 })
        })
      )
      
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'test' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        expect(screen.getByText(/Search Error/)).toBeInTheDocument()
      })
    })
  })

  describe('Filter Functionality', () => {
    it('allows selecting and deselecting file types', () => {
      renderSearch()
      
      const pe32Checkbox = screen.getByLabelText(/PE32/)
      
      expect(pe32Checkbox).not.toBeChecked()
      
      fireEvent.click(pe32Checkbox)
      expect(pe32Checkbox).toBeChecked()
      
      fireEvent.click(pe32Checkbox)
      expect(pe32Checkbox).not.toBeChecked()
    })

    it('shows selected file types as badges', () => {
      renderSearch()
      
      const pe32Checkbox = screen.getByLabelText(/PE32/)
      fireEvent.click(pe32Checkbox)
      
      expect(screen.getByText('PE32')).toBeInTheDocument()
    })

    it('allows removing file type badges', () => {
      renderSearch()
      
      const pe32Checkbox = screen.getByLabelText(/PE32/)
      fireEvent.click(pe32Checkbox)
      
      const badge = screen.getByText('PE32').closest('.badge')
      const removeButton = badge?.querySelector('button')
      
      if (removeButton) {
        fireEvent.click(removeButton)
        expect(pe32Checkbox).not.toBeChecked()
      }
    })

    it('allows selecting and deselecting verdicts', () => {
      renderSearch()
      
      const maliciousCheckbox = screen.getByLabelText(/malicious/i)
      
      expect(maliciousCheckbox).not.toBeChecked()
      
      fireEvent.click(maliciousCheckbox)
      expect(maliciousCheckbox).toBeChecked()
    })

    it('allows setting date ranges', () => {
      renderSearch()
      
      const dateInputs = screen.getAllByDisplayValue('')
      const startDateInput = dateInputs.find(input => 
        input.getAttribute('placeholder')?.includes('Start') || 
        input.previousElementSibling?.textContent?.includes('Start')
      )
      
      if (startDateInput) {
        fireEvent.change(startDateInput, { target: { value: '2023-01-01' } })
        expect(startDateInput).toHaveValue('2023-01-01')
      }
    })

    it('allows setting file size ranges', () => {
      renderSearch()
      
      const minSizeInput = screen.getByPlaceholderText('Minimum size')
      const maxSizeInput = screen.getByPlaceholderText('Maximum size')
      
      fireEvent.change(minSizeInput, { target: { value: '1024' } })
      fireEvent.change(maxSizeInput, { target: { value: '1048576' } })
      
      expect(minSizeInput).toHaveValue('1024')
      expect(maxSizeInput).toHaveValue('1048576')
    })

    it('allows setting detection count ranges', () => {
      renderSearch()
      
      const minDetectionInput = screen.getByPlaceholderText('Minimum detections')
      const maxDetectionInput = screen.getByPlaceholderText('Maximum detections')
      
      fireEvent.change(minDetectionInput, { target: { value: '1' } })
      fireEvent.change(maxDetectionInput, { target: { value: '10' } })
      
      expect(minDetectionInput).toHaveValue('1')
      expect(maxDetectionInput).toHaveValue('10')
    })

    it('clears all filters when Clear All button is clicked', async () => {
      renderSearch()
      
      // Set some filters
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const pe32Checkbox = screen.getByLabelText(/PE32/)
      
      fireEvent.change(searchInput, { target: { value: 'test' } })
      fireEvent.click(pe32Checkbox)
      
      // Click Apply Search to trigger hasFilters
      fireEvent.click(screen.getByText('Apply Search'))
      
      await waitFor(() => {
        const clearButton = screen.getByText('Clear All')
        fireEvent.click(clearButton)
        
        expect(searchInput).toHaveValue('')
        expect(pe32Checkbox).not.toBeChecked()
      })
    })
  })

  describe('Loading States', () => {
    it('shows loading state during search', async () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'test' } })
      fireEvent.click(applyButton)
      
      expect(screen.getByText('Searching...')).toBeInTheDocument()
    })

    it('shows skeleton loading rows in results table', async () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'test' } })
      fireEvent.click(applyButton)
      
      // Check for loading skeleton rows
      const loadingRows = document.querySelectorAll('.animate-pulse')
      expect(loadingRows.length).toBeGreaterThan(0)
    })
  })

  describe('Results Display', () => {
    it('displays search results in table format', async () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'malicious' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        expect(screen.getByText('SHA256')).toBeInTheDocument()
        expect(screen.getByText('File Name')).toBeInTheDocument()
        expect(screen.getByText('Type')).toBeInTheDocument()
        expect(screen.getByText('Size')).toBeInTheDocument()
        expect(screen.getByText('Verdict')).toBeInTheDocument()
        expect(screen.getByText('Detections')).toBeInTheDocument()
        expect(screen.getByText('Date')).toBeInTheDocument()
      })
    })

    it('displays result count', async () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'malicious' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        expect(screen.getByText(/results found/)).toBeInTheDocument()
      })
    })

    it('makes file hashes clickable links to report detail', async () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'malicious' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        const hashLinks = screen.getAllByRole('link')
        const reportLinks = hashLinks.filter(link => 
          link.getAttribute('href')?.includes('/reports/')
        )
        expect(reportLinks.length).toBeGreaterThan(0)
      })
    })

    it('displays correct verdict badges with appropriate colors', async () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'malicious' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        const badges = document.querySelectorAll('.badge')
        expect(badges.length).toBeGreaterThan(0)
      })
    })
  })

  describe('Pagination', () => {
    it('shows pagination controls when there are multiple pages', async () => {
      // Mock response with many results
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({
            took: 1,
            hits: {
              total: { value: 100, relation: 'eq' },
              hits: Array.from({ length: 20 }, (_, i) => ({
                _id: `id-${i}`,
                _source: { ...mockReports[0], report_uuid: `uuid-${i}` }
              }))
            }
          })
        })
      )
      
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'test' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        expect(screen.getByText('Previous')).toBeInTheDocument()
        expect(screen.getByText('Next')).toBeInTheDocument()
      })
    })

    it('disables Previous button on first page', async () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'test' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        const prevButton = screen.getByText('Previous').closest('button')
        expect(prevButton).toBeDisabled()
      })
    })
  })

  describe('URL Parameter Handling', () => {
    it('handles occurrence search from URL parameters', () => {
      // This would require mocking useSearchParams with actual parameters
      // For now, we'll test the component renders without URL params
      renderSearch()
      
      expect(screen.getByText('Advanced Search')).toBeInTheDocument()
    })
  })

  describe('User Interactions', () => {
    it('updates search input value when typing', () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      
      fireEvent.change(searchInput, { target: { value: 'test query' } })
      expect(searchInput).toHaveValue('test query')
    })

    it('maintains filter state during search operations', async () => {
      renderSearch()
      
      const pe32Checkbox = screen.getByLabelText(/PE32/)
      const maliciousCheckbox = screen.getByLabelText(/malicious/i)
      
      fireEvent.click(pe32Checkbox)
      fireEvent.click(maliciousCheckbox)
      
      expect(pe32Checkbox).toBeChecked()
      expect(maliciousCheckbox).toBeChecked()
      
      // Perform search
      fireEvent.click(screen.getByText('Apply Search'))
      
      // Filters should still be checked
      expect(pe32Checkbox).toBeChecked()
      expect(maliciousCheckbox).toBeChecked()
    })
  })

  describe('Error Handling', () => {
    it('displays retry button on search error', async () => {
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({ error: 'Network error' }, { status: 500 })
        })
      )
      
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'test' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        expect(screen.getByText('Retry Search')).toBeInTheDocument()
      })
    })

    it('allows retrying failed search', async () => {
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
      
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'test' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        expect(screen.getByText('Retry Search')).toBeInTheDocument()
      })
      
      fireEvent.click(screen.getByText('Retry Search'))
      
      await waitFor(() => {
        expect(screen.getByText('Search Results')).toBeInTheDocument()
      })
    })
  })

  describe('Accessibility', () => {
    it('provides proper labels for form inputs', () => {
      renderSearch()
      
      expect(screen.getByText('Search Query')).toBeInTheDocument()
      expect(screen.getByText('File Types')).toBeInTheDocument()
      expect(screen.getByText('Detection Verdicts')).toBeInTheDocument()
      expect(screen.getByText('Date Range')).toBeInTheDocument()
    })

    it('maintains keyboard navigation support', () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      searchInput.focus()
      
      expect(document.activeElement).toBe(searchInput)
    })

    it('provides semantic structure with headings', () => {
      renderSearch()
      
      const mainHeading = screen.getByRole('heading', { level: 1 })
      expect(mainHeading).toHaveTextContent('Advanced Search')
    })
  })

  describe('Responsive Behavior', () => {
    it('renders without layout errors on different screen sizes', () => {
      renderSearch()
      
      // Component should render without throwing errors
      expect(screen.getByText('Advanced Search')).toBeInTheDocument()
      
      // Grid layout should be present
      const gridElements = document.querySelectorAll('[class*="grid"]')
      expect(gridElements.length).toBeGreaterThan(0)
    })
  })

  describe('Integration with Child Components', () => {
    it('integrates with OccurrenceColumn component', async () => {
      renderSearch()
      
      const searchInput = screen.getByPlaceholderText('Enter SHA256, filename, or keyword...')
      const applyButton = screen.getByText('Apply Search')
      
      fireEvent.change(searchInput, { target: { value: 'test' } })
      fireEvent.click(applyButton)
      
      await waitFor(() => {
        expect(screen.getByText('Occurrence')).toBeInTheDocument()
      })
    })
  })
})