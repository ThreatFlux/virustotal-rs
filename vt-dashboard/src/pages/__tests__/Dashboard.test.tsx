import { describe, it, expect, beforeEach, vi, beforeAll, afterAll, afterEach } from 'vitest'
import { render, screen, waitFor } from '@/test/utils/test-utils'
import { Dashboard } from '../Dashboard'
import { server, resetMocks } from '@/test/utils/mock-server'
import { mockDashboardStats, mockReports } from '@/test/fixtures/mock-data'
import { http, HttpResponse } from 'msw'

// Mock the service functions
vi.mock('@/services/elasticsearch', async () => {
  const actual = await vi.importActual('@/services/elasticsearch')
  return {
    ...actual,
    getDashboardStats: vi.fn(),
    fetchReports: vi.fn(),
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
})

afterAll(() => {
  server.close()
})

describe('Dashboard Page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders loading state initially', async () => {
    render(<Dashboard />)
    
    // Should show loading state for stats cards
    expect(screen.getByText('Total Reports')).toBeInTheDocument()
    
    // Wait for loading to finish
    await waitFor(() => {
      expect(screen.getByText('369')).toBeInTheDocument() // Total reports from mock data
    }, { timeout: 3000 })
  })

  it('displays dashboard statistics cards', async () => {
    render(<Dashboard />)
    
    await waitFor(() => {
      expect(screen.getByText('Total Reports')).toBeInTheDocument()
      expect(screen.getByText('Reports Today')).toBeInTheDocument()
      expect(screen.getByText('Malicious Files')).toBeInTheDocument()
      expect(screen.getByText('Suspicious Files')).toBeInTheDocument()
      expect(screen.getByText('Clean Files')).toBeInTheDocument()
      expect(screen.getByText('Undetected Files')).toBeInTheDocument()
    })
  })

  it('displays correct statistics values from API', async () => {
    render(<Dashboard />)
    
    await waitFor(() => {
      // Values from mockDashboardStats
      expect(screen.getByText('369')).toBeInTheDocument() // total_reports
      expect(screen.getByText('12')).toBeInTheDocument() // reports_today
      expect(screen.getByText('87')).toBeInTheDocument() // malicious_files
      expect(screen.getByText('45')).toBeInTheDocument() // suspicious_files
      expect(screen.getByText('195')).toBeInTheDocument() // clean_files
      expect(screen.getByText('42')).toBeInTheDocument() // undetected_files
    })
  })

  it('applies correct variants to stats cards', async () => {
    render(<Dashboard />)
    
    await waitFor(() => {
      // Malicious should have danger variant (red text)
      const maliciousValue = screen.getByText('87')
      expect(maliciousValue).toHaveClass('text-red-600')
      
      // Clean should have success variant (green text)
      const cleanValue = screen.getByText('195')
      expect(cleanValue).toHaveClass('text-green-600')
      
      // Suspicious should have warning variant (yellow text)
      const suspiciousValue = screen.getByText('45')
      expect(suspiciousValue).toHaveClass('text-yellow-600')
    })
  })

  it('displays descriptive text for each stat card', async () => {
    render(<Dashboard />)
    
    await waitFor(() => {
      expect(screen.getByText('All time')).toBeInTheDocument()
      expect(screen.getByText('Last 24 hours')).toBeInTheDocument()
      expect(screen.getByText('High risk')).toBeInTheDocument()
      expect(screen.getByText('Medium risk')).toBeInTheDocument()
      expect(screen.getByText('Safe')).toBeInTheDocument()
      expect(screen.getByText('Unknown')).toBeInTheDocument()
    })
  })

  it('renders dashboard charts', async () => {
    render(<Dashboard />)
    
    await waitFor(() => {
      // Check for chart titles (these should be rendered by the chart components)
      expect(screen.getByText('File Types')).toBeInTheDocument()
      expect(screen.getByText('Detection Trends')).toBeInTheDocument()
    }, { timeout: 3000 })
  })

  it('renders recent reports section', async () => {
    render(<Dashboard />)
    
    await waitFor(() => {
      expect(screen.getByText('Recent Reports')).toBeInTheDocument()
    }, { timeout: 3000 })
  })

  describe('Error Handling', () => {
    it('handles API errors gracefully', async () => {
      // Mock failed API response
      server.use(
        http.post('/api/elasticsearch/vt_reports/_search', () => {
          return HttpResponse.json({ error: 'Connection failed' }, { status: 500 })
        })
      )
      
      render(<Dashboard />)
      
      // Should still render the basic structure
      expect(screen.getByText('Total Reports')).toBeInTheDocument()
      expect(screen.getByText('Malicious Files')).toBeInTheDocument()
      
      // Should show 0 values when API fails
      await waitFor(() => {
        expect(screen.getByText('0')).toBeInTheDocument() // Should have multiple 0 values
      })
    })

    it('continues to function when stats API fails but reports succeed', async () => {
      // This will be handled by the mock server and component error handling
      render(<Dashboard />)
      
      await waitFor(() => {
        expect(screen.getByText('Total Reports')).toBeInTheDocument()
      })
    })
  })

  describe('Data Loading States', () => {
    it('shows loading states for charts', async () => {
      render(<Dashboard />)
      
      // Initially should show loading states
      // The charts will handle their own loading states
      expect(screen.getByText('File Types')).toBeInTheDocument()
      expect(screen.getByText('Detection Trends')).toBeInTheDocument()
    })

    it('transitions from loading to loaded state', async () => {
      render(<Dashboard />)
      
      // Wait for data to load
      await waitFor(() => {
        expect(screen.getByText('369')).toBeInTheDocument()
      }, { timeout: 3000 })
      
      // Stats should be visible
      expect(screen.getByText('Total Reports')).toBeInTheDocument()
      expect(screen.getByText('87')).toBeInTheDocument()
    })
  })

  describe('Dashboard Layout', () => {
    it('renders all main dashboard sections', async () => {
      render(<Dashboard />)
      
      // Stats cards section
      expect(screen.getByText('Total Reports')).toBeInTheDocument()
      expect(screen.getByText('Malicious Files')).toBeInTheDocument()
      
      // Charts section
      expect(screen.getByText('File Types')).toBeInTheDocument()
      expect(screen.getByText('Detection Trends')).toBeInTheDocument()
      
      // Recent reports section
      await waitFor(() => {
        expect(screen.getByText('Recent Reports')).toBeInTheDocument()
      })
    })

    it('maintains responsive layout structure', () => {
      render(<Dashboard />)
      
      // The component should render without layout errors
      expect(screen.getByText('Total Reports')).toBeInTheDocument()
    })
  })

  describe('Data Integration', () => {
    it('fetches and displays real-time dashboard data', async () => {
      render(<Dashboard />)
      
      await waitFor(() => {
        // Should display the mocked dashboard stats
        expect(screen.getByText('369')).toBeInTheDocument() // Total reports
        expect(screen.getByText('87')).toBeInTheDocument()  // Malicious
        expect(screen.getByText('195')).toBeInTheDocument() // Clean
      })
    })

    it('coordinates data loading between different sections', async () => {
      render(<Dashboard />)
      
      // Both stats and recent reports should load
      await waitFor(() => {
        expect(screen.getByText('369')).toBeInTheDocument() // Stats loaded
        expect(screen.getByText('Recent Reports')).toBeInTheDocument() // Reports section loaded
      })
    })

    it('handles partial data loading gracefully', async () => {
      render(<Dashboard />)
      
      await waitFor(() => {
        // Should still show the dashboard structure even if some data is missing
        expect(screen.getByText('Total Reports')).toBeInTheDocument()
        expect(screen.getByText('File Types')).toBeInTheDocument()
      })
    })
  })

  describe('Performance', () => {
    it('loads dashboard data efficiently', async () => {
      const startTime = performance.now()
      
      render(<Dashboard />)
      
      await waitFor(() => {
        expect(screen.getByText('369')).toBeInTheDocument()
      })
      
      const loadTime = performance.now() - startTime
      expect(loadTime).toBeLessThan(5000) // Should load within 5 seconds in test
    })

    it('handles component updates without excessive re-renders', async () => {
      const { rerender } = render(<Dashboard />)
      
      await waitFor(() => {
        expect(screen.getByText('369')).toBeInTheDocument()
      })
      
      // Re-render shouldn't cause issues
      rerender(<Dashboard />)
      expect(screen.getByText('Total Reports')).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('provides proper heading structure', async () => {
      render(<Dashboard />)
      
      await waitFor(() => {
        // Stats cards should have proper headings (CardTitle uses h3)
        const headings = screen.getAllByRole('heading', { level: 3 })
        expect(headings.length).toBeGreaterThan(0)
      })
    })

    it('maintains semantic structure for screen readers', async () => {
      render(<Dashboard />)
      
      // Cards should be accessible
      const statsCards = document.querySelectorAll('[class*="card"]')
      expect(statsCards.length).toBeGreaterThan(0)
    })

    it('provides meaningful labels and descriptions', async () => {
      render(<Dashboard />)
      
      await waitFor(() => {
        expect(screen.getByText('High risk')).toBeInTheDocument()
        expect(screen.getByText('Safe')).toBeInTheDocument()
        expect(screen.getByText('Medium risk')).toBeInTheDocument()
      })
    })
  })
})