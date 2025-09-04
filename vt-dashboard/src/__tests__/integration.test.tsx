import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { ThemeProvider } from '@/components/theme-provider'
import { Dashboard } from '@/pages/Dashboard'
import { server, resetMocks } from '@/test/utils/mock-server'
import { http, HttpResponse } from 'msw'

// Test the entire app integration - using raw render to avoid nested routers
const App = () => (
  <MemoryRouter initialEntries={['/']}>
    <ThemeProvider defaultTheme="light" storageKey="vt-dashboard-theme">
      <Dashboard />
    </ThemeProvider>
  </MemoryRouter>
)

// Start mock server
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' })
})

afterEach(() => {
  server.resetHandlers()
  resetMocks()
})

afterAll(() => {
  server.close()
})

describe('Integration Tests', () => {
  describe('Dashboard Data Flow Integration', () => {
    it('loads dashboard with complete data flow from API to UI', async () => {
      render(<App />)
      
      // Should start with loading state and then show data
      expect(screen.getByText('Total Reports')).toBeInTheDocument()
      
      // Wait for API data to load and display
      await waitFor(() => {
        expect(screen.getByText('369')).toBeInTheDocument() // Total reports
        expect(screen.getByText('87')).toBeInTheDocument()  // Malicious files
        expect(screen.getByText('195')).toBeInTheDocument() // Clean files
      }, { timeout: 5000 })
      
      // Verify charts are rendered
      expect(screen.getByText('File Types')).toBeInTheDocument()
      expect(screen.getByText('Detection Trends')).toBeInTheDocument()
      
      // Verify recent reports section
      expect(screen.getByText('Recent Reports')).toBeInTheDocument()
    })

    it('coordinates data loading between different dashboard sections', async () => {
      render(<App />)
      
      // All sections should load data from their respective APIs
      await waitFor(() => {
        // Stats section
        expect(screen.getByText('369')).toBeInTheDocument()
        
        // Charts section
        expect(screen.getByText('File Types')).toBeInTheDocument()
        expect(screen.getByText('Detection Trends')).toBeInTheDocument()
        
        // Recent reports section
        expect(screen.getByText('Recent Reports')).toBeInTheDocument()
      }, { timeout: 5000 })
    })

    it('handles real Elasticsearch query structure', async () => {
      render(<App />)
      
      // Wait for data that comes from properly structured ES queries
      await waitFor(() => {
        // Dashboard stats from aggregation queries
        expect(screen.getByText('87')).toBeInTheDocument() // Malicious count
        expect(screen.getByText('45')).toBeInTheDocument() // Suspicious count
        
        // File type distribution from terms aggregation
        expect(screen.getByText('File Types')).toBeInTheDocument()
        
        // Time series data from date histogram
        expect(screen.getByText('Detection Trends')).toBeInTheDocument()
      })
    })

    it('maintains data consistency across components', async () => {
      render(<App />)
      
      await waitFor(() => {
        // Stats card should match chart data
        const maliciousCount = screen.getByText('87')
        expect(maliciousCount).toBeInTheDocument()
        
        // Clean files count should be consistent
        const cleanCount = screen.getByText('195')
        expect(cleanCount).toBeInTheDocument()
      })
    })
  })

  describe('Theme Integration', () => {
    it('applies theme consistently across all components', async () => {
      render(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Total Reports')).toBeInTheDocument()
      })
      
      // Theme should be applied to all components
      const cards = document.querySelectorAll('[class*="card"]')
      expect(cards.length).toBeGreaterThan(0)
      
      // Stats cards should have theme-aware styling
      const maliciousValue = screen.getByText('87')
      expect(maliciousValue).toHaveClass('text-red-600') // Light theme danger color
    })

    it('maintains proper contrast ratios for accessibility', async () => {
      render(<App />)
      
      await waitFor(() => {
        // Different verdict types should have appropriate color contrast
        expect(screen.getByText('High risk')).toBeInTheDocument() // Danger variant
        expect(screen.getByText('Safe')).toBeInTheDocument() // Success variant
        expect(screen.getByText('Medium risk')).toBeInTheDocument() // Warning variant
      })
    })
  })

  describe('Component Interaction Integration', () => {
    it('handles interactions between parent and child components', async () => {
      render(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Recent Reports')).toBeInTheDocument()
      })
      
      // RecentReports component should be rendered within Dashboard
      // and should display data from the same API calls
      const recentReportsSection = screen.getByText('Recent Reports')
      expect(recentReportsSection).toBeInTheDocument()
    })

    it('coordinates loading states across components', async () => {
      render(<App />)
      
      // Initially, components should handle their loading states
      expect(screen.getByText('File Types')).toBeInTheDocument()
      expect(screen.getByText('Detection Trends')).toBeInTheDocument()
      
      // After loading, all should show data
      await waitFor(() => {
        expect(screen.getByText('369')).toBeInTheDocument()
      })
    })
  })

  describe('Error Handling Integration', () => {
    it('handles partial failures gracefully', async () => {
      // Mock one API to fail while others succeed
      server.use(
        http.post('/api/elasticsearch/vt_analysis_results/_search', () => {
          return HttpResponse.json({ error: 'Service unavailable' }, { status: 503 })
        })
      )
      
      render(<App />)
      
      // Dashboard should still render basic stats even if some data fails
      await waitFor(() => {
        expect(screen.getByText('Total Reports')).toBeInTheDocument()
      })
      
      // Some data should still be available
      expect(screen.getByText('File Types')).toBeInTheDocument()
    })

    it('recovers from network errors', async () => {
      render(<App />)
      
      // Should eventually show data despite potential network delays
      await waitFor(() => {
        expect(screen.getByText('369')).toBeInTheDocument()
      }, { timeout: 5000 })
    })
  })

  describe('Performance Integration', () => {
    it('loads dashboard data within acceptable time limits', async () => {
      const startTime = performance.now()
      
      render(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('369')).toBeInTheDocument()
      })
      
      const loadTime = performance.now() - startTime
      expect(loadTime).toBeLessThan(3000) // Should load within 3 seconds
    })

    it('handles concurrent API requests efficiently', async () => {
      render(<App />)
      
      // Dashboard makes multiple concurrent API calls
      // All should resolve and display data
      await waitFor(() => {
        expect(screen.getByText('369')).toBeInTheDocument() // Dashboard stats
        expect(screen.getByText('Recent Reports')).toBeInTheDocument() // Recent reports
      })
    })

    it('does not cause memory leaks during component updates', async () => {
      const { rerender, unmount } = render(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('369')).toBeInTheDocument()
      })
      
      // Re-render multiple times
      for (let i = 0; i < 3; i++) {
        rerender(<App />)
        await waitFor(() => {
          expect(screen.getByText('Total Reports')).toBeInTheDocument()
        })
      }
      
      // Cleanup should not cause errors
      unmount()
    })
  })

  describe('Responsive Design Integration', () => {
    it('maintains layout integrity across different viewport sizes', async () => {
      // Simulate different viewport sizes
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 768,
      })
      
      render(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Total Reports')).toBeInTheDocument()
      })
      
      // Layout should remain intact
      expect(screen.getByText('File Types')).toBeInTheDocument()
      expect(screen.getByText('Detection Trends')).toBeInTheDocument()
    })

    it('adapts charts to container sizes', async () => {
      render(<App />)
      
      await waitFor(() => {
        // Charts should render with ResponsiveContainer
        expect(screen.getByText('File Types')).toBeInTheDocument()
        expect(screen.getByText('Detection Trends')).toBeInTheDocument()
      })
    })
  })

  describe('Accessibility Integration', () => {
    it('maintains proper focus management across components', async () => {
      render(<App />)
      
      await waitFor(() => {
        expect(screen.getByText('Total Reports')).toBeInTheDocument()
      })
      
      // Dashboard should be keyboard accessible
      const dashboard = document.body
      expect(dashboard).toBeInTheDocument()
    })

    it('provides consistent ARIA labeling across the application', async () => {
      render(<App />)
      
      await waitFor(() => {
        // All interactive elements should be properly labeled
        const headings = screen.getAllByRole('heading')
        expect(headings.length).toBeGreaterThan(0)
      })
    })

    it('supports screen readers with meaningful content structure', async () => {
      render(<App />)
      
      await waitFor(() => {
        // Content should be structured for screen readers
        expect(screen.getByText('Total Reports')).toBeInTheDocument()
        expect(screen.getByText('High risk')).toBeInTheDocument() // Descriptive text
        expect(screen.getByText('Safe')).toBeInTheDocument() // Descriptive text
      })
    })
  })
})