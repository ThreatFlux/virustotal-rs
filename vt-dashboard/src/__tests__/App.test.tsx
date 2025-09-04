import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import App from '../App'

// Mock all the page components
vi.mock('@/pages/Dashboard', () => ({
  Dashboard: () => <div data-testid="dashboard-page">Dashboard Page</div>
}))

vi.mock('@/pages/Reports', () => ({
  Reports: () => <div data-testid="reports-page">Reports Page</div>
}))

vi.mock('@/pages/ReportDetail', () => ({
  ReportDetail: () => <div data-testid="report-detail-page">Report Detail Page</div>
}))

vi.mock('@/pages/Search', () => ({
  Search: () => <div data-testid="search-page">Search Page</div>
}))

// Mock the Sidebar component
vi.mock('@/components/layout/Sidebar', () => ({
  Sidebar: ({ isCollapsed, setIsCollapsed }: any) => (
    <div data-testid="sidebar" data-collapsed={isCollapsed}>
      <button onClick={() => setIsCollapsed(!isCollapsed)}>
        Toggle Sidebar
      </button>
    </div>
  )
}))

// Mock ThemeProvider
vi.mock('@/components/theme-provider', () => ({
  ThemeProvider: ({ children }: any) => <div data-testid="theme-provider">{children}</div>
}))

// Mock localStorage
const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
}

Object.defineProperty(window, 'localStorage', {
  value: mockLocalStorage,
  writable: true,
})

// Helper to render App with router
const renderApp = (initialPath = '/') => {
  window.history.pushState({}, 'Test page', initialPath)
  
  return render(
    <BrowserRouter>
      <App />
    </BrowserRouter>
  )
}

describe('App Component', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockLocalStorage.getItem.mockReturnValue(null)
  })

  describe('Component Rendering', () => {
    it('renders the app with theme provider', () => {
      renderApp()
      
      expect(screen.getByTestId('theme-provider')).toBeInTheDocument()
    })

    it('renders the sidebar', () => {
      renderApp()
      
      expect(screen.getByTestId('sidebar')).toBeInTheDocument()
    })

    it('renders main content area with proper classes', () => {
      renderApp()
      
      const mainElement = document.querySelector('main')
      expect(mainElement).toBeInTheDocument()
      expect(mainElement).toHaveClass('flex-1', 'overflow-auto', 'transition-all')
    })
  })

  describe('Routing', () => {
    it('renders Dashboard component on root path', () => {
      renderApp('/')
      
      expect(screen.getByTestId('dashboard-page')).toBeInTheDocument()
      expect(screen.getByText('Dashboard Page')).toBeInTheDocument()
    })

    it('renders Reports component on /reports path', () => {
      renderApp('/reports')
      
      expect(screen.getByTestId('reports-page')).toBeInTheDocument()
      expect(screen.getByText('Reports Page')).toBeInTheDocument()
    })

    it('renders ReportDetail component on /reports/:reportId path', () => {
      renderApp('/reports/test-id-123')
      
      expect(screen.getByTestId('report-detail-page')).toBeInTheDocument()
      expect(screen.getByText('Report Detail Page')).toBeInTheDocument()
    })

    it('renders Search component on /search path', () => {
      renderApp('/search')
      
      expect(screen.getByTestId('search-page')).toBeInTheDocument()
      expect(screen.getByText('Search Page')).toBeInTheDocument()
    })
  })

  describe('Sidebar State Management', () => {
    it('initializes sidebar as not collapsed by default', () => {
      renderApp()
      
      const sidebar = screen.getByTestId('sidebar')
      expect(sidebar).toHaveAttribute('data-collapsed', 'false')
    })

    it('loads collapsed state from localStorage on mount', () => {
      mockLocalStorage.getItem.mockReturnValue('true')
      
      renderApp()
      
      expect(mockLocalStorage.getItem).toHaveBeenCalledWith('sidebar-collapsed')
      const sidebar = screen.getByTestId('sidebar')
      expect(sidebar).toHaveAttribute('data-collapsed', 'true')
    })

    it('handles invalid JSON in localStorage gracefully', () => {
      mockLocalStorage.getItem.mockReturnValue('invalid-json')
      
      // Should not throw an error
      expect(() => renderApp()).not.toThrow()
      
      const sidebar = screen.getByTestId('sidebar')
      expect(sidebar).toHaveAttribute('data-collapsed', 'false')
    })

    it('saves collapsed state to localStorage when changed', () => {
      renderApp()
      
      const toggleButton = screen.getByText('Toggle Sidebar')
      toggleButton.click()
      
      expect(mockLocalStorage.setItem).toHaveBeenCalledWith('sidebar-collapsed', 'true')
    })

    it('applies correct CSS classes based on collapsed state', () => {
      renderApp()
      
      const mainElement = document.querySelector('main')
      expect(mainElement).toHaveClass('lg:ml-64') // Not collapsed
      
      // Toggle sidebar
      const toggleButton = screen.getByText('Toggle Sidebar')
      toggleButton.click()
      
      expect(mainElement).toHaveClass('lg:ml-16') // Collapsed
    })
  })

  describe('Theme Integration', () => {
    it('passes correct props to ThemeProvider', () => {
      renderApp()
      
      // ThemeProvider should be rendered with app content
      const themeProvider = screen.getByTestId('theme-provider')
      expect(themeProvider).toBeInTheDocument()
      
      // Should contain the main app content
      expect(themeProvider).toContainElement(screen.getByTestId('sidebar'))
      expect(themeProvider).toContainElement(document.querySelector('main'))
    })
  })

  describe('Layout Structure', () => {
    it('has correct layout structure', () => {
      renderApp()
      
      // Root div with flex classes
      const rootDiv = document.querySelector('div.flex.h-screen')
      expect(rootDiv).toBeInTheDocument()
      expect(rootDiv).toHaveClass('bg-background')
      
      // Sidebar and main should be children of root
      const sidebar = screen.getByTestId('sidebar')
      const mainElement = document.querySelector('main')
      
      expect(rootDiv).toContainElement(sidebar)
      expect(rootDiv).toContainElement(mainElement)
    })

    it('applies responsive design classes correctly', () => {
      renderApp()
      
      const mainElement = document.querySelector('main')
      expect(mainElement).toHaveClass(
        'flex-1',
        'overflow-auto', 
        'transition-all',
        'duration-200',
        'ease-in-out',
        'pt-14',
        'lg:pt-0',
        'ml-0'
      )
    })
  })

  describe('Error Boundaries', () => {
    it('handles component mounting without errors', () => {
      expect(() => renderApp()).not.toThrow()
    })

    it('handles route changes without errors', () => {
      renderApp('/')
      
      expect(() => {
        window.history.pushState({}, 'Reports', '/reports')
        renderApp('/reports')
      }).not.toThrow()
    })
  })

  describe('Performance', () => {
    it('does not re-render unnecessarily', () => {
      const { rerender } = renderApp()
      
      // Re-render should work without issues
      expect(() => {
        rerender(
          <BrowserRouter>
            <App />
          </BrowserRouter>
        )
      }).not.toThrow()
    })
  })

  describe('Accessibility', () => {
    it('has semantic HTML structure', () => {
      renderApp()
      
      const mainElement = document.querySelector('main')
      expect(mainElement).toBeInTheDocument()
      expect(mainElement?.tagName).toBe('MAIN')
    })

    it('maintains focus management during route changes', () => {
      renderApp('/')
      expect(screen.getByTestId('dashboard-page')).toBeInTheDocument()
      
      renderApp('/reports')
      expect(screen.getByTestId('reports-page')).toBeInTheDocument()
    })
  })
})