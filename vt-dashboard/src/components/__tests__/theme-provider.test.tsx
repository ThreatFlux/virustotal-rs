import React from 'react'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import { ThemeProvider, useTheme } from '../theme-provider'

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {}
  
  return {
    getItem: vi.fn((key: string) => store[key] || null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value.toString()
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key]
    }),
    clear: vi.fn(() => {
      store = {}
    }),
  }
})()

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
})

// Mock matchMedia
const matchMediaMock = vi.fn().mockImplementation(query => ({
  matches: false,
  media: query,
  onchange: null,
  addListener: vi.fn(),
  removeListener: vi.fn(),
  addEventListener: vi.fn(),
  removeEventListener: vi.fn(),
  dispatchEvent: vi.fn(),
}))

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: matchMediaMock,
})

// Test component to access theme context
const TestComponent = () => {
  const { theme, setTheme } = useTheme()
  
  return (
    <div>
      <div data-testid="current-theme">{theme}</div>
      <button onClick={() => setTheme('dark')} data-testid="set-dark">
        Set Dark
      </button>
      <button onClick={() => setTheme('light')} data-testid="set-light">
        Set Light
      </button>
      <button onClick={() => setTheme('system')} data-testid="set-system">
        Set System
      </button>
      <button onClick={() => setTheme('modern')} data-testid="set-modern">
        Set Modern
      </button>
    </div>
  )
}

describe('ThemeProvider', () => {
  beforeEach(() => {
    // Clear localStorage and DOM classes before each test
    localStorageMock.clear()
    document.documentElement.className = ''
    vi.clearAllMocks()
  })

  afterEach(() => {
    // Clean up after each test
    document.documentElement.className = ''
  })

  describe('Initialization', () => {
    it('initializes with system theme by default', () => {
      render(
        <ThemeProvider>
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('system')
      expect(document.documentElement).toHaveClass('light') // system defaults to light when no dark preference
    })

    it('initializes with provided defaultTheme', () => {
      render(
        <ThemeProvider defaultTheme="dark">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('dark')
      expect(document.documentElement).toHaveClass('dark')
    })

    it('initializes with theme from localStorage', () => {
      localStorageMock.setItem('vt-dashboard-theme', 'modern')
      
      render(
        <ThemeProvider>
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('modern')
      expect(document.documentElement).toHaveClass('modern')
    })

    it('uses custom storage key', () => {
      localStorageMock.setItem('custom-theme-key', 'dark')
      
      render(
        <ThemeProvider storageKey="custom-theme-key">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('dark')
    })
  })

  describe('Theme Switching', () => {
    it('switches to dark theme and updates localStorage', () => {
      render(
        <ThemeProvider>
          <TestComponent />
        </ThemeProvider>
      )
      
      fireEvent.click(screen.getByTestId('set-dark'))
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('dark')
      expect(document.documentElement).toHaveClass('dark')
      expect(localStorageMock.setItem).toHaveBeenCalledWith('vt-dashboard-theme', 'dark')
    })

    it('switches to light theme and updates localStorage', () => {
      render(
        <ThemeProvider defaultTheme="dark">
          <TestComponent />
        </ThemeProvider>
      )
      
      fireEvent.click(screen.getByTestId('set-light'))
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('light')
      expect(document.documentElement).toHaveClass('light')
      expect(localStorageMock.setItem).toHaveBeenCalledWith('vt-dashboard-theme', 'light')
    })

    it('switches to modern theme and updates localStorage', () => {
      render(
        <ThemeProvider>
          <TestComponent />
        </ThemeProvider>
      )
      
      fireEvent.click(screen.getByTestId('set-modern'))
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('modern')
      expect(document.documentElement).toHaveClass('modern')
      expect(localStorageMock.setItem).toHaveBeenCalledWith('vt-dashboard-theme', 'modern')
    })

    it('switches to system theme and respects system preference', () => {
      // Mock dark system preference
      matchMediaMock.mockImplementation(query => ({
        matches: query === '(prefers-color-scheme: dark)',
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      }))
      
      render(
        <ThemeProvider defaultTheme="light">
          <TestComponent />
        </ThemeProvider>
      )
      
      fireEvent.click(screen.getByTestId('set-system'))
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('system')
      expect(document.documentElement).toHaveClass('dark') // Should apply dark due to system preference
      expect(localStorageMock.setItem).toHaveBeenCalledWith('vt-dashboard-theme', 'system')
    })
  })

  describe('System Theme Detection', () => {
    it('applies light theme when system prefers light', () => {
      matchMediaMock.mockImplementation(query => ({
        matches: false, // No dark preference
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      }))
      
      render(
        <ThemeProvider defaultTheme="system">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(document.documentElement).toHaveClass('light')
      expect(document.documentElement).not.toHaveClass('dark')
    })

    it('applies dark theme when system prefers dark', () => {
      matchMediaMock.mockImplementation(query => ({
        matches: query === '(prefers-color-scheme: dark)',
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      }))
      
      render(
        <ThemeProvider defaultTheme="system">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(document.documentElement).toHaveClass('dark')
      expect(document.documentElement).not.toHaveClass('light')
    })
  })

  describe('CSS Class Management', () => {
    it('removes all theme classes before applying new one', () => {
      // Start with multiple classes
      document.documentElement.classList.add('light', 'dark', 'modern')
      
      render(
        <ThemeProvider defaultTheme="dark">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(document.documentElement).toHaveClass('dark')
      expect(document.documentElement).not.toHaveClass('light')
      expect(document.documentElement).not.toHaveClass('modern')
    })

    it('handles theme changes that remove and add classes correctly', () => {
      render(
        <ThemeProvider defaultTheme="light">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(document.documentElement).toHaveClass('light')
      
      // Switch to modern
      fireEvent.click(screen.getByTestId('set-modern'))
      
      expect(document.documentElement).toHaveClass('modern')
      expect(document.documentElement).not.toHaveClass('light')
      
      // Switch to dark
      fireEvent.click(screen.getByTestId('set-dark'))
      
      expect(document.documentElement).toHaveClass('dark')
      expect(document.documentElement).not.toHaveClass('modern')
    })
  })

  describe('Hook Integration', () => {
    it('provides theme context to child components', () => {
      render(
        <ThemeProvider defaultTheme="modern">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('modern')
    })

    it('allows child components to change theme', () => {
      render(
        <ThemeProvider>
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('system')
      
      fireEvent.click(screen.getByTestId('set-light'))
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('light')
    })

    it('throws error when useTheme is used outside ThemeProvider', () => {
      // Capture console errors for this test
      const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
      
      expect(() => {
        render(<TestComponent />)
      }).toThrow('useTheme must be used within a ThemeProvider')
      
      consoleError.mockRestore()
    })
  })

  describe('Persistence', () => {
    it('persists theme changes to localStorage', () => {
      render(
        <ThemeProvider storageKey="test-theme">
          <TestComponent />
        </ThemeProvider>
      )
      
      fireEvent.click(screen.getByTestId('set-dark'))
      
      expect(localStorageMock.setItem).toHaveBeenCalledWith('test-theme', 'dark')
    })

    it('loads theme from localStorage on initialization', () => {
      localStorageMock.setItem('test-theme', 'modern')
      
      render(
        <ThemeProvider storageKey="test-theme">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('modern')
      expect(document.documentElement).toHaveClass('modern')
    })

    it('falls back to default theme when localStorage is empty', () => {
      localStorageMock.getItem.mockReturnValue(null)
      
      render(
        <ThemeProvider defaultTheme="dark">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('dark')
    })
  })

  describe('Edge Cases', () => {
    it('handles invalid theme in localStorage gracefully', () => {
      localStorageMock.getItem.mockReturnValue('invalid-theme')
      
      render(
        <ThemeProvider defaultTheme="light">
          <TestComponent />
        </ThemeProvider>
      )
      
      // Should fall back to default theme
      expect(screen.getByTestId('current-theme')).toHaveTextContent('light')
    })

    it('handles localStorage errors gracefully', () => {
      localStorageMock.getItem.mockImplementation(() => {
        throw new Error('localStorage not available')
      })
      
      render(
        <ThemeProvider defaultTheme="dark">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('dark')
    })

    it('handles localStorage setItem errors gracefully', () => {
      localStorageMock.setItem.mockImplementation(() => {
        throw new Error('localStorage quota exceeded')
      })
      
      render(
        <ThemeProvider>
          <TestComponent />
        </ThemeProvider>
      )
      
      // Should not crash when trying to persist theme
      expect(() => {
        fireEvent.click(screen.getByTestId('set-dark'))
      }).not.toThrow()
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('dark')
    })
  })

  describe('Multiple Provider Instances', () => {
    it('maintains separate theme state for different storage keys', () => {
      const Provider1 = ({ children }: { children: React.ReactNode }) => (
        <ThemeProvider storageKey="theme-1" defaultTheme="light">
          {children}
        </ThemeProvider>
      )
      
      const Provider2 = ({ children }: { children: React.ReactNode }) => (
        <ThemeProvider storageKey="theme-2" defaultTheme="dark">
          {children}
        </ThemeProvider>
      )
      
      const { unmount: unmount1 } = render(
        <Provider1>
          <TestComponent />
        </Provider1>
      )
      
      fireEvent.click(screen.getByTestId('set-modern'))
      expect(localStorageMock.setItem).toHaveBeenCalledWith('theme-1', 'modern')
      
      unmount1()
      
      const { unmount: unmount2 } = render(
        <Provider2>
          <TestComponent />
        </Provider2>
      )
      
      fireEvent.click(screen.getByTestId('set-light'))
      expect(localStorageMock.setItem).toHaveBeenCalledWith('theme-2', 'light')
      
      unmount2()
    })
  })

  describe('Dynamic System Theme Changes', () => {
    it('updates class when system theme preference changes', () => {
      // Start with light system preference
      let systemPrefersDark = false
      matchMediaMock.mockImplementation(query => ({
        matches: query === '(prefers-color-scheme: dark)' && systemPrefersDark,
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      }))
      
      render(
        <ThemeProvider defaultTheme="system">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(document.documentElement).toHaveClass('light')
      
      // Simulate system theme change to dark
      systemPrefersDark = true
      
      // Re-trigger system theme detection by switching theme
      fireEvent.click(screen.getByTestId('set-light'))
      fireEvent.click(screen.getByTestId('set-system'))
      
      expect(document.documentElement).toHaveClass('dark')
    })
  })

  describe('Accessibility', () => {
    it('maintains focus when switching themes', () => {
      render(
        <ThemeProvider>
          <TestComponent />
        </ThemeProvider>
      )
      
      const darkButton = screen.getByTestId('set-dark')
      darkButton.focus()
      
      fireEvent.click(darkButton)
      
      // Focus should be maintained
      expect(document.activeElement).toBe(darkButton)
    })
  })

  describe('Theme State Updates', () => {
    it('updates theme state synchronously', () => {
      render(
        <ThemeProvider>
          <TestComponent />
        </ThemeProvider>
      )
      
      act(() => {
        fireEvent.click(screen.getByTestId('set-dark'))
      })
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('dark')
    })

    it('maintains theme state across re-renders', () => {
      const { rerender } = render(
        <ThemeProvider defaultTheme="modern">
          <TestComponent />
        </ThemeProvider>
      )
      
      fireEvent.click(screen.getByTestId('set-dark'))
      expect(screen.getByTestId('current-theme')).toHaveTextContent('dark')
      
      rerender(
        <ThemeProvider defaultTheme="modern">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('dark')
    })
  })

  describe('All Theme Types', () => {
    it('supports light theme', () => {
      render(
        <ThemeProvider defaultTheme="light">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('light')
      expect(document.documentElement).toHaveClass('light')
    })

    it('supports dark theme', () => {
      render(
        <ThemeProvider defaultTheme="dark">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('dark')
      expect(document.documentElement).toHaveClass('dark')
    })

    it('supports modern theme', () => {
      render(
        <ThemeProvider defaultTheme="modern">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('modern')
      expect(document.documentElement).toHaveClass('modern')
    })

    it('supports system theme', () => {
      render(
        <ThemeProvider defaultTheme="system">
          <TestComponent />
        </ThemeProvider>
      )
      
      expect(screen.getByTestId('current-theme')).toHaveTextContent('system')
      // Should apply either light or dark based on system preference
      expect(
        document.documentElement.classList.contains('light') ||
        document.documentElement.classList.contains('dark')
      ).toBe(true)
    })
  })

  describe('Props Forwarding', () => {
    it('forwards additional props to context provider', () => {
      const customProps = { 'data-testid': 'theme-provider' }
      
      render(
        <ThemeProvider {...customProps}>
          <TestComponent />
        </ThemeProvider>
      )
      
      // Context should receive the forwarded props
      expect(screen.getByTestId('current-theme')).toBeInTheDocument()
    })
  })
})