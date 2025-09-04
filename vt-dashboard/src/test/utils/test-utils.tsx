import React, { ReactElement } from 'react'
import { render, RenderOptions } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import { ThemeProvider } from '@/components/theme-provider'

// Create a custom render function that includes providers
const AllTheProviders = ({ children }: { children: React.ReactNode }) => {
  return (
    <BrowserRouter>
      <ThemeProvider defaultTheme="light" storageKey="vt-dashboard-theme">
        {children}
      </ThemeProvider>
    </BrowserRouter>
  )
}

const customRender = (
  ui: ReactElement,
  options?: Omit<RenderOptions, 'wrapper'>
) => render(ui, { wrapper: AllTheProviders, ...options })

export * from '@testing-library/react'
export { customRender as render }

// Custom render for components that need specific router state
export const renderWithRouter = (
  ui: ReactElement,
  { initialEntries = ['/'] } = {}
) => {
  const Wrapper = ({ children }: { children: React.ReactNode }) => (
    <BrowserRouter>
      <ThemeProvider defaultTheme="light" storageKey="vt-dashboard-theme">
        {children}
      </ThemeProvider>
    </BrowserRouter>
  )
  
  return render(ui, { wrapper: Wrapper })
}

// Helper to wait for loading states to finish
export const waitForLoadingToFinish = () => new Promise(resolve => setTimeout(resolve, 0))

// Helper to create mock API responses
export function createMockApiResponse<T>(data: T, success = true) {
  return {
    success,
    data: success ? data : undefined,
    error: success ? undefined : 'Mock error',
  }
}

// Helper to format dates consistently in tests
export const formatTestDate = (date: Date) => date.toISOString().split('T')[0]

// Helper to generate unique test IDs
let testIdCounter = 0
export const generateTestId = (prefix = 'test') => `${prefix}-${++testIdCounter}`

// Mock fetch responses
export const mockFetchResponse = (data: any, ok = true, status = 200) => {
  return Promise.resolve({
    ok,
    status,
    json: () => Promise.resolve(data),
  } as Response)
}

// Assert that an element has correct accessibility attributes
export const assertAccessibility = (element: HTMLElement) => {
  // Check for ARIA labels where appropriate
  if (element.role === 'button' || element.tagName === 'BUTTON') {
    expect(element).toHaveAttribute('type')
  }
  
  if (element.role === 'table' || element.tagName === 'TABLE') {
    const headers = element.querySelectorAll('th')
    headers.forEach(header => {
      expect(header).toBeInTheDocument()
    })
  }
}

// Helper to test theme switching
export const getThemeElements = () => {
  const html = document.documentElement
  return {
    isDark: html.classList.contains('dark'),
    isLight: html.classList.contains('light') || !html.classList.contains('dark'),
  }
}