import '@testing-library/jest-dom'
import { beforeAll, afterEach, afterAll, vi } from 'vitest'
import { server } from '@/test/utils/mock-server'

// Provide vi globally for compatibility with jest-style mocking
global.vi = vi

// Mock PrismJS globally before any component imports
const mockPrism = {
  languages: {
    yara: {},
    yaml: {},
    sigma: {},
    extend: vi.fn().mockImplementation((base, extension) => ({
      ...base,
      ...extension
    }))
  },
  highlightAll: vi.fn(),
  highlight: vi.fn().mockReturnValue('highlighted code'),
}

// Set up Prism mock globally
global.Prism = mockPrism
// Also set it on window for components that might access it there
Object.defineProperty(window, 'Prism', {
  value: mockPrism,
  writable: true,
  configurable: true,
})

// Mock PrismJS module and its imports
vi.mock('prismjs', () => ({
  default: mockPrism,
}))

vi.mock('prismjs/themes/prism-tomorrow.css', () => ({}))
vi.mock('prismjs/components/prism-yaml', () => ({}))
vi.mock('prismjs/components/prism-sigma', () => ({}))

// Setup MSW
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' })
})

afterEach(() => {
  server.resetHandlers()
})

afterAll(() => {
  server.close()
})

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(), // deprecated
    removeListener: vi.fn(), // deprecated
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// Mock ResizeObserver
global.ResizeObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}))

// Mock IntersectionObserver
global.IntersectionObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}))

// Mock scrollTo
Object.defineProperty(window, 'scrollTo', {
  value: vi.fn(),
  writable: true,
})

// Mock HTMLElement methods that might not be available in jsdom
Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
  value: vi.fn(),
  writable: true,
})

// Mock Pointer Events and related APIs for Radix UI components
class MockPointerEvent extends Event {
  public button: number
  public ctrlKey: boolean
  public pointerId: number
  public width: number
  public height: number
  public pressure: number
  public tiltX: number
  public tiltY: number
  public pointerType: string
  public isPrimary: boolean
  
  constructor(type: string, props: any = {}) {
    super(type, props)
    this.button = props.button || 0
    this.ctrlKey = props.ctrlKey || false
    this.pointerId = props.pointerId || 1
    this.width = props.width || 1
    this.height = props.height || 1
    this.pressure = props.pressure || 0
    this.tiltX = props.tiltX || 0
    this.tiltY = props.tiltY || 0
    this.pointerType = props.pointerType || 'mouse'
    this.isPrimary = props.isPrimary || false
  }
}

// Replace window.PointerEvent with our mock
global.PointerEvent = MockPointerEvent as any
window.PointerEvent = MockPointerEvent as any

// Mock hasPointerCapture and releasePointerCapture methods
Object.defineProperty(HTMLElement.prototype, 'hasPointerCapture', {
  value: vi.fn(() => false),
  writable: true,
})

Object.defineProperty(HTMLElement.prototype, 'setPointerCapture', {
  value: vi.fn(),
  writable: true,
})

Object.defineProperty(HTMLElement.prototype, 'releasePointerCapture', {
  value: vi.fn(),
  writable: true,
})

// Mock getBoundingClientRect for better positioning support
Object.defineProperty(HTMLElement.prototype, 'getBoundingClientRect', {
  value: vi.fn(() => ({
    bottom: 0,
    height: 0,
    left: 0,
    right: 0,
    top: 0,
    width: 0,
    x: 0,
    y: 0,
    toJSON: () => {},
  })),
  writable: true,
})

// Mock DOMRect
global.DOMRect = vi.fn().mockImplementation((x = 0, y = 0, width = 0, height = 0) => ({
  x,
  y,
  width,
  height,
  top: y,
  left: x,
  bottom: y + height,
  right: x + width,
  toJSON: () => {},
}))

// Mock requestAnimationFrame and cancelAnimationFrame
global.requestAnimationFrame = vi.fn((callback) => {
  setTimeout(callback, 16)
  return 1
})

global.cancelAnimationFrame = vi.fn()

// Mock setTimeout and setInterval to run immediately for predictable tests
// Only for tests that need immediate execution
global.originalSetTimeout = global.setTimeout
global.originalClearTimeout = global.clearTimeout

// Override specific methods that Radix might use for animations
global.HTMLElement.prototype.animate = vi.fn(() => ({
  addEventListener: vi.fn(),
  removeEventListener: vi.fn(),
  dispatchEvent: vi.fn(),
  finish: vi.fn(),
  cancel: vi.fn(),
  play: vi.fn(),
  pause: vi.fn(),
  updatePlaybackRate: vi.fn(),
  reverse: vi.fn(),
  currentTime: 0,
  playbackRate: 1,
  playState: 'finished',
  ready: Promise.resolve(),
  finished: Promise.resolve(),
}))

// Mock getComputedStyle to return consistent values for pointer events
const originalGetComputedStyle = global.getComputedStyle
global.getComputedStyle = vi.fn((element) => {
  const originalStyles = originalGetComputedStyle(element)
  return {
    ...originalStyles,
    getPropertyValue: (property: string) => {
      if (property === 'pointer-events') {
        return 'auto' // Always return 'auto' to prevent pointer-events: none issues in tests
      }
      return originalStyles.getPropertyValue(property)
    },
    pointerEvents: 'auto',
  }
})

// Mock console methods to avoid noise during tests unless explicitly needed
const originalConsole = console
beforeAll(() => {
  console.warn = vi.fn()
  console.error = vi.fn()
})

afterAll(() => {
  console.warn = originalConsole.warn
  console.error = originalConsole.error
})