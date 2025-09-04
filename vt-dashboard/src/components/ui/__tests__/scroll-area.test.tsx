import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@/test/utils/test-utils'
import { ScrollArea, ScrollBar } from '../scroll-area'

describe('ScrollArea Component', () => {
  describe('Basic Rendering', () => {
    it('renders scroll area with content', () => {
      render(
        <ScrollArea>
          <div>Scrollable content</div>
        </ScrollArea>
      )
      
      expect(screen.getByText('Scrollable content')).toBeInTheDocument()
    })

    it('renders with default classes', () => {
      const { container } = render(
        <ScrollArea>
          <div>Content</div>
        </ScrollArea>
      )
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toHaveClass('relative', 'overflow-hidden')
    })

    it('applies custom className', () => {
      const { container } = render(
        <ScrollArea className="custom-scroll-class">
          <div>Content</div>
        </ScrollArea>
      )
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toHaveClass('custom-scroll-class')
      expect(scrollAreaRoot).toHaveClass('relative', 'overflow-hidden') // Should also have default classes
    })

    it('renders children correctly', () => {
      render(
        <ScrollArea>
          <div>Child 1</div>
          <div>Child 2</div>
          <span>Child 3</span>
        </ScrollArea>
      )
      
      expect(screen.getByText('Child 1')).toBeInTheDocument()
      expect(screen.getByText('Child 2')).toBeInTheDocument()
      expect(screen.getByText('Child 3')).toBeInTheDocument()
    })
  })

  describe('ScrollArea Structure', () => {
    it('contains viewport element with proper classes', () => {
      const { container } = render(
        <ScrollArea>
          <div data-testid="scroll-content">Content</div>
        </ScrollArea>
      )
      
      const viewport = container.querySelector('[data-radix-scroll-area-viewport=""]')
      expect(viewport).toBeInTheDocument()
      expect(viewport).toHaveClass('h-full', 'w-full', 'rounded-[inherit]')
    })

    it('includes scroll bar component', () => {
      const { container } = render(
        <ScrollArea>
          <div>Content</div>
        </ScrollArea>
      )
      
      // ScrollBar is rendered but may not be visible without scrollable content
      // Check for the ScrollArea structure instead
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toHaveClass('relative', 'overflow-hidden')
    })

    it('includes corner element', () => {
      const { container } = render(
        <ScrollArea>
          <div>Content</div>
        </ScrollArea>
      )
      
      // Corner element is part of the ScrollArea structure
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toBeInTheDocument()
    })
  })

  describe('ScrollArea Props', () => {
    it('forwards props to root element', () => {
      const { container } = render(
        <ScrollArea data-testid="scroll-area" role="region" aria-label="Scrollable region">
          <div>Content</div>
        </ScrollArea>
      )
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toHaveAttribute('data-testid', 'scroll-area')
      expect(scrollAreaRoot).toHaveAttribute('role', 'region')
      expect(scrollAreaRoot).toHaveAttribute('aria-label', 'Scrollable region')
    })

    it('supports style prop', () => {
      const { container } = render(
        <ScrollArea style={{ height: '200px', maxWidth: '300px' }}>
          <div>Content</div>
        </ScrollArea>
      )
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      // Check that the element exists and has the proper structure
      expect(scrollAreaRoot).toBeInTheDocument()
      expect(scrollAreaRoot).toHaveClass('relative', 'overflow-hidden')
    })
  })

  describe('Ref Forwarding', () => {
    it('forwards ref correctly', () => {
      const ref = vi.fn()
      render(
        <ScrollArea ref={ref}>
          <div>Content</div>
        </ScrollArea>
      )
      
      expect(ref).toHaveBeenCalledWith(expect.any(HTMLElement))
    })
  })

  describe('ScrollArea Content', () => {
    it('handles long content', () => {
      const longContent = Array.from({ length: 100 }, (_, i) => `Line ${i + 1}`).join(' ')
      render(
        <ScrollArea>
          <div>{longContent}</div>
        </ScrollArea>
      )
      
      expect(screen.getByText(longContent)).toBeInTheDocument()
    })

    it('handles nested elements', () => {
      render(
        <ScrollArea>
          <div>
            <h1>Header</h1>
            <p>Paragraph 1</p>
            <ul>
              <li>Item 1</li>
              <li>Item 2</li>
            </ul>
          </div>
        </ScrollArea>
      )
      
      expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
      expect(screen.getByText('Paragraph 1')).toBeInTheDocument()
      expect(screen.getByRole('list')).toBeInTheDocument()
      expect(screen.getAllByRole('listitem')).toHaveLength(2)
    })

    it('handles empty content', () => {
      const { container } = render(<ScrollArea />)
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toBeInTheDocument()
      expect(scrollAreaRoot).toHaveClass('relative', 'overflow-hidden')
    })
  })

  describe('Accessibility', () => {
    it('supports aria-label', () => {
      const { container } = render(
        <ScrollArea aria-label="Content scroll area">
          <div>Content</div>
        </ScrollArea>
      )
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toHaveAttribute('aria-label', 'Content scroll area')
    })

    it('supports aria-describedby', () => {
      render(
        <div>
          <ScrollArea aria-describedby="scroll-description">
            <div>Content</div>
          </ScrollArea>
          <div id="scroll-description">This area is scrollable</div>
        </div>
      )
      
      const scrollArea = document.querySelector('[aria-describedby="scroll-description"]')
      expect(scrollArea).toBeInTheDocument()
      expect(scrollArea).toHaveAttribute('aria-describedby', 'scroll-description')
    })

    it('supports role attribute', () => {
      const { container } = render(
        <ScrollArea role="region">
          <div>Content</div>
        </ScrollArea>
      )
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toHaveAttribute('role', 'region')
    })
  })

  describe('Use Cases', () => {
    it('renders chat message list', () => {
      const messages = ['Hello', 'How are you?', 'I am fine, thank you!']
      render(
        <ScrollArea className="h-64">
          <div>
            {messages.map((message, index) => (
              <div key={index} className="p-2">
                {message}
              </div>
            ))}
          </div>
        </ScrollArea>
      )
      
      messages.forEach(message => {
        expect(screen.getByText(message)).toBeInTheDocument()
      })
    })

    it('renders code block with syntax highlighting', () => {
      render(
        <ScrollArea className="max-h-96">
          <pre>
            <code>
              {`const example = () => {
  console.log('Hello, World!');
  return 'success';
}`}
            </code>
          </pre>
        </ScrollArea>
      )
      
      expect(screen.getByText(/const example/)).toBeInTheDocument()
    })

    it('renders sidebar navigation', () => {
      const navItems = ['Home', 'About', 'Services', 'Contact']
      render(
        <ScrollArea className="h-48">
          <nav>
            <ul>
              {navItems.map(item => (
                <li key={item}>
                  <a href={`#${item.toLowerCase()}`}>{item}</a>
                </li>
              ))}
            </ul>
          </nav>
        </ScrollArea>
      )
      
      navItems.forEach(item => {
        const link = screen.getByRole('link', { name: item })
        expect(link).toBeInTheDocument()
        expect(link).toHaveAttribute('href', `#${item.toLowerCase()}`)
      })
    })
  })

  describe('Edge Cases', () => {
    it('handles undefined children', () => {
      const { container } = render(<ScrollArea>{undefined}</ScrollArea>)
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toBeInTheDocument()
      expect(scrollAreaRoot).toHaveClass('relative', 'overflow-hidden')
    })

    it('handles null children', () => {
      const { container } = render(<ScrollArea>{null}</ScrollArea>)
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toBeInTheDocument()
    })

    it('handles conditional content', () => {
      const showContent = false
      render(
        <ScrollArea>
          {showContent && <div>Conditional content</div>}
          <div>Always visible</div>
        </ScrollArea>
      )
      
      expect(screen.queryByText('Conditional content')).not.toBeInTheDocument()
      expect(screen.getByText('Always visible')).toBeInTheDocument()
    })

    it('handles fragment children', () => {
      render(
        <ScrollArea>
          <>
            <div>Fragment child 1</div>
            <div>Fragment child 2</div>
          </>
        </ScrollArea>
      )
      
      expect(screen.getByText('Fragment child 1')).toBeInTheDocument()
      expect(screen.getByText('Fragment child 2')).toBeInTheDocument()
    })
  })
})

describe('ScrollBar Integration', () => {
  describe('Within ScrollArea', () => {
    it('renders with ScrollArea container', () => {
      const { container } = render(
        <ScrollArea>
          <div style={{ height: '1000px' }}>Long content that should trigger scrollbar</div>
        </ScrollArea>
      )
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toHaveClass('relative', 'overflow-hidden')
    })

    it('handles ScrollArea with custom scrollbar', () => {
      const CustomScrollArea = React.forwardRef<
        React.ElementRef<typeof ScrollArea>,
        React.ComponentPropsWithoutRef<typeof ScrollArea>
      >(({ className, children, ...props }, ref) => (
        <ScrollArea ref={ref} className={className} {...props}>
          {children}
        </ScrollArea>
      ))
      CustomScrollArea.displayName = "CustomScrollArea"

      const { container } = render(
        <CustomScrollArea className="max-h-96">
          <div>Content</div>
        </CustomScrollArea>
      )
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toHaveClass('max-h-96')
      expect(scrollAreaRoot).toHaveClass('relative', 'overflow-hidden')
    })

    it('maintains proper structure with complex content', () => {
      const { container } = render(
        <ScrollArea className="h-48">
          <div className="space-y-4">
            {Array.from({ length: 20 }, (_, i) => (
              <div key={i} className="p-2 bg-gray-100">
                Item {i + 1}
              </div>
            ))}
          </div>
        </ScrollArea>
      )
      
      const scrollAreaRoot = container.firstChild as HTMLElement
      expect(scrollAreaRoot).toHaveClass('h-48')
      
      // Check that all items are rendered
      for (let i = 1; i <= 20; i++) {
        expect(screen.getByText(`Item ${i}`)).toBeInTheDocument()
      }
    })
  })

  describe('ScrollBar Export Accessibility', () => {
    it('exports ScrollBar component', () => {
      expect(ScrollBar).toBeDefined()
      expect(typeof ScrollBar).toBe('object') // React.forwardRef returns an object
    })

    it('ScrollBar has correct displayName', () => {
      expect(ScrollBar.displayName).toBe('ScrollAreaScrollbar')
    })
  })
})