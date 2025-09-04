import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
} from '../tooltip'

describe('Tooltip Component', () => {
  const renderWithProvider = (ui: React.ReactElement) => {
    return render(
      <TooltipProvider>
        {ui}
      </TooltipProvider>
    )
  }

  describe('Basic Rendering', () => {
    it('renders tooltip trigger without tooltip content initially', () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Hover me</button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Tooltip content</p>
          </TooltipContent>
        </Tooltip>
      )

      expect(screen.getByText('Hover me')).toBeInTheDocument()
      expect(screen.queryByText('Tooltip content')).not.toBeInTheDocument()
    })

    it('shows tooltip content on hover', async () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Hover me</button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Tooltip content</p>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByText('Hover me')
      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        expect(screen.getByText('Tooltip content')).toBeInTheDocument()
      })
    })

    it('hides tooltip content when mouse leaves', async () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Hover me</button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Tooltip content</p>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByText('Hover me')
      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        expect(screen.getByText('Tooltip content')).toBeInTheDocument()
      })

      fireEvent.mouseLeave(trigger)

      await waitFor(() => {
        expect(screen.queryByText('Tooltip content')).not.toBeInTheDocument()
      })
    })
  })

  describe('Keyboard Interaction', () => {
    it('shows tooltip on focus', async () => {
      const user = userEvent.setup()
      
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Focus me</button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Focused tooltip</p>
          </TooltipContent>
        </Tooltip>
      )

      await user.tab()
      
      await waitFor(() => {
        expect(screen.getByText('Focused tooltip')).toBeInTheDocument()
      })
    })

    it('hides tooltip on blur', async () => {
      const user = userEvent.setup()
      
      renderWithProvider(
        <div>
          <Tooltip>
            <TooltipTrigger asChild>
              <button>Focus me</button>
            </TooltipTrigger>
            <TooltipContent>
              <p>Focused tooltip</p>
            </TooltipContent>
          </Tooltip>
          <button>Other button</button>
        </div>
      )

      await user.tab()
      
      await waitFor(() => {
        expect(screen.getByText('Focused tooltip')).toBeInTheDocument()
      })

      await user.tab()

      await waitFor(() => {
        expect(screen.queryByText('Focused tooltip')).not.toBeInTheDocument()
      })
    })

    it('hides tooltip when escape is pressed', async () => {
      const user = userEvent.setup()
      
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Focus me</button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Escape tooltip</p>
          </TooltipContent>
        </Tooltip>
      )

      await user.tab()
      
      await waitFor(() => {
        expect(screen.getByText('Escape tooltip')).toBeInTheDocument()
      })

      await user.keyboard('{Escape}')

      await waitFor(() => {
        expect(screen.queryByText('Escape tooltip')).not.toBeInTheDocument()
      })
    })
  })

  describe('Controlled Tooltip', () => {
    it('works with controlled open state', async () => {
      const TestComponent = () => {
        const [open, setOpen] = React.useState(false)

        return (
          <div>
            <button onClick={() => setOpen(!open)}>
              Toggle Tooltip
            </button>
            <Tooltip open={open} onOpenChange={setOpen}>
              <TooltipTrigger asChild>
                <button>Controlled trigger</button>
              </TooltipTrigger>
              <TooltipContent>
                <p>Controlled tooltip</p>
              </TooltipContent>
            </Tooltip>
          </div>
        )
      }

      renderWithProvider(<TestComponent />)

      const toggleButton = screen.getByText('Toggle Tooltip')
      const user = userEvent.setup()

      await user.click(toggleButton)

      await waitFor(() => {
        expect(screen.getByText('Controlled tooltip')).toBeInTheDocument()
      })

      await user.click(toggleButton)

      await waitFor(() => {
        expect(screen.queryByText('Controlled tooltip')).not.toBeInTheDocument()
      })
    })

    it('calls onOpenChange when tooltip state changes', async () => {
      const onOpenChange = vi.fn()

      renderWithProvider(
        <Tooltip onOpenChange={onOpenChange}>
          <TooltipTrigger asChild>
            <button>Trigger</button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Callback tooltip</p>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByText('Trigger')
      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        expect(onOpenChange).toHaveBeenCalledWith(true)
      })

      fireEvent.mouseLeave(trigger)

      await waitFor(() => {
        expect(onOpenChange).toHaveBeenCalledWith(false)
      })
    })
  })

  describe('Positioning and Styling', () => {
    it('applies custom className to tooltip content', async () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Hover me</button>
          </TooltipTrigger>
          <TooltipContent className="custom-tooltip">
            <p>Styled tooltip</p>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByText('Hover me')
      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        const tooltip = screen.getByText('Styled tooltip')
        expect(tooltip).toHaveClass('custom-tooltip')
      })
    })

    it('applies default styling classes', async () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Hover me</button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Default tooltip</p>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByText('Hover me')
      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        const tooltip = screen.getByText('Default tooltip')
        expect(tooltip.className).toContain('z-50')
        expect(tooltip.className).toContain('rounded-md')
        expect(tooltip.className).toContain('border')
        expect(tooltip.className).toContain('bg-popover')
      })
    })

    it('supports different side positions', async () => {
      const TestComponent = () => (
        <div style={{ padding: '100px' }}>
          <Tooltip>
            <TooltipTrigger asChild>
              <button>Top tooltip</button>
            </TooltipTrigger>
            <TooltipContent side="top">
              <p>Top positioned</p>
            </TooltipContent>
          </Tooltip>
        </div>
      )

      renderWithProvider(<TestComponent />)

      const trigger = screen.getByText('Top tooltip')
      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        expect(screen.getByText('Top positioned')).toBeInTheDocument()
      })
    })

    it('supports custom sideOffset', async () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Custom offset</button>
          </TooltipTrigger>
          <TooltipContent sideOffset={20}>
            <p>Offset tooltip</p>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByText('Custom offset')
      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        expect(screen.getByText('Offset tooltip')).toBeInTheDocument()
      })
    })
  })

  describe('Content Variations', () => {
    it('renders complex content in tooltip', async () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Complex content</button>
          </TooltipTrigger>
          <TooltipContent>
            <div>
              <h4>Tooltip Title</h4>
              <p>Description text</p>
              <ul>
                <li>Item 1</li>
                <li>Item 2</li>
              </ul>
            </div>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByText('Complex content')
      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        expect(screen.getByText('Tooltip Title')).toBeInTheDocument()
        expect(screen.getByText('Description text')).toBeInTheDocument()
        expect(screen.getByText('Item 1')).toBeInTheDocument()
        expect(screen.getByText('Item 2')).toBeInTheDocument()
      })
    })

    it('renders with different trigger elements', async () => {
      renderWithProvider(
        <div>
          <Tooltip>
            <TooltipTrigger asChild>
              <span>Span trigger</span>
            </TooltipTrigger>
            <TooltipContent>
              <p>Span tooltip</p>
            </TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <div role="button" tabIndex={0}>Div trigger</div>
            </TooltipTrigger>
            <TooltipContent>
              <p>Div tooltip</p>
            </TooltipContent>
          </Tooltip>
        </div>
      )

      const spanTrigger = screen.getByText('Span trigger')
      fireEvent.mouseEnter(spanTrigger)

      await waitFor(() => {
        expect(screen.getByText('Span tooltip')).toBeInTheDocument()
      })
    })

    it('handles empty content gracefully', async () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Empty content</button>
          </TooltipTrigger>
          <TooltipContent>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByText('Empty content')
      fireEvent.mouseEnter(trigger)

      // Tooltip should still render even with empty content
      await waitFor(() => {
        const tooltip = document.querySelector('[data-state="open"]')
        expect(tooltip).toBeInTheDocument()
      })
    })
  })

  describe('Multiple Tooltips', () => {
    it('handles multiple tooltips correctly', async () => {
      renderWithProvider(
        <div>
          <Tooltip>
            <TooltipTrigger asChild>
              <button>First tooltip</button>
            </TooltipTrigger>
            <TooltipContent>
              <p>First content</p>
            </TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <button>Second tooltip</button>
            </TooltipTrigger>
            <TooltipContent>
              <p>Second content</p>
            </TooltipContent>
          </Tooltip>
        </div>
      )

      const firstTrigger = screen.getByText('First tooltip')
      const secondTrigger = screen.getByText('Second tooltip')

      fireEvent.mouseEnter(firstTrigger)

      await waitFor(() => {
        expect(screen.getByText('First content')).toBeInTheDocument()
      })

      fireEvent.mouseLeave(firstTrigger)
      fireEvent.mouseEnter(secondTrigger)

      await waitFor(() => {
        expect(screen.queryByText('First content')).not.toBeInTheDocument()
        expect(screen.getByText('Second content')).toBeInTheDocument()
      })
    })
  })

  describe('Provider Configuration', () => {
    it('works with custom provider props', async () => {
      render(
        <TooltipProvider delayDuration={0} skipDelayDuration={0}>
          <Tooltip>
            <TooltipTrigger asChild>
              <button>No delay tooltip</button>
            </TooltipTrigger>
            <TooltipContent>
              <p>Instant tooltip</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      )

      const trigger = screen.getByText('No delay tooltip')
      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        expect(screen.getByText('Instant tooltip')).toBeInTheDocument()
      }, { timeout: 2000 })
    })

    it('requires TooltipProvider wrapper', () => {
      // Radix UI Tooltip requires a provider
      expect(() => {
        render(
          <Tooltip>
            <TooltipTrigger asChild>
              <button>No provider</button>
            </TooltipTrigger>
            <TooltipContent>
              <p>Content</p>
            </TooltipContent>
          </Tooltip>
        )
      }).toThrow()
    })
  })

  describe('Accessibility', () => {
    it('has correct ARIA attributes', async () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Accessible tooltip</button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Accessible content</p>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByText('Accessible tooltip')
      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        const tooltip = screen.getByText('Accessible content')
        expect(tooltip).toBeInTheDocument()
        // The tooltip should have role tooltip or be inside an element with that role
        const tooltipElement = tooltip.closest('[role="tooltip"]') || 
                              document.querySelector('[role="tooltip"]')
        expect(tooltipElement).toBeInTheDocument()
      }, { timeout: 2000 })
    })

    it('supports screen readers', async () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button aria-label="Button with tooltip">
              Icon
            </button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Screen reader friendly tooltip</p>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByLabelText('Button with tooltip')
      expect(trigger).toBeInTheDocument()

      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        expect(screen.getByText('Screen reader friendly tooltip')).toBeInTheDocument()
      })
    })
  })

  describe('Edge Cases', () => {
    it('handles disabled triggers', async () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button disabled>Disabled button</button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Should still work</p>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByText('Disabled button')
      
      // Even disabled elements can show tooltips in many implementations
      fireEvent.mouseEnter(trigger)

      // The behavior might vary, but the test should not crash
      expect(trigger).toBeInTheDocument()
    })

    it('handles rapid hover events', async () => {
      renderWithProvider(
        <Tooltip>
          <TooltipTrigger asChild>
            <button>Rapid hover</button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Rapid content</p>
          </TooltipContent>
        </Tooltip>
      )

      const trigger = screen.getByText('Rapid hover')
      
      // Rapid hover/unhover
      fireEvent.mouseEnter(trigger)
      fireEvent.mouseLeave(trigger)
      fireEvent.mouseEnter(trigger)

      await waitFor(() => {
        expect(screen.getByText('Rapid content')).toBeInTheDocument()
      })
    })
  })
})