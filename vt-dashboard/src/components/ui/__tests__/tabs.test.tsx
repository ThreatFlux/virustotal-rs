import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from '../tabs'

describe('Tabs Component', () => {
  describe('Basic Rendering', () => {
    it('renders tabs with triggers and content', () => {
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
            <TabsTrigger value="tab3">Tab 3</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">
            <div>Content 1</div>
          </TabsContent>
          <TabsContent value="tab2">
            <div>Content 2</div>
          </TabsContent>
          <TabsContent value="tab3">
            <div>Content 3</div>
          </TabsContent>
        </Tabs>
      )

      expect(screen.getByText('Tab 1')).toBeInTheDocument()
      expect(screen.getByText('Tab 2')).toBeInTheDocument()
      expect(screen.getByText('Tab 3')).toBeInTheDocument()
      expect(screen.getByText('Content 1')).toBeInTheDocument()
      expect(screen.queryByText('Content 2')).not.toBeInTheDocument()
      expect(screen.queryByText('Content 3')).not.toBeInTheDocument()
    })

    it('shows first tab as active by default', () => {
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
        </Tabs>
      )

      const activeTab = screen.getByText('Tab 1')
      expect(activeTab).toHaveAttribute('data-state', 'active')
      expect(screen.getByText('Content 1')).toBeInTheDocument()
    })

    it('can start with a different default tab', () => {
      render(
        <Tabs defaultValue="tab2">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
        </Tabs>
      )

      expect(screen.getByText('Tab 2')).toHaveAttribute('data-state', 'active')
      expect(screen.getByText('Content 2')).toBeInTheDocument()
      expect(screen.queryByText('Content 1')).not.toBeInTheDocument()
    })
  })

  describe('Tab Switching', () => {
    it('switches content when tab is clicked', async () => {
      const user = userEvent.setup()
      
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
        </Tabs>
      )

      expect(screen.getByText('Content 1')).toBeInTheDocument()
      expect(screen.queryByText('Content 2')).not.toBeInTheDocument()

      await user.click(screen.getByText('Tab 2'))

      expect(screen.getByText('Content 2')).toBeInTheDocument()
      expect(screen.queryByText('Content 1')).not.toBeInTheDocument()
      expect(screen.getByText('Tab 2')).toHaveAttribute('data-state', 'active')
    })

    it('updates active state when tabs are switched', async () => {
      const user = userEvent.setup()
      
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
            <TabsTrigger value="tab3">Tab 3</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
          <TabsContent value="tab3">Content 3</TabsContent>
        </Tabs>
      )

      const tab1 = screen.getByText('Tab 1')
      const tab2 = screen.getByText('Tab 2')
      const tab3 = screen.getByText('Tab 3')

      expect(tab1).toHaveAttribute('data-state', 'active')
      expect(tab2).toHaveAttribute('data-state', 'inactive')
      expect(tab3).toHaveAttribute('data-state', 'inactive')

      await user.click(tab2)

      expect(tab1).toHaveAttribute('data-state', 'inactive')
      expect(tab2).toHaveAttribute('data-state', 'active')
      expect(tab3).toHaveAttribute('data-state', 'inactive')

      await user.click(tab3)

      expect(tab1).toHaveAttribute('data-state', 'inactive')
      expect(tab2).toHaveAttribute('data-state', 'inactive')
      expect(tab3).toHaveAttribute('data-state', 'active')
    })

    it('switches tabs rapidly without issues', async () => {
      const user = userEvent.setup()
      
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
            <TabsTrigger value="tab3">Tab 3</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
          <TabsContent value="tab3">Content 3</TabsContent>
        </Tabs>
      )

      // Rapid tab switching
      await user.click(screen.getByText('Tab 2'))
      await user.click(screen.getByText('Tab 3'))
      await user.click(screen.getByText('Tab 1'))
      await user.click(screen.getByText('Tab 2'))

      expect(screen.getByText('Content 2')).toBeInTheDocument()
      expect(screen.getByText('Tab 2')).toHaveAttribute('data-state', 'active')
    })
  })

  describe('Keyboard Navigation', () => {
    it('supports arrow key navigation', async () => {
      const user = userEvent.setup()
      
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
            <TabsTrigger value="tab3">Tab 3</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
          <TabsContent value="tab3">Content 3</TabsContent>
        </Tabs>
      )

      const tab1 = screen.getByText('Tab 1')
      await user.tab()
      expect(tab1).toHaveFocus()

      await user.keyboard('{ArrowRight}')
      expect(screen.getByText('Tab 2')).toHaveFocus()

      await user.keyboard('{ArrowRight}')
      expect(screen.getByText('Tab 3')).toHaveFocus()

      await user.keyboard('{ArrowLeft}')
      expect(screen.getByText('Tab 2')).toHaveFocus()
    })

    it('wraps around when using arrow keys', async () => {
      const user = userEvent.setup()
      
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
            <TabsTrigger value="tab3">Tab 3</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
          <TabsContent value="tab3">Content 3</TabsContent>
        </Tabs>
      )

      const tab1 = screen.getByText('Tab 1')
      const tab3 = screen.getByText('Tab 3')
      
      await user.tab()
      expect(tab1).toHaveFocus()

      await user.keyboard('{ArrowLeft}')
      expect(tab3).toHaveFocus()

      await user.keyboard('{ArrowRight}')
      expect(tab1).toHaveFocus()
    })

    it('activates tab on Enter or Space', async () => {
      const user = userEvent.setup()
      
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
        </Tabs>
      )

      await user.tab()
      await user.keyboard('{ArrowRight}')
      expect(screen.getByText('Tab 2')).toHaveFocus()

      await user.keyboard('{Enter}')
      expect(screen.getByText('Content 2')).toBeInTheDocument()
      expect(screen.getByText('Tab 2')).toHaveAttribute('data-state', 'active')
    })
  })

  describe('Controlled Tabs', () => {
    it('works with controlled value', async () => {
      const user = userEvent.setup()
      const TestComponent = () => {
        const [value, setValue] = React.useState('tab1')

        return (
          <div>
            <button onClick={() => setValue('tab2')}>Set Tab 2</button>
            <Tabs value={value} onValueChange={setValue}>
              <TabsList>
                <TabsTrigger value="tab1">Tab 1</TabsTrigger>
                <TabsTrigger value="tab2">Tab 2</TabsTrigger>
              </TabsList>
              <TabsContent value="tab1">Content 1</TabsContent>
              <TabsContent value="tab2">Content 2</TabsContent>
            </Tabs>
          </div>
        )
      }

      render(<TestComponent />)

      expect(screen.getByText('Content 1')).toBeInTheDocument()

      await user.click(screen.getByText('Set Tab 2'))

      expect(screen.getByText('Content 2')).toBeInTheDocument()
      expect(screen.getByText('Tab 2')).toHaveAttribute('data-state', 'active')
    })

    it('calls onValueChange when tabs are clicked', async () => {
      const user = userEvent.setup()
      const onValueChange = vi.fn()
      
      render(
        <Tabs defaultValue="tab1" onValueChange={onValueChange}>
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
        </Tabs>
      )

      await user.click(screen.getByText('Tab 2'))

      expect(onValueChange).toHaveBeenCalledWith('tab2')
    })
  })

  describe('Disabled Tabs', () => {
    it('handles disabled tab triggers', async () => {
      const user = userEvent.setup()
      
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2" disabled>Tab 2 (Disabled)</TabsTrigger>
            <TabsTrigger value="tab3">Tab 3</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
          <TabsContent value="tab3">Content 3</TabsContent>
        </Tabs>
      )

      const disabledTab = screen.getByText('Tab 2 (Disabled)')
      expect(disabledTab).toBeDisabled()

      await user.click(disabledTab)
      // Content should not change
      expect(screen.getByText('Content 1')).toBeInTheDocument()
      expect(screen.queryByText('Content 2')).not.toBeInTheDocument()
    })

    it('skips disabled tabs during keyboard navigation', async () => {
      const user = userEvent.setup()
      
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2" disabled>Tab 2 (Disabled)</TabsTrigger>
            <TabsTrigger value="tab3">Tab 3</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
          <TabsContent value="tab3">Content 3</TabsContent>
        </Tabs>
      )

      await user.tab()
      expect(screen.getByText('Tab 1')).toHaveFocus()

      await user.keyboard('{ArrowRight}')
      expect(screen.getByText('Tab 3')).toHaveFocus() // Should skip disabled tab
    })
  })

  describe('Custom Styling', () => {
    it('applies custom className to all components', () => {
      render(
        <Tabs defaultValue="tab1" className="custom-tabs">
          <TabsList className="custom-tabs-list">
            <TabsTrigger value="tab1" className="custom-tab-trigger">
              Tab 1
            </TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1" className="custom-tab-content">
            Content 1
          </TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
        </Tabs>
      )

      expect(screen.getByRole('tablist')).toHaveClass('custom-tabs-list')
      expect(screen.getByText('Tab 1')).toHaveClass('custom-tab-trigger')
      expect(screen.getByText('Content 1')).toHaveClass('custom-tab-content')
    })

    it('applies default styling classes', () => {
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
        </Tabs>
      )

      const tabsList = screen.getByRole('tablist')
      const tabTrigger = screen.getByText('Tab 1')
      const tabContent = screen.getByText('Content 1')

      expect(tabsList.className).toContain('inline-flex')
      expect(tabsList.className).toContain('h-10')
      expect(tabsList.className).toContain('bg-muted')

      expect(tabTrigger.className).toContain('inline-flex')
      expect(tabTrigger.className).toContain('items-center')
      expect(tabTrigger.className).toContain('rounded-sm')

      expect(tabContent.className).toContain('mt-2')
      expect(tabContent.className).toContain('ring-offset-background')
    })
  })

  describe('Content Variations', () => {
    it('renders complex content in tab panels', () => {
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Complex Tab</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">
            <div>
              <h2>Tab Title</h2>
              <p>Description text</p>
              <ul>
                <li>Item 1</li>
                <li>Item 2</li>
              </ul>
              <button>Action Button</button>
            </div>
          </TabsContent>
        </Tabs>
      )

      expect(screen.getByText('Tab Title')).toBeInTheDocument()
      expect(screen.getByText('Description text')).toBeInTheDocument()
      expect(screen.getByText('Item 1')).toBeInTheDocument()
      expect(screen.getByText('Action Button')).toBeInTheDocument()
    })

    it('handles empty content gracefully', () => {
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Empty Tab</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1"></TabsContent>
        </Tabs>
      )

      expect(screen.getByText('Empty Tab')).toBeInTheDocument()
      // Content panel should exist even if empty
      expect(screen.getByRole('tabpanel')).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('has correct ARIA attributes', () => {
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
        </Tabs>
      )

      const tabsList = screen.getByRole('tablist')
      const tab1 = screen.getByRole('tab', { name: 'Tab 1' })
      const tab2 = screen.getByRole('tab', { name: 'Tab 2' })
      const panel1 = screen.getByRole('tabpanel')

      expect(tabsList).toBeInTheDocument()
      expect(tab1).toHaveAttribute('aria-selected', 'true')
      expect(tab2).toHaveAttribute('aria-selected', 'false')
      expect(panel1).toHaveAttribute('aria-labelledby', tab1.id)
    })

    it('updates ARIA attributes when tabs change', async () => {
      const user = userEvent.setup()
      
      render(
        <Tabs defaultValue="tab1">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
        </Tabs>
      )

      const tab1 = screen.getByRole('tab', { name: 'Tab 1' })
      const tab2 = screen.getByRole('tab', { name: 'Tab 2' })

      expect(tab1).toHaveAttribute('aria-selected', 'true')
      expect(tab2).toHaveAttribute('aria-selected', 'false')

      await user.click(tab2)

      expect(tab1).toHaveAttribute('aria-selected', 'false')
      expect(tab2).toHaveAttribute('aria-selected', 'true')
    })

    it('manages focus correctly', async () => {
      const user = userEvent.setup()
      
      render(
        <div>
          <button>Before</button>
          <Tabs defaultValue="tab1">
            <TabsList>
              <TabsTrigger value="tab1">Tab 1</TabsTrigger>
              <TabsTrigger value="tab2">Tab 2</TabsTrigger>
            </TabsList>
            <TabsContent value="tab1">
              <button>Content Button 1</button>
            </TabsContent>
            <TabsContent value="tab2">
              <button>Content Button 2</button>
            </TabsContent>
          </Tabs>
          <button>After</button>
        </div>
      )

      await user.tab() // Before button
      await user.tab() // First tab
      expect(screen.getByText('Tab 1')).toHaveFocus()

      await user.tab() // Content button
      expect(screen.getByText('Content Button 1')).toHaveFocus()

      await user.tab() // After button
      expect(screen.getByText('After')).toHaveFocus()
    })
  })

  describe('Edge Cases', () => {
    it('handles single tab', () => {
      render(
        <Tabs defaultValue="single">
          <TabsList>
            <TabsTrigger value="single">Single Tab</TabsTrigger>
          </TabsList>
          <TabsContent value="single">Single Content</TabsContent>
        </Tabs>
      )

      expect(screen.getByText('Single Tab')).toHaveAttribute('data-state', 'active')
      expect(screen.getByText('Single Content')).toBeInTheDocument()
    })

    it('handles tabs without default value', () => {
      render(
        <Tabs>
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
        </Tabs>
      )

      // Should render without errors
      expect(screen.getByText('Tab 1')).toBeInTheDocument()
      expect(screen.getByText('Tab 2')).toBeInTheDocument()
    })

    it('handles non-existent default value', () => {
      render(
        <Tabs defaultValue="nonexistent">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
        </Tabs>
      )

      // Should handle gracefully - likely no tab will be active
      expect(screen.getByText('Tab 1')).toBeInTheDocument()
      expect(screen.getByText('Tab 2')).toBeInTheDocument()
    })

    it('handles tab value changes during render', () => {
      const TestComponent = () => {
        const [value, setValue] = React.useState('tab1')
        
        React.useEffect(() => {
          const timeout = setTimeout(() => setValue('tab2'), 10)
          return () => clearTimeout(timeout)
        }, [])

        return (
          <Tabs value={value} onValueChange={setValue}>
            <TabsList>
              <TabsTrigger value="tab1">Tab 1</TabsTrigger>
              <TabsTrigger value="tab2">Tab 2</TabsTrigger>
            </TabsList>
            <TabsContent value="tab1">Content 1</TabsContent>
            <TabsContent value="tab2">Content 2</TabsContent>
          </Tabs>
        )
      }

      render(<TestComponent />)

      expect(screen.getByText('Tab 1')).toBeInTheDocument()
      expect(screen.getByText('Tab 2')).toBeInTheDocument()
    })
  })

  describe('Direction and Orientation', () => {
    it('supports different orientation', () => {
      render(
        <Tabs defaultValue="tab1" orientation="vertical">
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content 1</TabsContent>
          <TabsContent value="tab2">Content 2</TabsContent>
        </Tabs>
      )

      const tabsList = screen.getByRole('tablist')
      expect(tabsList).toHaveAttribute('aria-orientation', 'vertical')
    })
  })
})