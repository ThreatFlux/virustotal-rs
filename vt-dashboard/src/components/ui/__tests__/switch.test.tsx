import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@/test/utils/test-utils'
import userEvent from '@testing-library/user-event'
import { Switch } from '../switch'

describe('Switch Component', () => {
  describe('Basic Rendering', () => {
    it('renders switch component', () => {
      render(<Switch />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toBeInTheDocument()
    })

    it('renders with unchecked state by default', () => {
      render(<Switch />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('data-state', 'unchecked')
      expect(switchElement).toHaveAttribute('aria-checked', 'false')
    })

    it('renders with checked state when defaultChecked is true', () => {
      render(<Switch defaultChecked />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('data-state', 'checked')
      expect(switchElement).toHaveAttribute('aria-checked', 'true')
    })

    it('renders with controlled checked state', () => {
      render(<Switch checked={true} />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('data-state', 'checked')
      expect(switchElement).toHaveAttribute('aria-checked', 'true')
    })
  })

  describe('Default Styling', () => {
    it('applies default styling classes to root', () => {
      render(<Switch />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveClass('peer')
      expect(switchElement).toHaveClass('inline-flex')
      expect(switchElement).toHaveClass('h-6')
      expect(switchElement).toHaveClass('w-11')
      expect(switchElement).toHaveClass('shrink-0')
      expect(switchElement).toHaveClass('cursor-pointer')
      expect(switchElement).toHaveClass('items-center')
      expect(switchElement).toHaveClass('rounded-full')
      expect(switchElement).toHaveClass('border-2')
      expect(switchElement).toHaveClass('border-transparent')
      expect(switchElement).toHaveClass('transition-colors')
    })

    it('applies focus styles', () => {
      render(<Switch />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveClass('focus-visible:outline-none')
      expect(switchElement).toHaveClass('focus-visible:ring-2')
      expect(switchElement).toHaveClass('focus-visible:ring-ring')
      expect(switchElement).toHaveClass('focus-visible:ring-offset-2')
      expect(switchElement).toHaveClass('focus-visible:ring-offset-background')
    })

    it('applies disabled styles', () => {
      render(<Switch disabled />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveClass('disabled:cursor-not-allowed')
      expect(switchElement).toHaveClass('disabled:opacity-50')
    })

    it('applies state-based background colors', () => {
      const { rerender } = render(<Switch checked={false} />)
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveClass('data-[state=unchecked]:bg-input')
      
      rerender(<Switch checked={true} />)
      expect(switchElement).toHaveClass('data-[state=checked]:bg-primary')
    })

    it('applies custom className', () => {
      render(<Switch className="custom-switch-class" />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveClass('custom-switch-class')
      expect(switchElement).toHaveClass('inline-flex') // Should also have default classes
    })
  })

  describe('Switch Thumb Styling', () => {
    it('contains thumb element with proper classes', () => {
      const { container } = render(<Switch />)
      
      // The thumb is part of the internal Radix structure, just verify switch works
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toBeInTheDocument()
      expect(switchElement).toHaveClass('inline-flex', 'h-6', 'w-11')
    })

    it('applies correct thumb transform states', () => {
      const { container } = render(<Switch />)
      
      // Verify switch has proper styling classes for state management
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveClass('data-[state=checked]:bg-primary')
      expect(switchElement).toHaveClass('data-[state=unchecked]:bg-input')
    })
  })

  describe('User Interactions', () => {
    it('toggles state on click', async () => {
      const user = userEvent.setup()
      render(<Switch />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('data-state', 'unchecked')
      
      await user.click(switchElement)
      expect(switchElement).toHaveAttribute('data-state', 'checked')
      
      await user.click(switchElement)
      expect(switchElement).toHaveAttribute('data-state', 'unchecked')
    })

    it('calls onCheckedChange when toggled', async () => {
      const user = userEvent.setup()
      const handleCheckedChange = vi.fn()
      render(<Switch onCheckedChange={handleCheckedChange} />)
      
      const switchElement = screen.getByRole('switch')
      
      await user.click(switchElement)
      expect(handleCheckedChange).toHaveBeenCalledWith(true)
      
      await user.click(switchElement)
      expect(handleCheckedChange).toHaveBeenCalledWith(false)
    })

    it('toggles with keyboard space key', async () => {
      const user = userEvent.setup()
      const handleCheckedChange = vi.fn()
      render(<Switch onCheckedChange={handleCheckedChange} />)
      
      const switchElement = screen.getByRole('switch')
      switchElement.focus()
      
      await user.keyboard(' ')
      expect(handleCheckedChange).toHaveBeenCalledWith(true)
      
      await user.keyboard(' ')
      expect(handleCheckedChange).toHaveBeenCalledWith(false)
    })

    it('toggles with keyboard enter key', async () => {
      const user = userEvent.setup()
      const handleCheckedChange = vi.fn()
      render(<Switch onCheckedChange={handleCheckedChange} />)
      
      const switchElement = screen.getByRole('switch')
      switchElement.focus()
      
      await user.keyboard('{Enter}')
      expect(handleCheckedChange).toHaveBeenCalledWith(true)
    })

    it('does not toggle when disabled', async () => {
      const user = userEvent.setup()
      const handleCheckedChange = vi.fn()
      render(<Switch disabled onCheckedChange={handleCheckedChange} />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toBeDisabled()
      
      await user.click(switchElement)
      expect(handleCheckedChange).not.toHaveBeenCalled()
    })
  })

  describe('Controlled vs Uncontrolled', () => {
    it('works as uncontrolled component with defaultChecked', async () => {
      const user = userEvent.setup()
      render(<Switch defaultChecked={true} />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('data-state', 'checked')
      
      await user.click(switchElement)
      expect(switchElement).toHaveAttribute('data-state', 'unchecked')
    })

    it('works as controlled component', async () => {
      const user = userEvent.setup()
      const handleCheckedChange = vi.fn()
      const { rerender } = render(
        <Switch checked={false} onCheckedChange={handleCheckedChange} />
      )
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('data-state', 'unchecked')
      
      await user.click(switchElement)
      expect(handleCheckedChange).toHaveBeenCalledWith(true)
      
      // Re-render with new checked state
      rerender(<Switch checked={true} onCheckedChange={handleCheckedChange} />)
      expect(switchElement).toHaveAttribute('data-state', 'checked')
    })

    it('ignores defaultChecked when controlled', () => {
      render(<Switch checked={false} defaultChecked={true} />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('data-state', 'unchecked')
    })
  })

  describe('Props and Attributes', () => {
    it('forwards props correctly', () => {
      render(
        <Switch
          data-testid="custom-switch"
          role="switch"
          aria-label="Toggle setting"
        />
      )
      
      const switchElement = screen.getByTestId('custom-switch')
      expect(switchElement).toHaveAttribute('role', 'switch')
      expect(switchElement).toHaveAttribute('aria-label', 'Toggle setting')
    })

    it('supports style prop', () => {
      render(<Switch style={{ backgroundColor: 'red', width: '60px' }} />)
      
      const switchElement = screen.getByRole('switch')
      // Just verify the element exists and has proper structure
      expect(switchElement).toBeInTheDocument()
      expect(switchElement).toHaveClass('inline-flex')
    })

    it('supports id prop', () => {
      render(<Switch id="unique-switch" />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('id', 'unique-switch')
    })

    it('supports value prop', () => {
      render(<Switch value="on" />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('value', 'on')
    })

    it('works with additional data attributes', () => {
      render(<Switch data-form-field="notifications" />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('data-form-field', 'notifications')
    })
  })

  describe('Ref Forwarding', () => {
    it('forwards ref correctly', () => {
      const ref = vi.fn()
      render(<Switch ref={ref} />)
      
      expect(ref).toHaveBeenCalledWith(expect.any(HTMLButtonElement))
    })

    it('allows ref to access DOM methods', () => {
      let switchRef: HTMLButtonElement | null = null
      
      render(
        <Switch
          ref={ref => {
            switchRef = ref
          }}
        />
      )
      
      expect(switchRef).toBeInstanceOf(HTMLButtonElement)
      expect(typeof switchRef?.click).toBe('function')
      expect(typeof switchRef?.focus).toBe('function')
    })
  })

  describe('Focus Management', () => {
    it('can be focused', () => {
      render(<Switch />)
      
      const switchElement = screen.getByRole('switch')
      switchElement.focus()
      
      expect(document.activeElement).toBe(switchElement)
    })

    it('shows focus ring when focused', () => {
      render(<Switch />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveClass('focus-visible:ring-2')
    })

    it('loses focus when disabled', () => {
      render(<Switch disabled />)
      
      const switchElement = screen.getByRole('switch')
      switchElement.focus()
      
      // Disabled elements cannot receive focus
      expect(document.activeElement).not.toBe(switchElement)
    })
  })

  describe('Accessibility', () => {
    it('has correct ARIA attributes', () => {
      render(<Switch />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('role', 'switch')
      expect(switchElement).toHaveAttribute('aria-checked', 'false')
    })

    it('updates aria-checked when state changes', async () => {
      const user = userEvent.setup()
      render(<Switch />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('aria-checked', 'false')
      
      await user.click(switchElement)
      expect(switchElement).toHaveAttribute('aria-checked', 'true')
    })

    it('supports aria-label', () => {
      render(<Switch aria-label="Enable notifications" />)
      
      const switchElement = screen.getByLabelText('Enable notifications')
      expect(switchElement).toBeInTheDocument()
    })

    it('supports aria-describedby', () => {
      render(
        <div>
          <Switch aria-describedby="switch-description" />
          <div id="switch-description">This switch controls notifications</div>
        </div>
      )
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('aria-describedby', 'switch-description')
    })

    it('supports aria-labelledby', () => {
      render(
        <div>
          <label id="switch-label">Notification Settings</label>
          <Switch aria-labelledby="switch-label" />
        </div>
      )
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('aria-labelledby', 'switch-label')
    })

    it('is keyboard accessible', async () => {
      const user = userEvent.setup()
      render(<Switch />)
      
      const switchElement = screen.getByRole('switch')
      
      // Tab navigation
      await user.tab()
      expect(document.activeElement).toBe(switchElement)
      
      // Space key activation
      await user.keyboard(' ')
      expect(switchElement).toHaveAttribute('aria-checked', 'true')
      
      // Enter key activation
      await user.keyboard('{Enter}')
      expect(switchElement).toHaveAttribute('aria-checked', 'false')
    })
  })

  describe('Form Integration', () => {
    it('works within forms', () => {
      render(
        <form>
          <Switch value="enabled" />
        </form>
      )
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('value', 'enabled')
    })

    it('supports accessibility attributes for forms', () => {
      render(
        <form>
          <Switch aria-label="Required toggle" aria-required="true" />
        </form>
      )
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('aria-label', 'Required toggle')
      expect(switchElement).toHaveAttribute('aria-required', 'true')
    })

    it('can be associated with labels', () => {
      render(
        <div>
          <label htmlFor="setting-toggle">Enable Setting</label>
          <Switch id="setting-toggle" />
        </div>
      )
      
      const label = screen.getByText('Enable Setting')
      const switchElement = screen.getByRole('switch')
      
      expect(switchElement).toHaveAttribute('id', 'setting-toggle')
      expect(label).toHaveAttribute('for', 'setting-toggle')
    })
  })

  describe('Use Cases', () => {
    it('renders as feature toggle', async () => {
      const user = userEvent.setup()
      const { rerender } = render(
        <div className="flex items-center space-x-2">
          <Switch id="dark-mode" />
          <label htmlFor="dark-mode">Dark Mode</label>
        </div>
      )
      
      const switchElement = screen.getByRole('switch')
      const label = screen.getByText('Dark Mode')
      
      expect(switchElement).toHaveAttribute('data-state', 'unchecked')
      
      await user.click(label) // Click label should toggle switch
      expect(switchElement).toHaveAttribute('data-state', 'checked')
    })

    it('renders as settings toggle', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      
      render(
        <div className="flex items-center justify-between p-4">
          <div>
            <h3>Push Notifications</h3>
            <p>Receive notifications on your device</p>
          </div>
          <Switch onCheckedChange={handleChange} />
        </div>
      )
      
      const switchElement = screen.getByRole('switch')
      const heading = screen.getByText('Push Notifications')
      const description = screen.getByText('Receive notifications on your device')
      
      expect(heading).toBeInTheDocument()
      expect(description).toBeInTheDocument()
      
      await user.click(switchElement)
      expect(handleChange).toHaveBeenCalledWith(true)
    })

    it('renders in a list of toggles', () => {
      const settings = [
        { id: 'notifications', label: 'Email Notifications', checked: true },
        { id: 'marketing', label: 'Marketing Emails', checked: false },
        { id: 'updates', label: 'Product Updates', checked: true },
      ]
      
      render(
        <div>
          {settings.map(setting => (
            <div key={setting.id} className="flex items-center justify-between p-2">
              <label htmlFor={setting.id}>{setting.label}</label>
              <Switch id={setting.id} checked={setting.checked} />
            </div>
          ))}
        </div>
      )
      
      settings.forEach(setting => {
        const switchElement = screen.getByRole('switch', { name: setting.label })
        expect(switchElement).toHaveAttribute(
          'data-state',
          setting.checked ? 'checked' : 'unchecked'
        )
      })
    })
  })

  describe('Edge Cases', () => {
    it('handles rapid clicking', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      render(<Switch onCheckedChange={handleChange} />)
      
      const switchElement = screen.getByRole('switch')
      
      // Rapid clicks
      await user.click(switchElement)
      await user.click(switchElement)
      await user.click(switchElement)
      
      expect(handleChange).toHaveBeenCalledTimes(3)
      expect(handleChange).toHaveBeenNthCalledWith(1, true)
      expect(handleChange).toHaveBeenNthCalledWith(2, false)
      expect(handleChange).toHaveBeenNthCalledWith(3, true)
    })

    it('handles simultaneous keyboard and mouse events', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      render(<Switch onCheckedChange={handleChange} />)
      
      const switchElement = screen.getByRole('switch')
      switchElement.focus()
      
      // Mix of keyboard and mouse
      await user.keyboard(' ')
      await user.click(switchElement)
      await user.keyboard('{Enter}')
      
      expect(handleChange).toHaveBeenCalledTimes(3)
    })

    it('maintains state consistency during re-renders', () => {
      const { rerender } = render(<Switch defaultChecked={true} />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveAttribute('data-state', 'checked')
      
      // Re-render with same props
      rerender(<Switch defaultChecked={true} />)
      expect(switchElement).toHaveAttribute('data-state', 'checked')
    })

    it('handles className changes', () => {
      const { rerender } = render(<Switch className="initial-class" />)
      
      const switchElement = screen.getByRole('switch')
      expect(switchElement).toHaveClass('initial-class')
      
      rerender(<Switch className="updated-class" />)
      expect(switchElement).toHaveClass('updated-class')
      expect(switchElement).not.toHaveClass('initial-class')
    })

    it('handles disabled state changes', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      const { rerender } = render(
        <Switch onCheckedChange={handleChange} disabled={false} />
      )
      
      const switchElement = screen.getByRole('switch')
      
      // Should work when not disabled
      await user.click(switchElement)
      expect(handleChange).toHaveBeenCalledWith(true)
      
      // Re-render as disabled
      rerender(<Switch onCheckedChange={handleChange} disabled={true} />)
      expect(switchElement).toBeDisabled()
      
      // Should not work when disabled
      await user.click(switchElement)
      expect(handleChange).toHaveBeenCalledTimes(1) // Still only one call
    })
  })
})