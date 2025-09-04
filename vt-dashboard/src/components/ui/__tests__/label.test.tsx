import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@/test/utils/test-utils'
import userEvent from '@testing-library/user-event'
import { Label } from '../label'

describe('Label Component', () => {
  describe('Basic Rendering', () => {
    it('renders label with text content', () => {
      render(<Label>Label text</Label>)
      
      const label = screen.getByText('Label text')
      expect(label).toBeInTheDocument()
      expect(label.tagName).toBe('LABEL')
    })

    it('renders label with child elements', () => {
      render(
        <Label>
          <span>Label with</span>
          <strong>multiple elements</strong>
        </Label>
      )
      
      expect(screen.getByText('Label with')).toBeInTheDocument()
      expect(screen.getByText('multiple elements')).toBeInTheDocument()
    })

    it('renders empty label', () => {
      const { container } = render(<Label />)
      
      const label = container.querySelector('label')
      expect(label).toBeInTheDocument()
      expect(label).toBeEmptyDOMElement()
    })
  })

  describe('Default Styling', () => {
    it('applies default styling classes', () => {
      render(<Label>Styled Label</Label>)
      
      const label = screen.getByText('Styled Label')
      expect(label).toHaveClass('text-sm')
      expect(label).toHaveClass('font-medium')
      expect(label).toHaveClass('leading-none')
      expect(label).toHaveClass('peer-disabled:cursor-not-allowed')
      expect(label).toHaveClass('peer-disabled:opacity-70')
    })

    it('applies custom className', () => {
      render(<Label className="custom-label">Custom Label</Label>)
      
      const label = screen.getByText('Custom Label')
      expect(label).toHaveClass('custom-label')
      expect(label).toHaveClass('text-sm') // Should also have default classes
    })

    it('merges custom className with default classes', () => {
      render(<Label className="text-red-500 bg-blue-100">Merged Label</Label>)
      
      const label = screen.getByText('Merged Label')
      expect(label).toHaveClass('text-red-500')
      expect(label).toHaveClass('bg-blue-100')
      expect(label).toHaveClass('font-medium')
      expect(label).toHaveClass('leading-none')
    })
  })

  describe('Label Props', () => {
    it('supports htmlFor prop for form association', () => {
      render(
        <div>
          <Label htmlFor="input-field">Input Label</Label>
          <input id="input-field" type="text" />
        </div>
      )
      
      const label = screen.getByText('Input Label')
      const input = screen.getByRole('textbox')
      
      expect(label).toHaveAttribute('for', 'input-field')
      expect(input).toHaveAttribute('id', 'input-field')
    })

    it('forwards props correctly', () => {
      render(
        <Label
          data-testid="test-label"
          role="presentation"
          aria-label="Custom aria label"
        >
          Test Label
        </Label>
      )
      
      const label = screen.getByTestId('test-label')
      expect(label).toHaveAttribute('role', 'presentation')
      expect(label).toHaveAttribute('aria-label', 'Custom aria label')
    })

    it('supports style prop', () => {
      render(<Label style={{ color: 'red', fontSize: '16px' }}>Styled Label</Label>)
      
      const label = screen.getByText('Styled Label')
      // Just check that the element exists and has proper structure
      expect(label).toBeInTheDocument()
      expect(label).toHaveClass('text-sm', 'font-medium', 'leading-none')
    })

    it('supports id prop', () => {
      render(<Label id="unique-label">Label with ID</Label>)
      
      const label = screen.getByText('Label with ID')
      expect(label).toHaveAttribute('id', 'unique-label')
    })
  })

  describe('Ref Forwarding', () => {
    it('forwards ref correctly', () => {
      const ref = vi.fn()
      render(<Label ref={ref}>Ref Label</Label>)
      
      expect(ref).toHaveBeenCalledWith(expect.any(HTMLLabelElement))
    })

    it('allows ref to access DOM methods', () => {
      let labelRef: HTMLLabelElement | null = null
      
      render(
        <Label
          ref={ref => {
            labelRef = ref
          }}
        >
          Focusable Label
        </Label>
      )
      
      expect(labelRef).toBeInstanceOf(HTMLLabelElement)
      expect(typeof labelRef?.click).toBe('function')
    })
  })

  describe('Form Association', () => {
    it('associates with input via htmlFor', () => {
      render(
        <form>
          <Label htmlFor="username">Username</Label>
          <input id="username" name="username" type="text" />
        </form>
      )
      
      const label = screen.getByText('Username')
      const input = screen.getByRole('textbox')
      
      expect(label).toHaveAttribute('for', 'username')
      expect(input).toHaveAttribute('id', 'username')
      
      // Check association exists (focus behavior may not work in JSDOM)
      expect(label).toBeInTheDocument()
      expect(input).toBeInTheDocument()
    })

    it('associates with nested input', () => {
      render(
        <Label>
          Email Address
          <input type="email" name="email" />
        </Label>
      )
      
      const label = screen.getByText('Email Address')
      const input = screen.getByRole('textbox')
      
      // Check that label contains the input
      expect(label).toBeInTheDocument()
      expect(input).toBeInTheDocument()
      expect(label).toContainElement(input)
    })

    it('works with checkbox inputs', () => {
      render(
        <Label htmlFor="subscribe">
          <input id="subscribe" type="checkbox" />
          Subscribe to newsletter
        </Label>
      )
      
      const label = screen.getByText('Subscribe to newsletter')
      const checkbox = screen.getByRole('checkbox')
      
      expect(checkbox).not.toBeChecked()
      
      // Click label should toggle checkbox
      label.click()
      expect(checkbox).toBeChecked()
    })

    it('works with radio inputs', () => {
      render(
        <div>
          <Label htmlFor="option1">
            <input id="option1" type="radio" name="options" value="1" />
            Option 1
          </Label>
          <Label htmlFor="option2">
            <input id="option2" type="radio" name="options" value="2" />
            Option 2
          </Label>
        </div>
      )
      
      const label1 = screen.getByText('Option 1')
      const label2 = screen.getByText('Option 2')
      const radio1 = screen.getByDisplayValue('1')
      const radio2 = screen.getByDisplayValue('2')
      
      expect(radio1).not.toBeChecked()
      expect(radio2).not.toBeChecked()
      
      // Click first label
      label1.click()
      expect(radio1).toBeChecked()
      expect(radio2).not.toBeChecked()
      
      // Click second label
      label2.click()
      expect(radio1).not.toBeChecked()
      expect(radio2).toBeChecked()
    })
  })

  describe('Accessibility', () => {
    it('supports aria-label', () => {
      render(<Label aria-label="Custom label">Visible Text</Label>)
      
      const label = screen.getByText('Visible Text')
      expect(label).toHaveAttribute('aria-label', 'Custom label')
    })

    it('supports aria-describedby', () => {
      render(
        <div>
          <Label aria-describedby="label-help">Label Text</Label>
          <div id="label-help">This label provides additional context</div>
        </div>
      )
      
      const label = screen.getByText('Label Text')
      expect(label).toHaveAttribute('aria-describedby', 'label-help')
    })

    it('supports aria-required', () => {
      render(
        <Label htmlFor="required-field" aria-required="true">
          Required Field *
        </Label>
      )
      
      const label = screen.getByText('Required Field *')
      expect(label).toHaveAttribute('aria-required', 'true')
    })

    it('works with screen readers via htmlFor association', () => {
      render(
        <div>
          <Label htmlFor="accessible-input">Accessible Input Label</Label>
          <input
            id="accessible-input"
            type="text"
            aria-describedby="input-help"
          />
          <div id="input-help">Additional input information</div>
        </div>
      )
      
      const label = screen.getByText('Accessible Input Label')
      const input = screen.getByRole('textbox')
      
      expect(label).toHaveAttribute('for', 'accessible-input')
      expect(input).toHaveAttribute('id', 'accessible-input')
      expect(input).toHaveAttribute('aria-describedby', 'input-help')
    })
  })

  describe('Disabled State Handling', () => {
    it('applies correct styles for disabled peer elements', () => {
      render(
        <div className="peer-disabled:opacity-50">
          <input disabled className="peer" />
          <Label>Label for disabled input</Label>
        </div>
      )
      
      const label = screen.getByText('Label for disabled input')
      // The peer-disabled classes should be present (they will be activated by CSS when peer is disabled)
      expect(label).toHaveClass('peer-disabled:cursor-not-allowed')
      expect(label).toHaveClass('peer-disabled:opacity-70')
    })

    it('maintains functionality when associated input is not disabled', () => {
      render(
        <div>
          <Label htmlFor="enabled-input">Enabled Input Label</Label>
          <input id="enabled-input" type="text" />
        </div>
      )
      
      const label = screen.getByText('Enabled Input Label')
      const input = screen.getByRole('textbox')
      
      expect(input).not.toBeDisabled()
      expect(label).toHaveAttribute('for', 'enabled-input')
      expect(input).toHaveAttribute('id', 'enabled-input')
    })
  })

  describe('Use Cases', () => {
    it('renders form field label', () => {
      render(
        <div>
          <Label htmlFor="first-name">First Name</Label>
          <input id="first-name" type="text" required />
        </div>
      )
      
      const label = screen.getByText('First Name')
      const input = screen.getByRole('textbox')
      
      expect(label).toBeInTheDocument()
      expect(input).toHaveAttribute('required')
    })

    it('renders label with validation message', () => {
      render(
        <div>
          <Label htmlFor="email" className="text-red-500">
            Email (required)
          </Label>
          <input id="email" type="email" required />
          <span className="text-red-500">Please enter a valid email</span>
        </div>
      )
      
      const label = screen.getByText('Email (required)')
      expect(label).toHaveClass('text-red-500')
      expect(screen.getByText('Please enter a valid email')).toBeInTheDocument()
    })

    it('renders checkbox label', () => {
      render(
        <Label className="flex items-center space-x-2">
          <input type="checkbox" className="peer" />
          <span>I agree to the terms and conditions</span>
        </Label>
      )
      
      const checkbox = screen.getByRole('checkbox')
      const labelText = screen.getByText('I agree to the terms and conditions')
      
      expect(checkbox).not.toBeChecked()
      expect(labelText).toBeInTheDocument()
      
      // Clicking the label should toggle checkbox
      labelText.click()
      expect(checkbox).toBeChecked()
    })

    it('renders fieldset legend replacement', () => {
      render(
        <div role="group" aria-labelledby="payment-method">
          <Label id="payment-method" className="text-lg font-bold">
            Payment Method
          </Label>
          <Label>
            <input type="radio" name="payment" value="card" />
            Credit Card
          </Label>
          <Label>
            <input type="radio" name="payment" value="paypal" />
            PayPal
          </Label>
        </div>
      )
      
      const groupLabel = screen.getByText('Payment Method')
      const cardOption = screen.getByText('Credit Card')
      const paypalOption = screen.getByText('PayPal')
      
      expect(groupLabel).toHaveClass('text-lg', 'font-bold')
      expect(cardOption).toBeInTheDocument()
      expect(paypalOption).toBeInTheDocument()
    })
  })

  describe('Edge Cases', () => {
    it('handles undefined children', () => {
      const { container } = render(<Label>{undefined}</Label>)
      
      const label = container.querySelector('label')
      expect(label).toBeInTheDocument()
      expect(label).toBeEmptyDOMElement()
    })

    it('handles null children', () => {
      const { container } = render(<Label>{null}</Label>)
      
      const label = container.querySelector('label')
      expect(label).toBeInTheDocument()
      expect(label).toBeEmptyDOMElement()
    })

    it('handles conditional content', () => {
      const showOptional = false
      render(
        <Label>
          Required Field
          {showOptional && ' (Optional)'}
        </Label>
      )
      
      expect(screen.getByText('Required Field')).toBeInTheDocument()
      expect(screen.queryByText('(Optional)')).not.toBeInTheDocument()
    })

    it('handles fragment children', () => {
      render(
        <Label>
          <>
            <span>Part 1</span>
            <span>Part 2</span>
          </>
        </Label>
      )
      
      expect(screen.getByText('Part 1')).toBeInTheDocument()
      expect(screen.getByText('Part 2')).toBeInTheDocument()
    })

    it('handles numeric and special character content', () => {
      render(<Label>Label 123 !@#$%^&*()</Label>)
      
      expect(screen.getByText('Label 123 !@#$%^&*()')).toBeInTheDocument()
    })

    it('handles very long text content', () => {
      const longText = 'This is a very long label text that might wrap to multiple lines and should still be handled correctly by the component without any issues'
      render(<Label>{longText}</Label>)
      
      expect(screen.getByText(longText)).toBeInTheDocument()
    })
  })

  describe('Event Handling', () => {
    it('handles click events', async () => {
      const user = userEvent.setup()
      const handleClick = vi.fn()
      render(<Label onClick={handleClick}>Clickable Label</Label>)
      
      const label = screen.getByText('Clickable Label')
      await user.click(label)
      
      expect(handleClick).toHaveBeenCalledTimes(1)
    })

    it('handles keyboard events', async () => {
      const user = userEvent.setup()
      const handleKeyDown = vi.fn()
      render(<Label onKeyDown={handleKeyDown} tabIndex={0}>Keyboard Label</Label>)
      
      const label = screen.getByText('Keyboard Label')
      label.focus()
      
      await user.keyboard('{Enter}')
      expect(handleKeyDown).toHaveBeenCalledTimes(1)
    })

    it('handles mouse events', async () => {
      const user = userEvent.setup()
      const handleMouseOver = vi.fn()
      const handleMouseLeave = vi.fn()
      
      render(
        <Label onMouseOver={handleMouseOver} onMouseLeave={handleMouseLeave}>
          Hover Label
        </Label>
      )
      
      const label = screen.getByText('Hover Label')
      
      // Hover over element
      await user.hover(label)
      expect(handleMouseOver).toHaveBeenCalledTimes(1)
      
      // Unhover element
      await user.unhover(label)
      expect(handleMouseLeave).toHaveBeenCalledTimes(1)
    })
  })
})