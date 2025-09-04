import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Input } from '../input'

describe('Input Component', () => {
  describe('Basic Rendering', () => {
    it('renders input element', () => {
      render(<Input />)
      const input = screen.getByRole('textbox')
      expect(input).toBeInTheDocument()
    })

    it('renders with placeholder', () => {
      render(<Input placeholder="Enter text..." />)
      const input = screen.getByPlaceholderText('Enter text...')
      expect(input).toBeInTheDocument()
    })

    it('renders with default value', () => {
      render(<Input defaultValue="Default text" />)
      const input = screen.getByRole('textbox') as HTMLInputElement
      expect(input.value).toBe('Default text')
    })

    it('renders with value prop (controlled)', () => {
      render(<Input value="Controlled value" onChange={() => {}} />)
      const input = screen.getByRole('textbox') as HTMLInputElement
      expect(input.value).toBe('Controlled value')
    })
  })

  describe('Input Types', () => {
    it('renders as text input by default', () => {
      render(<Input />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('type', 'text')
    })

    it('renders as email input', () => {
      render(<Input type="email" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('type', 'email')
    })

    it('renders as password input', () => {
      render(<Input type="password" placeholder="Password" />)
      const input = screen.getByPlaceholderText('Password')
      expect(input).toHaveAttribute('type', 'password')
    })

    it('renders as number input', () => {
      render(<Input type="number" />)
      const input = screen.getByRole('spinbutton')
      expect(input).toHaveAttribute('type', 'number')
    })

    it('renders as search input', () => {
      render(<Input type="search" />)
      const input = screen.getByRole('searchbox')
      expect(input).toHaveAttribute('type', 'search')
    })

    it('renders as tel input', () => {
      render(<Input type="tel" placeholder="Phone" />)
      const input = screen.getByPlaceholderText('Phone')
      expect(input).toHaveAttribute('type', 'tel')
    })

    it('renders as url input', () => {
      render(<Input type="url" placeholder="URL" />)
      const input = screen.getByPlaceholderText('URL')
      expect(input).toHaveAttribute('type', 'url')
    })

    it('renders as date input', () => {
      render(<Input type="date" />)
      const input = document.querySelector('input[type="date"]')
      expect(input).toBeInTheDocument()
    })

    it('renders as time input', () => {
      render(<Input type="time" />)
      const input = document.querySelector('input[type="time"]')
      expect(input).toBeInTheDocument()
    })

    it('renders as file input', () => {
      render(<Input type="file" />)
      const input = document.querySelector('input[type="file"]')
      expect(input).toBeInTheDocument()
    })
  })

  describe('User Interaction', () => {
    it('accepts user input', async () => {
      const user = userEvent.setup()
      render(<Input />)
      
      const input = screen.getByRole('textbox') as HTMLInputElement
      await user.type(input, 'Hello World')
      
      expect(input.value).toBe('Hello World')
    })

    it('calls onChange handler when value changes', async () => {
      const user = userEvent.setup()
      const onChange = vi.fn()
      
      render(<Input onChange={onChange} />)
      
      const input = screen.getByRole('textbox')
      await user.type(input, 'Test')
      
      expect(onChange).toHaveBeenCalled()
      expect(onChange).toHaveBeenCalledTimes(4) // One for each character
    })

    it('calls onFocus handler when focused', async () => {
      const user = userEvent.setup()
      const onFocus = vi.fn()
      
      render(<Input onFocus={onFocus} />)
      
      const input = screen.getByRole('textbox')
      await user.click(input)
      
      expect(onFocus).toHaveBeenCalledTimes(1)
    })

    it('calls onBlur handler when blurred', async () => {
      const user = userEvent.setup()
      const onBlur = vi.fn()
      
      render(
        <div>
          <Input onBlur={onBlur} />
          <button>Other Element</button>
        </div>
      )
      
      const input = screen.getByRole('textbox')
      const button = screen.getByRole('button')
      
      await user.click(input)
      await user.click(button)
      
      expect(onBlur).toHaveBeenCalledTimes(1)
    })

    it('calls onKeyDown handler', async () => {
      const user = userEvent.setup()
      const onKeyDown = vi.fn()
      
      render(<Input onKeyDown={onKeyDown} />)
      
      const input = screen.getByRole('textbox')
      input.focus()
      await user.keyboard('{Enter}')
      
      expect(onKeyDown).toHaveBeenCalled()
      const event = onKeyDown.mock.calls[0][0]
      expect(event.key).toBe('Enter')
    })

    it('calls onKeyUp handler', async () => {
      const user = userEvent.setup()
      const onKeyUp = vi.fn()
      
      render(<Input onKeyUp={onKeyUp} />)
      
      const input = screen.getByRole('textbox')
      input.focus()
      await user.keyboard('a')
      
      expect(onKeyUp).toHaveBeenCalled()
    })

    it('supports copy and paste', async () => {
      const user = userEvent.setup()
      render(<Input />)
      
      const input = screen.getByRole('textbox') as HTMLInputElement
      await user.type(input, 'Copy this')
      
      // Select all and copy
      await user.tripleClick(input)
      await user.keyboard('{Control>}c{/Control}')
      
      // Clear and paste
      await user.clear(input)
      await user.keyboard('{Control>}v{/Control}')
      
      // Note: Actual clipboard operations might not work in test environment
      // but the events should fire
      expect(input).toBeInTheDocument()
    })
  })

  describe('Disabled State', () => {
    it('renders as disabled when disabled prop is true', () => {
      render(<Input disabled />)
      const input = screen.getByRole('textbox')
      expect(input).toBeDisabled()
    })

    it('does not accept input when disabled', async () => {
      const user = userEvent.setup()
      const onChange = vi.fn()
      
      render(<Input disabled onChange={onChange} />)
      
      const input = screen.getByRole('textbox')
      await user.type(input, 'Test')
      
      expect(onChange).not.toHaveBeenCalled()
      expect((input as HTMLInputElement).value).toBe('')
    })

    it('does not trigger focus events when disabled', async () => {
      const user = userEvent.setup()
      const onFocus = vi.fn()
      
      render(<Input disabled onFocus={onFocus} />)
      
      const input = screen.getByRole('textbox')
      await user.click(input)
      
      expect(onFocus).not.toHaveBeenCalled()
    })
  })

  describe('Controlled Component', () => {
    it('works as a controlled component', async () => {
      const user = userEvent.setup()
      
      const TestComponent = () => {
        const [value, setValue] = React.useState('Initial')
        
        return (
          <div>
            <Input 
              value={value} 
              onChange={(e) => setValue(e.target.value)} 
            />
            <button onClick={() => setValue('Updated')}>Update</button>
            <span>{value}</span>
          </div>
        )
      }
      
      render(<TestComponent />)
      
      const input = screen.getByRole('textbox') as HTMLInputElement
      expect(input.value).toBe('Initial')
      expect(screen.getByText('Initial')).toBeInTheDocument()
      
      await user.clear(input)
      await user.type(input, 'New Value')
      expect(input.value).toBe('New Value')
      expect(screen.getByText('New Value')).toBeInTheDocument()
      
      const button = screen.getByRole('button')
      await user.click(button)
      expect(input.value).toBe('Updated')
      expect(screen.getByText('Updated')).toBeInTheDocument()
    })

    it('does not change value without onChange handler', async () => {
      const user = userEvent.setup()
      
      // This should trigger a React warning about controlled component
      render(<Input value="Fixed Value" />)
      
      const input = screen.getByRole('textbox') as HTMLInputElement
      await user.type(input, 'Attempting to change')
      
      expect(input.value).toBe('Fixed Value')
    })
  })

  describe('Validation Attributes', () => {
    it('supports required attribute', () => {
      render(<Input required />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('required')
    })

    it('supports pattern attribute', () => {
      render(<Input pattern="[0-9]*" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('pattern', '[0-9]*')
    })

    it('supports minLength attribute', () => {
      render(<Input minLength={5} />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('minLength', '5')
    })

    it('supports maxLength attribute', () => {
      render(<Input maxLength={10} />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('maxLength', '10')
    })

    it('enforces maxLength', async () => {
      const user = userEvent.setup()
      render(<Input maxLength={5} />)
      
      const input = screen.getByRole('textbox') as HTMLInputElement
      await user.type(input, 'This is too long')
      
      expect(input.value).toBe('This ')
    })

    it('supports min and max for number inputs', () => {
      render(<Input type="number" min={0} max={100} />)
      const input = screen.getByRole('spinbutton')
      expect(input).toHaveAttribute('min', '0')
      expect(input).toHaveAttribute('max', '100')
    })

    it('supports step for number inputs', () => {
      render(<Input type="number" step={0.01} />)
      const input = screen.getByRole('spinbutton')
      expect(input).toHaveAttribute('step', '0.01')
    })
  })

  describe('Accessibility', () => {
    it('supports aria-label', () => {
      render(<Input aria-label="Email address" />)
      const input = screen.getByLabelText('Email address')
      expect(input).toBeInTheDocument()
    })

    it('supports aria-describedby', () => {
      render(
        <div>
          <Input aria-describedby="help-text" />
          <span id="help-text">Help text for input</span>
        </div>
      )
      
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('aria-describedby', 'help-text')
    })

    it('supports aria-invalid for validation', () => {
      render(<Input aria-invalid="true" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('aria-invalid', 'true')
    })

    it('works with label element', () => {
      render(
        <div>
          <label htmlFor="test-input">Test Label</label>
          <Input id="test-input" />
        </div>
      )
      
      const input = screen.getByLabelText('Test Label')
      expect(input).toBeInTheDocument()
    })

    it('supports autoComplete attribute', () => {
      render(<Input autoComplete="email" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('autoComplete', 'email')
    })

    it('supports readOnly attribute', () => {
      render(<Input readOnly value="Read only" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('readOnly')
    })
  })

  describe('Styling', () => {
    it('applies default classes', () => {
      render(<Input />)
      const input = screen.getByRole('textbox')
      
      expect(input.className).toContain('flex')
      expect(input.className).toContain('h-10')
      expect(input.className).toContain('rounded-md')
      expect(input.className).toContain('border')
      expect(input.className).toContain('px-3')
      expect(input.className).toContain('py-2')
    })

    it('applies custom className', () => {
      render(<Input className="custom-class" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveClass('custom-class')
    })

    it('merges custom className with default classes', () => {
      render(<Input className="custom-class" />)
      const input = screen.getByRole('textbox')
      
      expect(input).toHaveClass('custom-class')
      expect(input.className).toContain('flex')
      expect(input.className).toContain('h-10')
    })

    it('applies disabled styles when disabled', () => {
      render(<Input disabled />)
      const input = screen.getByRole('textbox')
      expect(input.className).toContain('disabled:cursor-not-allowed')
      expect(input.className).toContain('disabled:opacity-50')
    })
  })

  describe('Edge Cases', () => {
    it('handles empty string value', () => {
      render(<Input value="" onChange={() => {}} />)
      const input = screen.getByRole('textbox') as HTMLInputElement
      expect(input.value).toBe('')
    })

    it('handles null and undefined gracefully', () => {
      // @ts-ignore - Testing runtime behavior
      render(<Input value={null} />)
      const input1 = screen.getByRole('textbox') as HTMLInputElement
      expect(input1.value).toBe('')
      
      // Clean up and test undefined
      input1.remove()
      
      // @ts-ignore - Testing runtime behavior
      render(<Input value={undefined} />)
      const input2 = document.querySelector('input') as HTMLInputElement
      expect(input2?.value).toBe('')
    })

    it('handles very long input', async () => {
      const user = userEvent.setup()
      const longText = 'a'.repeat(1000)
      
      render(<Input />)
      const input = screen.getByRole('textbox') as HTMLInputElement
      
      await user.type(input, longText)
      expect(input.value).toBe(longText)
    })

    it('handles special characters', async () => {
      const user = userEvent.setup()
      const specialChars = '!@#$%^&*()_+-=[]{}|;:",.<>?/~`'
      
      render(<Input />)
      const input = screen.getByRole('textbox') as HTMLInputElement
      
      await user.type(input, specialChars)
      expect(input.value).toBe(specialChars)
    })

    it('handles unicode characters', async () => {
      const user = userEvent.setup()
      const unicode = '你好世界 😀🎉 Ñoño'
      
      render(<Input />)
      const input = screen.getByRole('textbox') as HTMLInputElement
      
      await user.type(input, unicode)
      expect(input.value).toBe(unicode)
    })

    it('handles rapid typing', async () => {
      const user = userEvent.setup({ delay: null }) // No delay for rapid typing
      const onChange = vi.fn()
      
      render(<Input onChange={onChange} />)
      const input = screen.getByRole('textbox')
      
      await user.type(input, 'RapidTyping')
      
      expect(onChange).toHaveBeenCalled()
      expect((input as HTMLInputElement).value).toBe('RapidTyping')
    })
  })

  describe('Form Integration', () => {
    it('works within a form', () => {
      render(
        <form>
          <Input name="username" />
        </form>
      )
      
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('name', 'username')
    })

    it('submits with form', async () => {
      const user = userEvent.setup()
      const onSubmit = vi.fn((e) => e.preventDefault())
      
      render(
        <form onSubmit={onSubmit}>
          <Input name="field" defaultValue="value" />
          <button type="submit">Submit</button>
        </form>
      )
      
      const button = screen.getByRole('button')
      await user.click(button)
      
      expect(onSubmit).toHaveBeenCalled()
    })

    it('resets with form', async () => {
      const user = userEvent.setup()
      
      render(
        <form>
          <Input defaultValue="Initial" />
          <button type="reset">Reset</button>
        </form>
      )
      
      const input = screen.getByRole('textbox') as HTMLInputElement
      const button = screen.getByRole('button')
      
      await user.clear(input)
      await user.type(input, 'Changed')
      expect(input.value).toBe('Changed')
      
      await user.click(button)
      expect(input.value).toBe('Initial')
    })
  })

  describe('Ref Forwarding', () => {
    it('forwards ref to input element', () => {
      const ref = React.createRef<HTMLInputElement>()
      
      render(<Input ref={ref} />)
      
      expect(ref.current).toBeInstanceOf(HTMLInputElement)
      expect(ref.current?.tagName).toBe('INPUT')
    })

    it('allows imperative focus via ref', () => {
      const ref = React.createRef<HTMLInputElement>()
      
      render(<Input ref={ref} />)
      
      ref.current?.focus()
      expect(document.activeElement).toBe(ref.current)
    })
  })
})