import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  Select,
  SelectTrigger,
  SelectContent,
  SelectItem,
  SelectValue,
  SelectGroup,
  SelectLabel,
  SelectSeparator,
} from '../select'

describe('Select Component', () => {
  describe('Basic Rendering', () => {
    it('renders select with trigger and items', () => {
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select an option" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
            <SelectItem value="option2">Option 2</SelectItem>
            <SelectItem value="option3">Option 3</SelectItem>
          </SelectContent>
        </Select>
      )

      expect(screen.getByRole('combobox')).toBeInTheDocument()
      expect(screen.getByText('Select an option')).toBeInTheDocument()
    })

    it('displays placeholder text when no value is selected', () => {
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Choose..." />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="test">Test</SelectItem>
          </SelectContent>
        </Select>
      )

      expect(screen.getByText('Choose...')).toBeInTheDocument()
    })

    it('opens dropdown when trigger is clicked', async () => {
      const user = userEvent.setup()
      
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
            <SelectItem value="option2">Option 2</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      await waitFor(() => {
        expect(screen.getByRole('option', { name: 'Option 1' })).toBeInTheDocument()
        expect(screen.getByRole('option', { name: 'Option 2' })).toBeInTheDocument()
      })
    })
  })

  describe('Selection Behavior', () => {
    it('selects an item when clicked', async () => {
      const user = userEvent.setup()
      const onValueChange = vi.fn()
      
      render(
        <Select onValueChange={onValueChange}>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
            <SelectItem value="option2">Option 2</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      await waitFor(() => {
        expect(screen.getByRole('option', { name: 'Option 1' })).toBeInTheDocument()
      })

      const option = screen.getByRole('option', { name: 'Option 1' })
      await user.click(option)

      expect(onValueChange).toHaveBeenCalledWith('option1')
    })

    it('displays selected value in trigger', async () => {
      const user = userEvent.setup()
      
      const TestComponent = () => {
        const [value, setValue] = React.useState('')
        return (
          <Select value={value} onValueChange={setValue}>
            <SelectTrigger>
              <SelectValue placeholder="Select" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="option1">Option 1</SelectItem>
              <SelectItem value="option2">Option 2</SelectItem>
            </SelectContent>
          </Select>
        )
      }

      render(<TestComponent />)

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      const option = screen.getByRole('option', { name: 'Option 2' })
      await user.click(option)

      await waitFor(() => {
        expect(screen.getByRole('combobox')).toHaveTextContent('Option 2')
      })
    })

    it('closes dropdown after selection', async () => {
      const user = userEvent.setup()
      
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      const option = screen.getByRole('option', { name: 'Option 1' })
      await user.click(option)

      await waitFor(() => {
        expect(screen.queryByRole('option')).not.toBeInTheDocument()
      })
    })
  })

  describe('Keyboard Navigation', () => {
    it('opens dropdown with Enter key', async () => {
      const user = userEvent.setup()
      
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      trigger.focus()
      await user.keyboard('{Enter}')

      await waitFor(() => {
        expect(screen.getByRole('option', { name: 'Option 1' })).toBeInTheDocument()
      })
    })

    it('opens dropdown with Space key', async () => {
      const user = userEvent.setup()
      
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      trigger.focus()
      await user.keyboard(' ')

      await waitFor(() => {
        expect(screen.getByRole('option', { name: 'Option 1' })).toBeInTheDocument()
      })
    })

    it('navigates options with arrow keys', async () => {
      const user = userEvent.setup()
      
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
            <SelectItem value="option2">Option 2</SelectItem>
            <SelectItem value="option3">Option 3</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      await waitFor(() => {
        expect(screen.getByRole('option', { name: 'Option 1' })).toBeInTheDocument()
      })

      await user.keyboard('{ArrowDown}')
      await user.keyboard('{ArrowDown}')
      await user.keyboard('{Enter}')

      await waitFor(() => {
        expect(trigger).toHaveTextContent('Option 3')
      })
    })

    it('closes dropdown with Escape key', async () => {
      const user = userEvent.setup()
      
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      await waitFor(() => {
        expect(screen.getByRole('option', { name: 'Option 1' })).toBeInTheDocument()
      })

      await user.keyboard('{Escape}')

      await waitFor(() => {
        expect(screen.queryByRole('option')).not.toBeInTheDocument()
      })
    })
  })

  describe('Select Groups', () => {
    it('renders grouped items correctly', async () => {
      const user = userEvent.setup()
      
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectLabel>Fruits</SelectLabel>
              <SelectItem value="apple">Apple</SelectItem>
              <SelectItem value="banana">Banana</SelectItem>
            </SelectGroup>
            <SelectSeparator />
            <SelectGroup>
              <SelectLabel>Vegetables</SelectLabel>
              <SelectItem value="carrot">Carrot</SelectItem>
              <SelectItem value="lettuce">Lettuce</SelectItem>
            </SelectGroup>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      await waitFor(() => {
        expect(screen.getByText('Fruits')).toBeInTheDocument()
        expect(screen.getByText('Vegetables')).toBeInTheDocument()
        expect(screen.getByRole('option', { name: 'Apple' })).toBeInTheDocument()
        expect(screen.getByRole('option', { name: 'Carrot' })).toBeInTheDocument()
      })
    })

    it('group labels are not selectable', async () => {
      const user = userEvent.setup()
      const onValueChange = vi.fn()
      
      render(
        <Select onValueChange={onValueChange}>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectLabel>Group Label</SelectLabel>
              <SelectItem value="item1">Item 1</SelectItem>
            </SelectGroup>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      const label = screen.getByText('Group Label')
      await user.click(label)

      expect(onValueChange).not.toHaveBeenCalled()
    })
  })

  describe('Disabled State', () => {
    it('disables the trigger when disabled prop is true', () => {
      render(
        <Select disabled>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      expect(trigger).toBeDisabled()
    })

    it('does not open when disabled', async () => {
      const user = userEvent.setup()
      
      render(
        <Select disabled>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      expect(screen.queryByRole('option')).not.toBeInTheDocument()
    })

    it('disables individual items', async () => {
      const user = userEvent.setup()
      const onValueChange = vi.fn()
      
      render(
        <Select onValueChange={onValueChange}>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
            <SelectItem value="option2" disabled>Option 2</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      const disabledOption = screen.getByRole('option', { name: 'Option 2' })
      expect(disabledOption).toHaveAttribute('aria-disabled', 'true')
      
      await user.click(disabledOption)
      expect(onValueChange).not.toHaveBeenCalled()
    })
  })

  describe('Controlled Component', () => {
    it('works as a controlled component', async () => {
      const user = userEvent.setup()
      
      const TestComponent = () => {
        const [value, setValue] = React.useState('option2')
        
        return (
          <div>
            <Select value={value} onValueChange={setValue}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="option1">Option 1</SelectItem>
                <SelectItem value="option2">Option 2</SelectItem>
                <SelectItem value="option3">Option 3</SelectItem>
              </SelectContent>
            </Select>
            <button onClick={() => setValue('option3')}>Set to Option 3</button>
          </div>
        )
      }

      render(<TestComponent />)

      expect(screen.getByRole('combobox')).toHaveTextContent('Option 2')

      const button = screen.getByText('Set to Option 3')
      await user.click(button)

      expect(screen.getByRole('combobox')).toHaveTextContent('Option 3')
    })

    it('calls onOpenChange when dropdown state changes', async () => {
      const user = userEvent.setup()
      const onOpenChange = vi.fn()
      
      render(
        <Select onOpenChange={onOpenChange}>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      expect(onOpenChange).toHaveBeenCalledWith(true)

      await user.keyboard('{Escape}')

      expect(onOpenChange).toHaveBeenCalledWith(false)
    })
  })

  describe('Custom Styling', () => {
    it('applies custom className to components', async () => {
      const user = userEvent.setup()
      
      render(
        <Select>
          <SelectTrigger className="custom-trigger">
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent className="custom-content">
            <SelectItem value="option1" className="custom-item">
              Option 1
            </SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      expect(trigger).toHaveClass('custom-trigger')

      await user.click(trigger)

      await waitFor(() => {
        const content = screen.getByRole('option', { name: 'Option 1' }).closest('[role="listbox"]')
        expect(content).toHaveClass('custom-content')
        
        const item = screen.getByRole('option', { name: 'Option 1' })
        expect(item).toHaveClass('custom-item')
      })
    })

    it('applies default styling classes', () => {
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      expect(trigger.className).toContain('flex')
      expect(trigger.className).toContain('h-10')
      expect(trigger.className).toContain('rounded-md')
      expect(trigger.className).toContain('border')
    })
  })

  describe('Accessibility', () => {
    it('has proper ARIA attributes', async () => {
      const user = userEvent.setup()
      
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select an option" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
            <SelectItem value="option2">Option 2</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      expect(trigger).toHaveAttribute('role', 'combobox')
      expect(trigger).toHaveAttribute('aria-expanded', 'false')

      await user.click(trigger)

      await waitFor(() => {
        expect(trigger).toHaveAttribute('aria-expanded', 'true')
        
        const listbox = screen.getByRole('listbox')
        expect(listbox).toBeInTheDocument()
        
        const options = screen.getAllByRole('option')
        expect(options).toHaveLength(2)
      })
    })

    it('supports aria-label on trigger', () => {
      render(
        <Select>
          <SelectTrigger aria-label="Choose a fruit">
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="apple">Apple</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox', { name: 'Choose a fruit' })
      expect(trigger).toBeInTheDocument()
    })

    it('indicates selected state on options', async () => {
      const user = userEvent.setup()
      
      render(
        <Select defaultValue="option2">
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
            <SelectItem value="option2">Option 2</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      await waitFor(() => {
        const selectedOption = screen.getByRole('option', { name: 'Option 2' })
        expect(selectedOption).toHaveAttribute('aria-selected', 'true')
        
        const unselectedOption = screen.getByRole('option', { name: 'Option 1' })
        expect(unselectedOption).toHaveAttribute('aria-selected', 'false')
      })
    })
  })

  describe('Edge Cases', () => {
    it('handles empty content gracefully', async () => {
      const user = userEvent.setup()
      
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent />
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      await waitFor(() => {
        const listbox = screen.getByRole('listbox')
        expect(listbox).toBeInTheDocument()
        // Check that there are no options in the listbox
        const options = screen.queryAllByRole('option')
        expect(options).toHaveLength(0)
      })
    })

    it('handles rapid open/close operations', async () => {
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="option1">Option 1</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      
      // Use fireEvent for rapid clicking to avoid pointer-events issues
      fireEvent.click(trigger)
      fireEvent.click(trigger)
      fireEvent.click(trigger)

      // Should be open after odd number of clicks
      await waitFor(() => {
        expect(screen.getByRole('option', { name: 'Option 1' })).toBeInTheDocument()
      })
    })

    it('handles very long option text', async () => {
      const user = userEvent.setup()
      const longText = 'This is a very long option text that might overflow the select dropdown width'
      
      render(
        <Select>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="long">{longText}</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      const option = screen.getByRole('option', { name: longText })
      await user.click(option)

      await waitFor(() => {
        expect(trigger).toHaveTextContent(longText)
      })
    })

    it('handles special characters in values', async () => {
      const user = userEvent.setup()
      const onValueChange = vi.fn()
      
      render(
        <Select onValueChange={onValueChange}>
          <SelectTrigger>
            <SelectValue placeholder="Select" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="special!@#$%^&*()">Special Characters</SelectItem>
            <SelectItem value="with spaces">With Spaces</SelectItem>
            <SelectItem value="unicode-😀">Unicode</SelectItem>
          </SelectContent>
        </Select>
      )

      const trigger = screen.getByRole('combobox')
      await user.click(trigger)

      const specialOption = screen.getByRole('option', { name: 'Special Characters' })
      await user.click(specialOption)

      expect(onValueChange).toHaveBeenCalledWith('special!@#$%^&*()')
    })
  })

  describe('Multiple Select Support', () => {
    it('renders multiple select components independently', async () => {
      const user = userEvent.setup()
      const onValueChange1 = vi.fn()
      const onValueChange2 = vi.fn()
      
      render(
        <div>
          <Select onValueChange={onValueChange1}>
            <SelectTrigger>
              <SelectValue placeholder="Select 1" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="a">A</SelectItem>
            </SelectContent>
          </Select>
          
          <Select onValueChange={onValueChange2}>
            <SelectTrigger>
              <SelectValue placeholder="Select 2" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="b">B</SelectItem>
            </SelectContent>
          </Select>
        </div>
      )

      const triggers = screen.getAllByRole('combobox')
      
      await user.click(triggers[0])
      const optionA = await screen.findByRole('option', { name: 'A' })
      await user.click(optionA)
      
      expect(onValueChange1).toHaveBeenCalledWith('a')
      expect(onValueChange2).not.toHaveBeenCalled()
    })
  })
})