import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuCheckboxItem,
  DropdownMenuRadioItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuGroup,
  DropdownMenuPortal,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuRadioGroup,
} from '../dropdown-menu'

describe('DropdownMenu Component', () => {
  describe('Basic Rendering', () => {
    it('renders dropdown menu with trigger', () => {
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Open Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Item 1</DropdownMenuItem>
            <DropdownMenuItem>Item 2</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      expect(screen.getByRole('button', { name: 'Open Menu' })).toBeInTheDocument()
    })

    it('opens menu when trigger is clicked', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Open Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Item 1</DropdownMenuItem>
            <DropdownMenuItem>Item 2</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      const trigger = screen.getByRole('button', { name: 'Open Menu' })
      await user.click(trigger)

      await waitFor(() => {
        expect(screen.getByRole('menu')).toBeInTheDocument()
        expect(screen.getByRole('menuitem', { name: 'Item 1' })).toBeInTheDocument()
        expect(screen.getByRole('menuitem', { name: 'Item 2' })).toBeInTheDocument()
      })
    })

    it('closes menu when item is clicked', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Open Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Click me</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Open Menu' }))
      
      const item = await screen.findByRole('menuitem', { name: 'Click me' })
      await user.click(item)

      await waitFor(() => {
        expect(screen.queryByRole('menu')).not.toBeInTheDocument()
      })
    })

    it('closes menu when Escape is pressed', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Open Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Item</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Open Menu' }))
      
      await waitFor(() => {
        expect(screen.getByRole('menu')).toBeInTheDocument()
      })

      await user.keyboard('{Escape}')

      await waitFor(() => {
        expect(screen.queryByRole('menu')).not.toBeInTheDocument()
      })
    })
  })

  describe('Menu Items', () => {
    it('handles click events on menu items', async () => {
      const user = userEvent.setup()
      const handleClick = vi.fn()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem onSelect={handleClick}>Action Item</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      const item = await screen.findByRole('menuitem', { name: 'Action Item' })
      await user.click(item)

      expect(handleClick).toHaveBeenCalled()
    })

    it('renders disabled menu items', async () => {
      const user = userEvent.setup()
      const handleClick = vi.fn()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem disabled onSelect={handleClick}>
              Disabled Item
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      const item = await screen.findByRole('menuitem', { name: 'Disabled Item' })
      expect(item).toHaveAttribute('data-disabled')
      
      await user.click(item)
      expect(handleClick).not.toHaveBeenCalled()
    })

    it('renders menu item with shortcut', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>
              Save
              <DropdownMenuShortcut>⌘S</DropdownMenuShortcut>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      await waitFor(() => {
        expect(screen.getByText('Save')).toBeInTheDocument()
        expect(screen.getByText('⌘S')).toBeInTheDocument()
      })
    })

    it('prevents default on disabled items', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem disabled>Disabled</DropdownMenuItem>
            <DropdownMenuItem>Enabled</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      const disabledItem = await screen.findByRole('menuitem', { name: 'Disabled' })
      await user.click(disabledItem)
      
      // Menu should still be open
      expect(screen.getByRole('menu')).toBeInTheDocument()
    })
  })

  describe('Checkbox Items', () => {
    it('toggles checkbox items', async () => {
      const user = userEvent.setup()
      const onCheckedChange = vi.fn()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuCheckboxItem
              checked={false}
              onCheckedChange={onCheckedChange}
            >
              Toggle Option
            </DropdownMenuCheckboxItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      const checkbox = await screen.findByRole('menuitemcheckbox', { name: 'Toggle Option' })
      await user.click(checkbox)

      expect(onCheckedChange).toHaveBeenCalledWith(true)
    })

    it('displays checked state', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuCheckboxItem checked={true}>
              Checked Option
            </DropdownMenuCheckboxItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      const checkbox = await screen.findByRole('menuitemcheckbox', { name: 'Checked Option' })
      expect(checkbox).toHaveAttribute('aria-checked', 'true')
    })

    it('handles controlled checkbox state', async () => {
      const user = userEvent.setup()
      
      const TestComponent = () => {
        const [checked, setChecked] = React.useState(false)
        
        return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button>Menu</button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuCheckboxItem
                checked={checked}
                onCheckedChange={setChecked}
              >
                Option: {checked ? 'On' : 'Off'}
              </DropdownMenuCheckboxItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )
      }

      render(<TestComponent />)

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      const checkbox = await screen.findByRole('menuitemcheckbox')
      expect(checkbox).toHaveTextContent('Option: Off')
      
      await user.click(checkbox)
      
      await user.click(screen.getByRole('button', { name: 'Menu' }))
      const updatedCheckbox = await screen.findByRole('menuitemcheckbox')
      expect(updatedCheckbox).toHaveTextContent('Option: On')
    })
  })

  describe('Radio Items', () => {
    it('selects radio items', async () => {
      const user = userEvent.setup()
      const onValueChange = vi.fn()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuRadioGroup value="option1" onValueChange={onValueChange}>
              <DropdownMenuRadioItem value="option1">Option 1</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="option2">Option 2</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="option3">Option 3</DropdownMenuRadioItem>
            </DropdownMenuRadioGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      const option2 = await screen.findByRole('menuitemradio', { name: 'Option 2' })
      await user.click(option2)

      expect(onValueChange).toHaveBeenCalledWith('option2')
    })

    it('displays selected radio state', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuRadioGroup value="option2">
              <DropdownMenuRadioItem value="option1">Option 1</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="option2">Option 2</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="option3">Option 3</DropdownMenuRadioItem>
            </DropdownMenuRadioGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      const option2 = await screen.findByRole('menuitemradio', { name: 'Option 2' })
      expect(option2).toHaveAttribute('aria-checked', 'true')
      
      const option1 = await screen.findByRole('menuitemradio', { name: 'Option 1' })
      expect(option1).toHaveAttribute('aria-checked', 'false')
    })
  })

  describe('Menu Structure', () => {
    it('renders menu with labels and separators', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuLabel>Actions</DropdownMenuLabel>
            <DropdownMenuItem>New File</DropdownMenuItem>
            <DropdownMenuItem>Open</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuLabel>Edit</DropdownMenuLabel>
            <DropdownMenuItem>Cut</DropdownMenuItem>
            <DropdownMenuItem>Copy</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      await waitFor(() => {
        expect(screen.getByText('Actions')).toBeInTheDocument()
        expect(screen.getByText('Edit')).toBeInTheDocument()
        expect(screen.getByRole('menuitem', { name: 'New File' })).toBeInTheDocument()
        expect(screen.getByRole('menuitem', { name: 'Cut' })).toBeInTheDocument()
      })
    })

    it('renders menu groups', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuGroup>
              <DropdownMenuItem>Profile</DropdownMenuItem>
              <DropdownMenuItem>Settings</DropdownMenuItem>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem>Help</DropdownMenuItem>
              <DropdownMenuItem>About</DropdownMenuItem>
            </DropdownMenuGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      await waitFor(() => {
        expect(screen.getByRole('menuitem', { name: 'Profile' })).toBeInTheDocument()
        expect(screen.getByRole('menuitem', { name: 'Settings' })).toBeInTheDocument()
        expect(screen.getByRole('menuitem', { name: 'Help' })).toBeInTheDocument()
        expect(screen.getByRole('menuitem', { name: 'About' })).toBeInTheDocument()
      })
    })
  })

  describe('Submenu', () => {
    it('renders submenu', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Item 1</DropdownMenuItem>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>More Options</DropdownMenuSubTrigger>
              <DropdownMenuPortal>
                <DropdownMenuSubContent>
                  <DropdownMenuItem>Sub Item 1</DropdownMenuItem>
                  <DropdownMenuItem>Sub Item 2</DropdownMenuItem>
                </DropdownMenuSubContent>
              </DropdownMenuPortal>
            </DropdownMenuSub>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      const subTrigger = await screen.findByRole('menuitem', { name: 'More Options' })
      await user.hover(subTrigger)

      await waitFor(() => {
        expect(screen.getByRole('menuitem', { name: 'Sub Item 1' })).toBeInTheDocument()
        expect(screen.getByRole('menuitem', { name: 'Sub Item 2' })).toBeInTheDocument()
      })
    })

    it('closes submenu when item is selected', async () => {
      const user = userEvent.setup()
      const onSelect = vi.fn()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>Submenu</DropdownMenuSubTrigger>
              <DropdownMenuPortal>
                <DropdownMenuSubContent>
                  <DropdownMenuItem onSelect={onSelect}>Sub Action</DropdownMenuItem>
                </DropdownMenuSubContent>
              </DropdownMenuPortal>
            </DropdownMenuSub>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      const subTrigger = await screen.findByRole('menuitem', { name: 'Submenu' })
      await user.hover(subTrigger)

      const subItem = await screen.findByRole('menuitem', { name: 'Sub Action' })
      
      // Use fireEvent instead of user.click for more reliable submenu interaction
      fireEvent.click(subItem)

      await waitFor(() => {
        expect(onSelect).toHaveBeenCalled()
      })
      
      await waitFor(() => {
        expect(screen.queryByRole('menu')).not.toBeInTheDocument()
      })
    })
  })

  describe('Keyboard Navigation', () => {
    it('navigates with arrow keys', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Item 1</DropdownMenuItem>
            <DropdownMenuItem>Item 2</DropdownMenuItem>
            <DropdownMenuItem>Item 3</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      await waitFor(() => {
        expect(screen.getByRole('menu')).toBeInTheDocument()
      })

      await user.keyboard('{ArrowDown}')
      await user.keyboard('{ArrowDown}')
      await user.keyboard('{Enter}')

      // Menu should close after selection
      await waitFor(() => {
        expect(screen.queryByRole('menu')).not.toBeInTheDocument()
      })
    })

    it('opens with Enter key', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Item</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      const trigger = screen.getByRole('button', { name: 'Menu' })
      trigger.focus()
      await user.keyboard('{Enter}')

      await waitFor(() => {
        expect(screen.getByRole('menu')).toBeInTheDocument()
      })
    })
  })

  describe('Styling', () => {
    it('applies custom className to components', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="custom-content">
            <DropdownMenuItem className="custom-item">Item</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      await waitFor(() => {
        const content = screen.getByRole('menu')
        expect(content).toHaveClass('custom-content')
        
        const item = screen.getByRole('menuitem', { name: 'Item' })
        expect(item).toHaveClass('custom-item')
      })
    })

    it('applies default styles', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Item</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      await waitFor(() => {
        const content = screen.getByRole('menu')
        expect(content.className).toContain('z-50')
        expect(content.className).toContain('rounded-md')
        expect(content.className).toContain('border')
      })
    })
  })

  describe('Accessibility', () => {
    it('has proper ARIA attributes', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Item</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      const trigger = screen.getByRole('button', { name: 'Menu' })
      expect(trigger).toHaveAttribute('aria-haspopup', 'menu')
      
      await user.click(trigger)
      
      await waitFor(() => {
        expect(trigger).toHaveAttribute('aria-expanded', 'true')
        const menu = screen.getByRole('menu')
        expect(menu).toBeInTheDocument()
      })
    })

    it('supports keyboard shortcuts display', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>
              Copy
              <DropdownMenuShortcut>⌘C</DropdownMenuShortcut>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Menu' }))
      
      const shortcut = await screen.findByText('⌘C')
      expect(shortcut).toHaveClass('ml-auto')
      expect(shortcut).toHaveClass('text-xs')
    })
  })

  describe('Edge Cases', () => {
    it('handles empty menu', async () => {
      const user = userEvent.setup()
      
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Empty Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent />
        </DropdownMenu>
      )

      await user.click(screen.getByRole('button', { name: 'Empty Menu' }))
      
      await waitFor(() => {
        const menu = screen.getByRole('menu')
        expect(menu).toBeInTheDocument()
        expect(menu).toBeEmptyDOMElement()
      })
    })

    it('handles rapid open/close', async () => {
      render(
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button>Menu</button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Item</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )

      const trigger = screen.getByRole('button', { name: 'Menu' })
      
      // Use fireEvent for rapid clicking to avoid pointer-events issues
      // Just verify that rapid clicking doesn't crash the component
      expect(() => {
        fireEvent.click(trigger)
        fireEvent.click(trigger)
        fireEvent.click(trigger)
      }).not.toThrow()

      // Verify the component can still be interacted with normally
      const user = userEvent.setup()
      await user.click(trigger)
      
      await waitFor(() => {
        expect(screen.getByRole('menu')).toBeInTheDocument()
      })
    })
  })
})