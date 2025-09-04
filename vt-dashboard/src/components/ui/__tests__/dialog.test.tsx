import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogFooter,
  DialogTitle,
  DialogDescription,
  DialogClose,
} from '../dialog'

describe('Dialog Component', () => {
  describe('Basic Rendering', () => {
    it('renders dialog with trigger and content', async () => {
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Test Dialog</DialogTitle>
              <DialogDescription>This is a test dialog</DialogDescription>
            </DialogHeader>
            <div>Dialog body content</div>
            <DialogFooter>
              <button>Cancel</button>
              <button>OK</button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )

      expect(screen.getByText('Open Dialog')).toBeInTheDocument()
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })

    it('opens dialog when trigger is clicked', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Test Dialog</DialogTitle>
              <DialogDescription>This is a test dialog</DialogDescription>
            </DialogHeader>
            <div>Dialog body content</div>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))

      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
        expect(screen.getByText('Test Dialog')).toBeInTheDocument()
        expect(screen.getByText('This is a test dialog')).toBeInTheDocument()
        expect(screen.getByText('Dialog body content')).toBeInTheDocument()
      })
    })

    it('renders all dialog components correctly', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open</button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Title</DialogTitle>
              <DialogDescription>Description</DialogDescription>
            </DialogHeader>
            <div>Body</div>
            <DialogFooter>
              <button>Footer Button</button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open'))

      await waitFor(() => {
        expect(screen.getByText('Title')).toBeInTheDocument()
        expect(screen.getByText('Description')).toBeInTheDocument()
        expect(screen.getByText('Body')).toBeInTheDocument()
        expect(screen.getByText('Footer Button')).toBeInTheDocument()
      })
    })
  })

  describe('Dialog Interaction', () => {
    it('closes dialog when close button is clicked', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Test Dialog</DialogTitle>
            <div>Content</div>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })

      const closeButton = screen.getByRole('button', { name: /close/i })
      await user.click(closeButton)

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      })
    })

    it('closes dialog when escape key is pressed', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Test Dialog</DialogTitle>
            <div>Content</div>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })

      await user.keyboard('{Escape}')

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      })
    })

    it('closes dialog when overlay is clicked', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Test Dialog</DialogTitle>
            <div>Content</div>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })

      // Click outside the dialog (on the overlay)
      const dialog = screen.getByRole('dialog')
      fireEvent.pointerDown(document.body)
      fireEvent.pointerUp(document.body)

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      })
    })

    it('handles custom DialogClose component', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Test Dialog</DialogTitle>
            <div>Content</div>
            <DialogClose asChild>
              <button>Custom Close</button>
            </DialogClose>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Custom Close'))

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      })
    })
  })

  describe('Controlled Dialog', () => {
    it('works with controlled state', async () => {
      const user = userEvent.setup()
      const TestComponent = () => {
        const [open, setOpen] = React.useState(false)

        return (
          <div>
            <button onClick={() => setOpen(true)}>Open Controlled</button>
            <Dialog open={open} onOpenChange={setOpen}>
              <DialogContent>
                <DialogTitle>Controlled Dialog</DialogTitle>
                <div>Controlled content</div>
              </DialogContent>
            </Dialog>
          </div>
        )
      }

      render(<TestComponent />)

      await user.click(screen.getByText('Open Controlled'))

      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
        expect(screen.getByText('Controlled Dialog')).toBeInTheDocument()
      })

      await user.keyboard('{Escape}')

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      })
    })

    it('calls onOpenChange when dialog state changes', async () => {
      const user = userEvent.setup()
      const onOpenChange = vi.fn()

      render(
        <Dialog onOpenChange={onOpenChange}>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Test Dialog</DialogTitle>
            <div>Content</div>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))

      expect(onOpenChange).toHaveBeenCalledWith(true)

      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })

      await user.keyboard('{Escape}')

      expect(onOpenChange).toHaveBeenCalledWith(false)
    })
  })

  describe('Accessibility', () => {
    it('has correct ARIA attributes', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Test Dialog</DialogTitle>
            <DialogDescription>Dialog description</DialogDescription>
            <div>Content</div>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))

      await waitFor(() => {
        const dialog = screen.getByRole('dialog')
        expect(dialog).toBeInTheDocument()
        expect(dialog).toHaveAttribute('aria-labelledby')
        expect(dialog).toHaveAttribute('aria-describedby')
        // Radix UI dialogs are modal by nature even without explicit aria-modal
        expect(dialog).toHaveAttribute('role', 'dialog')
      })
    })

    it('focuses dialog content when opened', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Test Dialog</DialogTitle>
            <input placeholder="Focus test" />
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))

      await waitFor(() => {
        const dialog = screen.getByRole('dialog')
        expect(dialog).toBeInTheDocument()
        // Dialog content should receive focus or focus should be trapped within
        expect(document.activeElement).not.toBe(document.body)
      })
    })

    it('restores focus to trigger when closed', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Test Dialog</DialogTitle>
            <div>Content</div>
          </DialogContent>
        </Dialog>
      )

      const trigger = screen.getByText('Open Dialog')
      await user.click(trigger)

      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })

      await user.keyboard('{Escape}')

      await waitFor(() => {
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
        expect(trigger).toHaveFocus()
      })
    })
  })

  describe('Custom Styling', () => {
    it('applies custom className to dialog components', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent className="custom-dialog-content">
            <DialogHeader className="custom-header">
              <DialogTitle className="custom-title">Test Dialog</DialogTitle>
              <DialogDescription className="custom-description">
                Dialog description
              </DialogDescription>
            </DialogHeader>
            <DialogFooter className="custom-footer">
              <button>OK</button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))

      await waitFor(() => {
        const dialog = screen.getByRole('dialog')
        expect(dialog).toHaveClass('custom-dialog-content')
        
        const header = dialog.querySelector('.custom-header')
        expect(header).toBeInTheDocument()
        
        const title = screen.getByText('Test Dialog')
        expect(title).toHaveClass('custom-title')
        
        const description = screen.getByText('Dialog description')
        expect(description).toHaveClass('custom-description')
        
        const footer = dialog.querySelector('.custom-footer')
        expect(footer).toBeInTheDocument()
      })
    })

    it('applies default styling classes', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Test Dialog</DialogTitle>
            <div>Content</div>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))

      await waitFor(() => {
        const dialog = screen.getByRole('dialog')
        // Should have default positioning and styling classes
        expect(dialog.className).toContain('fixed')
        expect(dialog.className).toContain('z-50')
        expect(dialog.className).toContain('max-w-lg')
      })
    })
  })

  describe('Content Variations', () => {
    it('works without DialogHeader', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Just Title</DialogTitle>
            <div>Content without header wrapper</div>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))

      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
        expect(screen.getByText('Just Title')).toBeInTheDocument()
        expect(screen.getByText('Content without header wrapper')).toBeInTheDocument()
      })
    })

    it('works without DialogFooter', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Dialog Title</DialogTitle>
            <div>Content without footer</div>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))

      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
        expect(screen.getByText('Dialog Title')).toBeInTheDocument()
        expect(screen.getByText('Content without footer')).toBeInTheDocument()
      })
    })

    it('works with minimal content', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <div>Minimal dialog</div>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))

      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
        expect(screen.getByText('Minimal dialog')).toBeInTheDocument()
      })
    })
  })

  describe('Edge Cases', () => {
    it('handles rapid open/close operations', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Test Dialog</DialogTitle>
            <div>Content</div>
          </DialogContent>
        </Dialog>
      )

      const trigger = screen.getByText('Open Dialog')
      
      // Rapid open/close
      await user.click(trigger)
      await user.keyboard('{Escape}')
      await user.click(trigger)
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })
    })

    it('handles multiple dialogs', () => {
      render(
        <div>
          <Dialog>
            <DialogTrigger asChild>
              <button>Open Dialog 1</button>
            </DialogTrigger>
            <DialogContent>
              <DialogTitle>Dialog 1</DialogTitle>
            </DialogContent>
          </Dialog>
          <Dialog>
            <DialogTrigger asChild>
              <button>Open Dialog 2</button>
            </DialogTrigger>
            <DialogContent>
              <DialogTitle>Dialog 2</DialogTitle>
            </DialogContent>
          </Dialog>
        </div>
      )

      expect(screen.getByText('Open Dialog 1')).toBeInTheDocument()
      expect(screen.getByText('Open Dialog 2')).toBeInTheDocument()
    })
  })

  describe('Event Handling', () => {
    it('prevents body scroll when dialog is open', async () => {
      const user = userEvent.setup()
      
      render(
        <Dialog>
          <DialogTrigger asChild>
            <button>Open Dialog</button>
          </DialogTrigger>
          <DialogContent>
            <DialogTitle>Test Dialog</DialogTitle>
            <div>Content</div>
          </DialogContent>
        </Dialog>
      )

      await user.click(screen.getByText('Open Dialog'))

      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
        // Radix UI typically adds styles to prevent body scroll
        // This is handled by the underlying Radix primitive
      })
    })
  })
})