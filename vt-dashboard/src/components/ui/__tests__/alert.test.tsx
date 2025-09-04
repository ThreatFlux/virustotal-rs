import React from 'react'
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Alert, AlertDescription, AlertTitle } from '../alert'

describe('Alert Component', () => {
  describe('Basic Rendering', () => {
    it('renders alert with content', () => {
      render(
        <Alert>
          <AlertTitle>Alert Title</AlertTitle>
          <AlertDescription>Alert description text</AlertDescription>
        </Alert>
      )

      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByText('Alert Title')).toBeInTheDocument()
      expect(screen.getByText('Alert description text')).toBeInTheDocument()
    })

    it('renders alert without title', () => {
      render(
        <Alert>
          <AlertDescription>Just a description</AlertDescription>
        </Alert>
      )

      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByText('Just a description')).toBeInTheDocument()
    })

    it('renders alert without description', () => {
      render(
        <Alert>
          <AlertTitle>Just a title</AlertTitle>
        </Alert>
      )

      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByText('Just a title')).toBeInTheDocument()
    })

    it('renders with only custom content', () => {
      render(
        <Alert>
          <div>Custom alert content</div>
          <button>Action</button>
        </Alert>
      )

      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByText('Custom alert content')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Action' })).toBeInTheDocument()
    })
  })

  describe('Alert Variants', () => {
    it('renders default variant', () => {
      render(
        <Alert>
          <AlertDescription>Default alert</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert')
      expect(alert).toHaveClass('bg-background')
      expect(alert).toHaveClass('text-foreground')
    })

    it('renders destructive variant', () => {
      render(
        <Alert variant="destructive">
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>Something went wrong</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert')
      expect(alert).toHaveClass('border-destructive/50')
      expect(alert).toHaveClass('text-destructive')
      expect(alert.querySelector('[class*="text-destructive"]')).toBeInTheDocument()
    })

    it('applies variant styles to icon', () => {
      render(
        <Alert variant="destructive">
          <AlertDescription>Destructive alert</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert')
      const icon = alert.querySelector('svg')
      if (icon) {
        expect(icon.parentElement).toHaveClass('text-destructive')
      }
    })
  })

  describe('Custom Styling', () => {
    it('applies custom className to Alert', () => {
      render(
        <Alert className="custom-alert-class">
          <AlertDescription>Custom styled alert</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert')
      expect(alert).toHaveClass('custom-alert-class')
    })

    it('applies custom className to AlertTitle', () => {
      render(
        <Alert>
          <AlertTitle className="custom-title-class">Custom Title</AlertTitle>
        </Alert>
      )

      const title = screen.getByText('Custom Title')
      expect(title).toHaveClass('custom-title-class')
    })

    it('applies custom className to AlertDescription', () => {
      render(
        <Alert>
          <AlertDescription className="custom-desc-class">
            Custom Description
          </AlertDescription>
        </Alert>
      )

      const description = screen.getByText('Custom Description')
      expect(description).toHaveClass('custom-desc-class')
    })

    it('maintains default classes with custom className', () => {
      render(
        <Alert className="custom-class">
          <AlertDescription>Alert content</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert')
      expect(alert).toHaveClass('custom-class')
      expect(alert).toHaveClass('relative')
      expect(alert).toHaveClass('rounded-lg')
      expect(alert).toHaveClass('border')
    })
  })

  describe('Alert Title Styling', () => {
    it('applies default title styles', () => {
      render(
        <Alert>
          <AlertTitle>Title Text</AlertTitle>
        </Alert>
      )

      const title = screen.getByText('Title Text')
      expect(title).toHaveClass('mb-1')
      expect(title).toHaveClass('font-medium')
      expect(title).toHaveClass('leading-none')
      expect(title).toHaveClass('tracking-tight')
    })

    it('renders as h5 element', () => {
      render(
        <Alert>
          <AlertTitle>Heading Title</AlertTitle>
        </Alert>
      )

      const title = screen.getByText('Heading Title')
      expect(title.tagName).toBe('H5')
    })
  })

  describe('Alert Description Styling', () => {
    it('applies default description styles', () => {
      render(
        <Alert>
          <AlertDescription>Description text</AlertDescription>
        </Alert>
      )

      const description = screen.getByText('Description text')
      expect(description).toHaveClass('text-sm')
      expect(description.className).toContain('leading-relaxed')
    })

    it('renders as div element with proper structure', () => {
      render(
        <Alert>
          <AlertDescription>Description content</AlertDescription>
        </Alert>
      )

      const description = screen.getByText('Description content')
      expect(description.tagName).toBe('DIV')
    })
  })

  describe('Complex Content', () => {
    it('renders multiple paragraphs in description', () => {
      render(
        <Alert>
          <AlertDescription>
            <p>First paragraph</p>
            <p>Second paragraph</p>
          </AlertDescription>
        </Alert>
      )

      expect(screen.getByText('First paragraph')).toBeInTheDocument()
      expect(screen.getByText('Second paragraph')).toBeInTheDocument()
    })

    it('renders lists in description', () => {
      render(
        <Alert>
          <AlertDescription>
            <ul>
              <li>Item 1</li>
              <li>Item 2</li>
              <li>Item 3</li>
            </ul>
          </AlertDescription>
        </Alert>
      )

      expect(screen.getByText('Item 1')).toBeInTheDocument()
      expect(screen.getByText('Item 2')).toBeInTheDocument()
      expect(screen.getByText('Item 3')).toBeInTheDocument()
    })

    it('renders links in alert content', () => {
      render(
        <Alert>
          <AlertDescription>
            Click <a href="/link">here</a> for more info
          </AlertDescription>
        </Alert>
      )

      const link = screen.getByRole('link', { name: 'here' })
      expect(link).toBeInTheDocument()
      expect(link).toHaveAttribute('href', '/link')
    })

    it('renders code blocks in description', () => {
      render(
        <Alert>
          <AlertDescription>
            Run <code>npm install</code> to continue
          </AlertDescription>
        </Alert>
      )

      const codeElement = screen.getByText('npm install')
      expect(codeElement.tagName).toBe('CODE')
    })
  })

  describe('Accessibility', () => {
    it('has role="alert" attribute', () => {
      render(
        <Alert>
          <AlertDescription>Accessible alert</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert')
      expect(alert).toBeInTheDocument()
    })

    it('supports aria-label', () => {
      render(
        <Alert aria-label="Important notification">
          <AlertDescription>Alert content</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert', { name: 'Important notification' })
      expect(alert).toBeInTheDocument()
    })

    it('supports aria-describedby', () => {
      render(
        <div>
          <Alert aria-describedby="help-text">
            <AlertDescription>Alert message</AlertDescription>
          </Alert>
          <div id="help-text">Additional help information</div>
        </div>
      )

      const alert = screen.getByRole('alert')
      expect(alert).toHaveAttribute('aria-describedby', 'help-text')
    })

    it('properly associates title and description', () => {
      render(
        <Alert>
          <AlertTitle>Warning Title</AlertTitle>
          <AlertDescription>Warning details here</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert')
      expect(alert).toContainElement(screen.getByText('Warning Title'))
      expect(alert).toContainElement(screen.getByText('Warning details here'))
    })
  })

  describe('Use Cases', () => {
    it('renders success alert', () => {
      render(
        <Alert className="border-green-500 text-green-600">
          <AlertTitle>Success!</AlertTitle>
          <AlertDescription>Your action was completed successfully.</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert')
      expect(alert).toHaveClass('border-green-500')
      expect(alert).toHaveClass('text-green-600')
    })

    it('renders warning alert', () => {
      render(
        <Alert className="border-yellow-500 text-yellow-600">
          <AlertTitle>Warning</AlertTitle>
          <AlertDescription>Please review before proceeding.</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert')
      expect(alert).toHaveClass('border-yellow-500')
      expect(alert).toHaveClass('text-yellow-600')
    })

    it('renders info alert', () => {
      render(
        <Alert className="border-blue-500 text-blue-600">
          <AlertTitle>Information</AlertTitle>
          <AlertDescription>Here is some helpful information.</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert')
      expect(alert).toHaveClass('border-blue-500')
      expect(alert).toHaveClass('text-blue-600')
    })

    it('renders error alert with details', () => {
      render(
        <Alert variant="destructive">
          <AlertTitle>Error occurred</AlertTitle>
          <AlertDescription>
            <p>Failed to save changes:</p>
            <ul>
              <li>Invalid email format</li>
              <li>Password too short</li>
            </ul>
          </AlertDescription>
        </Alert>
      )

      expect(screen.getByText('Error occurred')).toBeInTheDocument()
      expect(screen.getByText('Failed to save changes:')).toBeInTheDocument()
      expect(screen.getByText('Invalid email format')).toBeInTheDocument()
      expect(screen.getByText('Password too short')).toBeInTheDocument()
    })
  })

  describe('Edge Cases', () => {
    it('renders empty alert', () => {
      render(<Alert />)
      const alert = screen.getByRole('alert')
      expect(alert).toBeInTheDocument()
      expect(alert).toBeEmptyDOMElement()
    })

    it('renders with very long content', () => {
      const longText = 'Lorem ipsum '.repeat(100)
      
      render(
        <Alert>
          <AlertDescription>{longText}</AlertDescription>
        </Alert>
      )

      const alert = screen.getByRole('alert')
      expect(alert).toHaveTextContent(longText)
    })

    it('renders with special characters', () => {
      render(
        <Alert>
          <AlertTitle>Special: !@#$%^&*()</AlertTitle>
          <AlertDescription>Unicode: 你好 😀 Ñoño</AlertDescription>
        </Alert>
      )

      expect(screen.getByText('Special: !@#$%^&*()')).toBeInTheDocument()
      expect(screen.getByText('Unicode: 你好 😀 Ñoño')).toBeInTheDocument()
    })

    it('renders multiple alerts', () => {
      render(
        <div>
          <Alert>
            <AlertDescription>First alert</AlertDescription>
          </Alert>
          <Alert variant="destructive">
            <AlertDescription>Second alert</AlertDescription>
          </Alert>
          <Alert>
            <AlertDescription>Third alert</AlertDescription>
          </Alert>
        </div>
      )

      const alerts = screen.getAllByRole('alert')
      expect(alerts).toHaveLength(3)
      expect(screen.getByText('First alert')).toBeInTheDocument()
      expect(screen.getByText('Second alert')).toBeInTheDocument()
      expect(screen.getByText('Third alert')).toBeInTheDocument()
    })

    it('handles conditional rendering', () => {
      const TestComponent = ({ show }: { show: boolean }) => (
        <>
          {show && (
            <Alert>
              <AlertDescription>Conditional alert</AlertDescription>
            </Alert>
          )}
        </>
      )

      const { rerender } = render(<TestComponent show={false} />)
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()

      rerender(<TestComponent show={true} />)
      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByText('Conditional alert')).toBeInTheDocument()
    })
  })

  describe('Integration', () => {
    it('works with forms', () => {
      render(
        <form>
          <Alert>
            <AlertDescription>Please fill all required fields</AlertDescription>
          </Alert>
          <input type="text" />
          <button type="submit">Submit</button>
        </form>
      )

      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByRole('textbox')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument()
    })

    it('works in modals/dialogs', () => {
      render(
        <div role="dialog">
          <h2>Dialog Title</h2>
          <Alert variant="destructive">
            <AlertDescription>Error in dialog</AlertDescription>
          </Alert>
          <button>Close</button>
        </div>
      )

      const dialog = screen.getByRole('dialog')
      const alert = screen.getByRole('alert')
      expect(dialog).toContainElement(alert)
    })

    it('works with dynamic content updates', () => {
      const TestComponent = () => {
        const [message, setMessage] = React.useState('Initial message')
        
        return (
          <div>
            <Alert>
              <AlertDescription>{message}</AlertDescription>
            </Alert>
            <button onClick={() => setMessage('Updated message')}>
              Update
            </button>
          </div>
        )
      }

      render(<TestComponent />)
      
      expect(screen.getByText('Initial message')).toBeInTheDocument()
      
      const button = screen.getByRole('button', { name: 'Update' })
      button.click()
      
      expect(screen.getByText('Updated message')).toBeInTheDocument()
    })
  })
})