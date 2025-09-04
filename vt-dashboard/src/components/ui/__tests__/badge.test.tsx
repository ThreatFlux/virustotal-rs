import React from 'react'
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Badge, badgeVariants } from '../badge'

describe('Badge Component', () => {
  describe('Basic Rendering', () => {
    it('renders badge with text content', () => {
      render(<Badge>Test Badge</Badge>)
      expect(screen.getByText('Test Badge')).toBeInTheDocument()
    })

    it('renders badge with children elements', () => {
      render(
        <Badge>
          <span>Badge with</span>
          <strong>multiple elements</strong>
        </Badge>
      )
      expect(screen.getByText('Badge with')).toBeInTheDocument()
      expect(screen.getByText('multiple elements')).toBeInTheDocument()
    })

    it('renders as inline element', () => {
      render(<Badge>Inline Badge</Badge>)
      const badge = screen.getByText('Inline Badge')
      expect(badge.className).toContain('inline-flex')
    })
  })

  describe('Badge Variants', () => {
    it('renders default variant', () => {
      render(<Badge variant="default">Default</Badge>)
      const badge = screen.getByText('Default')
      expect(badge).toHaveClass('border-transparent')
      expect(badge).toHaveClass('bg-primary')
      expect(badge).toHaveClass('text-primary-foreground')
    })

    it('renders secondary variant', () => {
      render(<Badge variant="secondary">Secondary</Badge>)
      const badge = screen.getByText('Secondary')
      expect(badge).toHaveClass('border-transparent')
      expect(badge).toHaveClass('bg-secondary')
      expect(badge).toHaveClass('text-secondary-foreground')
    })

    it('renders destructive variant', () => {
      render(<Badge variant="destructive">Destructive</Badge>)
      const badge = screen.getByText('Destructive')
      expect(badge).toHaveClass('border-transparent')
      expect(badge).toHaveClass('bg-destructive')
      expect(badge).toHaveClass('text-destructive-foreground')
    })

    it('renders outline variant', () => {
      render(<Badge variant="outline">Outline</Badge>)
      const badge = screen.getByText('Outline')
      expect(badge).toHaveClass('text-foreground')
      expect(badge.className).not.toContain('bg-primary')
    })

    it('applies default variant when no variant specified', () => {
      render(<Badge>No Variant</Badge>)
      const badge = screen.getByText('No Variant')
      expect(badge).toHaveClass('bg-primary')
      expect(badge).toHaveClass('text-primary-foreground')
    })
  })

  describe('Custom Styling', () => {
    it('applies custom className', () => {
      render(<Badge className="custom-class">Custom</Badge>)
      const badge = screen.getByText('Custom')
      expect(badge).toHaveClass('custom-class')
    })

    it('merges custom className with default classes', () => {
      render(<Badge className="custom-class">Custom</Badge>)
      const badge = screen.getByText('Custom')
      expect(badge).toHaveClass('custom-class')
      expect(badge).toHaveClass('inline-flex')
      expect(badge).toHaveClass('items-center')
      expect(badge).toHaveClass('rounded-full')
    })

    it('applies base styling classes', () => {
      render(<Badge>Styled</Badge>)
      const badge = screen.getByText('Styled')
      expect(badge).toHaveClass('inline-flex')
      expect(badge).toHaveClass('items-center')
      expect(badge).toHaveClass('rounded-full')
      expect(badge).toHaveClass('border')
      expect(badge).toHaveClass('px-2.5')
      expect(badge).toHaveClass('py-0.5')
      expect(badge).toHaveClass('text-xs')
      expect(badge).toHaveClass('font-semibold')
    })

    it('supports style prop', () => {
      render(<Badge style={{ backgroundColor: 'red' }}>Styled</Badge>)
      const badge = screen.getByText('Styled')
      expect(badge).toHaveAttribute('style')
      expect(badge.getAttribute('style')).toContain('background-color: red')
    })
  })

  describe('Badge Content', () => {
    it('renders with numbers', () => {
      render(<Badge>123</Badge>)
      expect(screen.getByText('123')).toBeInTheDocument()
    })

    it('renders with special characters', () => {
      render(<Badge>!@#$%^&*()</Badge>)
      expect(screen.getByText('!@#$%^&*()')).toBeInTheDocument()
    })

    it('renders with emojis', () => {
      render(<Badge>🎉 Success</Badge>)
      expect(screen.getByText('🎉 Success')).toBeInTheDocument()
    })

    it('renders with long text', () => {
      const longText = 'This is a very long badge text that might overflow'
      render(<Badge>{longText}</Badge>)
      expect(screen.getByText(longText)).toBeInTheDocument()
    })

    it('renders empty badge', () => {
      const { container } = render(<Badge />)
      const badge = container.querySelector('div')
      expect(badge).toBeInTheDocument()
      expect(badge).toBeEmptyDOMElement()
    })
  })

  describe('Badge with Icons', () => {
    it('renders with leading icon', () => {
      render(
        <Badge>
          <svg className="w-3 h-3 mr-1" data-testid="icon" />
          <span>With Icon</span>
        </Badge>
      )
      expect(screen.getByTestId('icon')).toBeInTheDocument()
      expect(screen.getByText('With Icon')).toBeInTheDocument()
    })

    it('renders with trailing icon', () => {
      render(
        <Badge>
          <span>With Icon</span>
          <svg className="w-3 h-3 ml-1" data-testid="icon" />
        </Badge>
      )
      expect(screen.getByTestId('icon')).toBeInTheDocument()
      expect(screen.getByText('With Icon')).toBeInTheDocument()
    })
  })

  describe('Use Cases', () => {
    it('renders status badge', () => {
      render(<Badge variant="secondary">Active</Badge>)
      expect(screen.getByText('Active')).toBeInTheDocument()
    })

    it('renders count badge', () => {
      render(<Badge variant="destructive">99+</Badge>)
      expect(screen.getByText('99+')).toBeInTheDocument()
    })

    it('renders category badge', () => {
      render(<Badge variant="outline">Technology</Badge>)
      expect(screen.getByText('Technology')).toBeInTheDocument()
    })

    it('renders notification badge', () => {
      render(
        <Badge variant="destructive" className="absolute -top-2 -right-2">
          New
        </Badge>
      )
      const badge = screen.getByText('New')
      expect(badge).toHaveClass('absolute')
      expect(badge).toHaveClass('-top-2')
      expect(badge).toHaveClass('-right-2')
    })
  })

  describe('Badge Variants Function', () => {
    it('generates correct classes for default variant', () => {
      const classes = badgeVariants({ variant: 'default' })
      expect(classes).toContain('bg-primary')
      expect(classes).toContain('text-primary-foreground')
    })

    it('generates correct classes for secondary variant', () => {
      const classes = badgeVariants({ variant: 'secondary' })
      expect(classes).toContain('bg-secondary')
      expect(classes).toContain('text-secondary-foreground')
    })

    it('generates correct classes for destructive variant', () => {
      const classes = badgeVariants({ variant: 'destructive' })
      expect(classes).toContain('bg-destructive')
      expect(classes).toContain('text-destructive-foreground')
    })

    it('generates correct classes for outline variant', () => {
      const classes = badgeVariants({ variant: 'outline' })
      expect(classes).toContain('text-foreground')
      expect(classes).not.toContain('bg-primary')
    })

    it('includes base classes in all variants', () => {
      const variants = ['default', 'secondary', 'destructive', 'outline'] as const
      variants.forEach(variant => {
        const classes = badgeVariants({ variant })
        expect(classes).toContain('inline-flex')
        expect(classes).toContain('items-center')
        expect(classes).toContain('rounded-full')
        expect(classes).toContain('border')
      })
    })
  })

  describe('Accessibility', () => {
    it('can be referenced by aria-label', () => {
      render(<Badge aria-label="Status badge">Active</Badge>)
      const badge = screen.getByLabelText('Status badge')
      expect(badge).toBeInTheDocument()
    })

    it('supports role attribute', () => {
      render(<Badge role="status">Loading</Badge>)
      const badge = screen.getByRole('status')
      expect(badge).toBeInTheDocument()
    })

    it('supports aria-describedby', () => {
      render(
        <div>
          <Badge aria-describedby="badge-description">Info</Badge>
          <span id="badge-description">Additional information</span>
        </div>
      )
      const badge = screen.getByText('Info')
      expect(badge).toHaveAttribute('aria-describedby', 'badge-description')
    })
  })

  describe('Multiple Badges', () => {
    it('renders multiple badges correctly', () => {
      render(
        <div>
          <Badge variant="default">Badge 1</Badge>
          <Badge variant="secondary">Badge 2</Badge>
          <Badge variant="destructive">Badge 3</Badge>
          <Badge variant="outline">Badge 4</Badge>
        </div>
      )
      
      expect(screen.getByText('Badge 1')).toBeInTheDocument()
      expect(screen.getByText('Badge 2')).toBeInTheDocument()
      expect(screen.getByText('Badge 3')).toBeInTheDocument()
      expect(screen.getByText('Badge 4')).toBeInTheDocument()
    })

    it('maintains individual variants for multiple badges', () => {
      render(
        <div>
          <Badge variant="default">Default</Badge>
          <Badge variant="destructive">Destructive</Badge>
        </div>
      )
      
      const defaultBadge = screen.getByText('Default')
      const destructiveBadge = screen.getByText('Destructive')
      
      expect(defaultBadge).toHaveClass('bg-primary')
      expect(destructiveBadge).toHaveClass('bg-destructive')
    })
  })

  describe('Edge Cases', () => {
    it('handles undefined children gracefully', () => {
      render(<Badge>{undefined}</Badge>)
      const badges = document.querySelectorAll('[class*="inline-flex"]')
      expect(badges.length).toBeGreaterThan(0)
    })

    it('handles null children gracefully', () => {
      render(<Badge>{null}</Badge>)
      const badges = document.querySelectorAll('[class*="inline-flex"]')
      expect(badges.length).toBeGreaterThan(0)
    })

    it('handles conditional rendering', () => {
      const condition = false
      render(
        <Badge>
          {condition && <span>Hidden</span>}
          <span>Visible</span>
        </Badge>
      )
      
      expect(screen.queryByText('Hidden')).not.toBeInTheDocument()
      expect(screen.getByText('Visible')).toBeInTheDocument()
    })

    it('handles fragment children', () => {
      render(
        <Badge>
          <>
            <span>Part 1</span>
            <span>Part 2</span>
          </>
        </Badge>
      )
      
      expect(screen.getByText('Part 1')).toBeInTheDocument()
      expect(screen.getByText('Part 2')).toBeInTheDocument()
    })
  })
})