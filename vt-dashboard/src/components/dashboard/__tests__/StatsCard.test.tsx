import { describe, it, expect } from 'vitest'
import { render, screen } from '@/test/utils/test-utils'
import { StatsCard } from '../StatsCard'
import { Shield, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'

describe('StatsCard Component', () => {
  const defaultProps = {
    title: 'Test Stat',
    value: 100,
    icon: Shield,
  }

  it('renders basic stats card with title, value, and icon', () => {
    render(<StatsCard {...defaultProps} />)
    
    expect(screen.getByText('Test Stat')).toBeInTheDocument()
    expect(screen.getByText('100')).toBeInTheDocument()
    // Icon should be rendered (though testing Lucide icons is tricky, we check if the component renders without error)
  })

  it('formats numeric values with locale formatting', () => {
    render(<StatsCard {...defaultProps} value={123456} />)
    
    expect(screen.getByText('123,456')).toBeInTheDocument()
  })

  it('displays string values without formatting', () => {
    render(<StatsCard {...defaultProps} value="Processing..." />)
    
    expect(screen.getByText('Processing...')).toBeInTheDocument()
  })

  it('renders with different variants and applies correct styling', () => {
    const { rerender } = render(<StatsCard {...defaultProps} variant="default" />)
    expect(screen.getByText('100')).toHaveClass('text-foreground')

    rerender(<StatsCard {...defaultProps} variant="success" />)
    expect(screen.getByText('100')).toHaveClass('text-green-600', 'dark:text-green-400')

    rerender(<StatsCard {...defaultProps} variant="warning" />)
    expect(screen.getByText('100')).toHaveClass('text-yellow-600', 'dark:text-yellow-400')

    rerender(<StatsCard {...defaultProps} variant="danger" />)
    expect(screen.getByText('100')).toHaveClass('text-red-600', 'dark:text-red-400')
  })

  it('displays increase change indicator', () => {
    render(
      <StatsCard 
        {...defaultProps} 
        change={{ value: 15.5, type: 'increase' }}
      />
    )
    
    const changeElement = screen.getByText('↗ 15.5%')
    expect(changeElement).toBeInTheDocument()
    expect(changeElement).toHaveClass('text-green-600', 'dark:text-green-400')
  })

  it('displays decrease change indicator', () => {
    render(
      <StatsCard 
        {...defaultProps} 
        change={{ value: -8.2, type: 'decrease' }}
      />
    )
    
    const changeElement = screen.getByText('↘ 8.2%')
    expect(changeElement).toBeInTheDocument()
    expect(changeElement).toHaveClass('text-red-600', 'dark:text-red-400')
  })

  it('displays description when provided', () => {
    render(
      <StatsCard 
        {...defaultProps} 
        description="from last month"
      />
    )
    
    expect(screen.getByText('from last month')).toBeInTheDocument()
    expect(screen.getByText('from last month')).toHaveClass('text-muted-foreground')
  })

  it('displays both change and description', () => {
    render(
      <StatsCard 
        {...defaultProps} 
        change={{ value: 12, type: 'increase' }}
        description="from last week"
      />
    )
    
    expect(screen.getByText('↗ 12%')).toBeInTheDocument()
    expect(screen.getByText('from last week')).toBeInTheDocument()
  })

  it('applies custom className', () => {
    render(
      <StatsCard 
        {...defaultProps} 
        className="custom-stats-card" 
        data-testid="stats-card"
      />
    )
    
    const card = screen.getByTestId('stats-card')
    expect(card).toHaveClass('custom-stats-card')
    expect(card).toHaveClass('transition-shadow', 'hover:shadow-md') // Should maintain default classes
  })

  describe('VirusTotal Dashboard Context', () => {
    it('renders malicious files stats', () => {
      render(
        <StatsCard
          title="Malicious Files"
          value={87}
          icon={XCircle}
          variant="danger"
          change={{ value: 5.2, type: 'increase' }}
          description="detected this week"
        />
      )
      
      expect(screen.getByText('Malicious Files')).toBeInTheDocument()
      expect(screen.getByText('87')).toBeInTheDocument()
      expect(screen.getByText('87')).toHaveClass('text-red-600')
      expect(screen.getByText('↗ 5.2%')).toBeInTheDocument()
      expect(screen.getByText('detected this week')).toBeInTheDocument()
    })

    it('renders clean files stats', () => {
      render(
        <StatsCard
          title="Clean Files"
          value={1245}
          icon={CheckCircle}
          variant="success"
          change={{ value: 2.1, type: 'decrease' }}
          description="scanned today"
        />
      )
      
      expect(screen.getByText('Clean Files')).toBeInTheDocument()
      expect(screen.getByText('1,245')).toBeInTheDocument()
      expect(screen.getByText('1,245')).toHaveClass('text-green-600')
      expect(screen.getByText('↘ 2.1%')).toBeInTheDocument()
    })

    it('renders suspicious files stats', () => {
      render(
        <StatsCard
          title="Suspicious Files"
          value={23}
          icon={AlertTriangle}
          variant="warning"
          description="require review"
        />
      )
      
      expect(screen.getByText('Suspicious Files')).toBeInTheDocument()
      expect(screen.getByText('23')).toBeInTheDocument()
      expect(screen.getByText('23')).toHaveClass('text-yellow-600')
      expect(screen.getByText('require review')).toBeInTheDocument()
    })

    it('renders total reports stats', () => {
      render(
        <StatsCard
          title="Total Reports"
          value={369}
          icon={Shield}
          variant="default"
          change={{ value: 8.5, type: 'increase' }}
          description="analyzed"
        />
      )
      
      expect(screen.getByText('Total Reports')).toBeInTheDocument()
      expect(screen.getByText('369')).toBeInTheDocument()
      expect(screen.getByText('↗ 8.5%')).toBeInTheDocument()
      expect(screen.getByText('analyzed')).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('maintains proper semantic structure', () => {
      render(
        <StatsCard
          title="Test Metric"
          value={42}
          icon={Shield}
          description="test description"
        />
      )
      
      // Title should be rendered as CardTitle (which uses h3)
      expect(screen.getByText('Test Metric')).toBeInTheDocument()
      expect(screen.getByText('42')).toBeInTheDocument()
      expect(screen.getByText('test description')).toBeInTheDocument()
    })

    it('provides meaningful content for screen readers', () => {
      render(
        <StatsCard
          title="Security Threats"
          value={15}
          icon={AlertTriangle}
          variant="danger"
          change={{ value: 3, type: 'increase' }}
          description="detected today"
        />
      )
      
      // The combination of title, value, change, and description should provide context
      expect(screen.getByText('Security Threats')).toBeInTheDocument()
      expect(screen.getByText('15')).toBeInTheDocument()
      expect(screen.getByText('↗ 3%')).toBeInTheDocument()
      expect(screen.getByText('detected today')).toBeInTheDocument()
    })

    it('supports custom ARIA attributes through Card props', () => {
      render(
        <StatsCard
          {...defaultProps}
          role="region"
          aria-label="Statistics summary"
          data-testid="accessible-card"
        />
      )
      
      const card = screen.getByTestId('accessible-card')
      expect(card).toHaveAttribute('role', 'region')
      expect(card).toHaveAttribute('aria-label', 'Statistics summary')
    })
  })

  describe('Responsive and Interactive Behavior', () => {
    it('has hover effects', () => {
      render(<StatsCard {...defaultProps} data-testid="hoverable-card" />)
      
      const card = screen.getByTestId('hoverable-card')
      expect(card).toHaveClass('transition-shadow', 'hover:shadow-md')
    })

    it('handles very large numbers', () => {
      render(<StatsCard {...defaultProps} value={1234567890} />)
      
      expect(screen.getByText('1,234,567,890')).toBeInTheDocument()
    })

    it('handles zero values', () => {
      render(<StatsCard {...defaultProps} value={0} />)
      
      expect(screen.getByText('0')).toBeInTheDocument()
    })

    it('handles negative change values correctly', () => {
      render(
        <StatsCard 
          {...defaultProps} 
          change={{ value: -25.7, type: 'decrease' }}
        />
      )
      
      // Should display absolute value
      expect(screen.getByText('↘ 25.7%')).toBeInTheDocument()
    })

    it('handles edge cases with empty or undefined values', () => {
      render(
        <StatsCard
          title=""
          value=""
          icon={Shield}
          description=""
        />
      )
      
      // Should render without crashing
      expect(screen.getByText('')).toBeInTheDocument()
    })
  })
})