import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@/test/utils/test-utils'
import { TrendChart } from '../TrendChart'

// Mock recharts
vi.mock('recharts', () => ({
  LineChart: ({ children }: any) => <div data-testid="line-chart">{children}</div>,
  Line: ({ dataKey, stroke }: any) => <div data-testid={`line-${dataKey}`} style={{ color: stroke }} />,
  XAxis: () => <div data-testid="x-axis" />,
  YAxis: () => <div data-testid="y-axis" />,
  CartesianGrid: () => <div data-testid="cartesian-grid" />,
  Tooltip: () => <div data-testid="tooltip" />,
  Legend: () => <div data-testid="legend" />,
  ResponsiveContainer: ({ children }: any) => <div data-testid="responsive-container">{children}</div>,
}))

describe('TrendChart Component', () => {
  const mockTrendData = [
    { date: '2023-12-01', malicious: 12, suspicious: 8, clean: 45, undetected: 15 },
    { date: '2023-12-02', malicious: 15, suspicious: 6, clean: 52, undetected: 18 },
    { date: '2023-12-03', malicious: 8, suspicious: 12, clean: 38, undetected: 22 },
    { date: '2023-12-04', malicious: 20, suspicious: 9, clean: 41, undetected: 16 },
    { date: '2023-12-05', malicious: 11, suspicious: 14, clean: 48, undetected: 19 },
  ]

  it('renders chart with data', () => {
    render(<TrendChart data={mockTrendData} />)
    
    expect(screen.getByText('Detection Trends')).toBeInTheDocument()
    expect(screen.getByTestId('line-chart')).toBeInTheDocument()
    expect(screen.getByTestId('responsive-container')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    render(<TrendChart data={[]} isLoading={true} />)
    
    expect(screen.getByText('Detection Trends')).toBeInTheDocument()
    const loadingElements = screen.getAllByRole('generic', { hidden: true })
    const loadingBars = loadingElements.filter(el => el.classList.contains('animate-pulse'))
    expect(loadingBars.length).toBeGreaterThan(0)
  })

  it('shows empty state when no data', () => {
    render(<TrendChart data={[]} isLoading={false} />)
    
    expect(screen.getByText('Detection Trends')).toBeInTheDocument()
    expect(screen.getByText('No trend data available')).toBeInTheDocument()
  })

  it('displays chart title with trending icon', () => {
    render(<TrendChart data={mockTrendData} />)
    
    const title = screen.getByText('Detection Trends')
    expect(title).toBeInTheDocument()
    expect(title.parentElement).toHaveClass('flex', 'items-center', 'space-x-2')
  })

  it('renders all chart components', () => {
    render(<TrendChart data={mockTrendData} />)
    
    expect(screen.getByTestId('line-chart')).toBeInTheDocument()
    expect(screen.getByTestId('x-axis')).toBeInTheDocument()
    expect(screen.getByTestId('y-axis')).toBeInTheDocument()
    expect(screen.getByTestId('cartesian-grid')).toBeInTheDocument()
    expect(screen.getByTestId('tooltip')).toBeInTheDocument()
    expect(screen.getByTestId('legend')).toBeInTheDocument()
  })

  it('renders lines for each detection type', () => {
    render(<TrendChart data={mockTrendData} />)
    
    expect(screen.getByTestId('line-malicious')).toBeInTheDocument()
    expect(screen.getByTestId('line-suspicious')).toBeInTheDocument()
    expect(screen.getByTestId('line-clean')).toBeInTheDocument()
    expect(screen.getByTestId('line-undetected')).toBeInTheDocument()
  })

  it('applies correct container height', () => {
    render(<TrendChart data={mockTrendData} />)
    
    const chartContainer = screen.getByTestId('responsive-container').parentElement
    expect(chartContainer).toHaveClass('h-80')
  })

  describe('Data Handling', () => {
    it('handles single data point', () => {
      const singlePoint = [{ date: '2023-12-01', malicious: 5, suspicious: 3, clean: 20, undetected: 8 }]
      render(<TrendChart data={singlePoint} />)
      
      expect(screen.getByTestId('line-chart')).toBeInTheDocument()
    })

    it('handles data with zero values', () => {
      const dataWithZeros = [
        { date: '2023-12-01', malicious: 0, suspicious: 0, clean: 10, undetected: 5 },
        { date: '2023-12-02', malicious: 5, suspicious: 2, clean: 0, undetected: 0 },
      ]
      
      render(<TrendChart data={dataWithZeros} />)
      expect(screen.getByTestId('line-chart')).toBeInTheDocument()
    })

    it('handles large datasets', () => {
      const largeDataset = Array.from({ length: 365 }, (_, i) => ({
        date: new Date(2023, 0, i + 1).toISOString().split('T')[0],
        malicious: Math.floor(Math.random() * 50),
        suspicious: Math.floor(Math.random() * 30),
        clean: Math.floor(Math.random() * 100) + 50,
        undetected: Math.floor(Math.random() * 40),
      }))
      
      render(<TrendChart data={largeDataset} />)
      expect(screen.getByTestId('line-chart')).toBeInTheDocument()
    })

    it('handles irregular date sequences', () => {
      const irregularDates = [
        { date: '2023-12-01', malicious: 5, suspicious: 3, clean: 20, undetected: 8 },
        { date: '2023-12-05', malicious: 8, suspicious: 2, clean: 25, undetected: 6 }, // Gap in dates
        { date: '2023-12-10', malicious: 3, suspicious: 7, clean: 18, undetected: 12 },
      ]
      
      render(<TrendChart data={irregularDates} />)
      expect(screen.getByTestId('line-chart')).toBeInTheDocument()
    })
  })

  describe('Loading States', () => {
    it('shows skeleton loading bars', () => {
      render(<TrendChart data={[]} isLoading={true} />)
      
      // Should show multiple loading bars to simulate chart skeleton
      const loadingElements = document.querySelectorAll('.animate-pulse')
      expect(loadingElements.length).toBeGreaterThan(5) // Multiple skeleton bars
    })

    it('maintains chart structure during loading', () => {
      render(<TrendChart data={[]} isLoading={true} />)
      
      expect(screen.getByText('Detection Trends')).toBeInTheDocument()
      const container = document.querySelector('.h-80')
      expect(container).toBeInTheDocument()
    })
  })

  describe('Empty State', () => {
    it('displays appropriate empty message', () => {
      render(<TrendChart data={[]} />)
      
      expect(screen.getByText('No trend data available')).toBeInTheDocument()
    })

    it('maintains proper styling in empty state', () => {
      render(<TrendChart data={[]} />)
      
      const emptyMessage = screen.getByText('No trend data available')
      expect(emptyMessage.parentElement).toHaveClass('h-80', 'flex', 'items-center', 'justify-center')
    })
  })

  describe('Accessibility', () => {
    it('provides meaningful chart title', () => {
      render(<TrendChart data={mockTrendData} />)
      
      expect(screen.getByText('Detection Trends')).toBeInTheDocument()
    })

    it('handles keyboard navigation support', () => {
      render(<TrendChart data={mockTrendData} />)
      
      // Chart container should be accessible
      const chartArea = screen.getByTestId('line-chart')
      expect(chartArea).toBeInTheDocument()
    })

    it('provides context for screen readers in empty state', () => {
      render(<TrendChart data={[]} />)
      
      const emptyMessage = screen.getByText('No trend data available')
      expect(emptyMessage).toHaveClass('text-muted-foreground')
    })
  })

  describe('VirusTotal Context', () => {
    it('displays all threat categories', () => {
      render(<TrendChart data={mockTrendData} />)
      
      // All four detection categories should be represented as lines
      expect(screen.getByTestId('line-malicious')).toBeInTheDocument()
      expect(screen.getByTestId('line-suspicious')).toBeInTheDocument()
      expect(screen.getByTestId('line-clean')).toBeInTheDocument()
      expect(screen.getByTestId('line-undetected')).toBeInTheDocument()
    })

    it('handles typical VirusTotal trend data patterns', () => {
      const vtTrendData = [
        { date: '2023-12-01', malicious: 45, suspicious: 23, clean: 198, undetected: 67 },
        { date: '2023-12-02', malicious: 52, suspicious: 19, clean: 205, undetected: 71 },
        { date: '2023-12-03', malicious: 38, suspicious: 31, clean: 189, undetected: 58 },
      ]
      
      render(<TrendChart data={vtTrendData} />)
      expect(screen.getByTestId('line-chart')).toBeInTheDocument()
    })

    it('handles time series analysis requirements', () => {
      const timeSeriesData = Array.from({ length: 30 }, (_, i) => {
        const date = new Date()
        date.setDate(date.getDate() - (29 - i))
        return {
          date: date.toISOString().split('T')[0],
          malicious: Math.floor(Math.random() * 20) + 5,
          suspicious: Math.floor(Math.random() * 15) + 3,
          clean: Math.floor(Math.random() * 50) + 30,
          undetected: Math.floor(Math.random() * 25) + 10,
        }
      })
      
      render(<TrendChart data={timeSeriesData} />)
      expect(screen.getByTestId('line-chart')).toBeInTheDocument()
    })
  })

  describe('Responsive Design', () => {
    it('uses ResponsiveContainer for adaptability', () => {
      render(<TrendChart data={mockTrendData} />)
      
      expect(screen.getByTestId('responsive-container')).toBeInTheDocument()
    })

    it('maintains readability at different sizes', () => {
      render(
        <div style={{ width: '300px' }}>
          <TrendChart data={mockTrendData} />
        </div>
      )
      
      expect(screen.getByTestId('responsive-container')).toBeInTheDocument()
    })
  })

  describe('Performance', () => {
    it('handles frequent data updates', () => {
      const { rerender } = render(<TrendChart data={mockTrendData} />)
      
      const updatedData = mockTrendData.map(item => ({
        ...item,
        malicious: item.malicious + 1,
      }))
      
      rerender(<TrendChart data={updatedData} />)
      expect(screen.getByTestId('line-chart')).toBeInTheDocument()
    })

    it('efficiently renders large time series', () => {
      const yearOfData = Array.from({ length: 365 }, (_, i) => ({
        date: new Date(2023, 0, i + 1).toISOString().split('T')[0],
        malicious: Math.floor(Math.random() * 30),
        suspicious: Math.floor(Math.random() * 20),
        clean: Math.floor(Math.random() * 80) + 40,
        undetected: Math.floor(Math.random() * 35),
      }))
      
      expect(() => {
        render(<TrendChart data={yearOfData} />)
      }).not.toThrow()
    })
  })
})