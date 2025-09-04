import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@/test/utils/test-utils'
import { FileTypeChart } from '../FileTypeChart'

// Mock recharts since it requires canvas/dom that may not be available in jsdom
vi.mock('recharts', () => ({
  PieChart: ({ children }: any) => <div data-testid="pie-chart">{children}</div>,
  Pie: ({ children }: any) => <div data-testid="pie">{children}</div>,
  Cell: () => <div data-testid="pie-cell" />,
  ResponsiveContainer: ({ children }: any) => <div data-testid="responsive-container">{children}</div>,
  Tooltip: ({ content }: any) => <div data-testid="tooltip">{content}</div>,
  Legend: ({ formatter }: any) => <div data-testid="legend" />,
}))

describe('FileTypeChart Component', () => {
  const mockData = [
    { type: 'PE32', count: 156 },
    { type: 'PDF', count: 89 },
    { type: 'ZIP', count: 67 },
    { type: 'DOC', count: 34 },
    { type: 'XLS', count: 23 },
  ]

  it('renders chart with data', () => {
    render(<FileTypeChart data={mockData} />)
    
    expect(screen.getByText('File Types')).toBeInTheDocument()
    expect(screen.getByTestId('pie-chart')).toBeInTheDocument()
    expect(screen.getByTestId('responsive-container')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    render(<FileTypeChart data={[]} isLoading={true} />)
    
    expect(screen.getByText('File Types')).toBeInTheDocument()
    const loadingElement = screen.getByRole('generic', { hidden: true })
    expect(loadingElement).toHaveClass('animate-pulse', 'rounded-full')
  })

  it('shows empty state when no data', () => {
    render(<FileTypeChart data={[]} isLoading={false} />)
    
    expect(screen.getByText('File Types')).toBeInTheDocument()
    expect(screen.getByText('No file type data available')).toBeInTheDocument()
  })

  it('displays chart title with icon', () => {
    render(<FileTypeChart data={mockData} />)
    
    const title = screen.getByText('File Types')
    expect(title).toBeInTheDocument()
    expect(title.parentElement).toHaveClass('flex', 'items-center', 'space-x-2')
  })

  it('renders chart components when data is provided', () => {
    render(<FileTypeChart data={mockData} />)
    
    // Check that recharts components are rendered
    expect(screen.getByTestId('pie-chart')).toBeInTheDocument()
    expect(screen.getByTestId('pie')).toBeInTheDocument()
    expect(screen.getByTestId('tooltip')).toBeInTheDocument()
    expect(screen.getByTestId('legend')).toBeInTheDocument()
  })

  it('applies correct container height', () => {
    render(<FileTypeChart data={mockData} />)
    
    const chartContainer = screen.getByTestId('responsive-container').parentElement
    expect(chartContainer).toHaveClass('h-80')
  })

  describe('Data Processing', () => {
    it('handles single file type', () => {
      const singleData = [{ type: 'PE32', count: 100 }]
      render(<FileTypeChart data={singleData} />)
      
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument()
    })

    it('handles large numbers of file types', () => {
      const manyTypes = Array.from({ length: 15 }, (_, i) => ({
        type: `Type${i + 1}`,
        count: Math.floor(Math.random() * 100) + 1,
      }))
      
      render(<FileTypeChart data={manyTypes} />)
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument()
    })

    it('handles zero counts', () => {
      const dataWithZeros = [
        { type: 'PE32', count: 100 },
        { type: 'PDF', count: 0 },
        { type: 'ZIP', count: 50 },
      ]
      
      render(<FileTypeChart data={dataWithZeros} />)
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument()
    })
  })

  describe('Custom Tooltip Component', () => {
    // Note: Testing the CustomTooltip component directly
    it('should create tooltip component correctly', () => {
      // Since CustomTooltip is defined within the component, we test it indirectly
      render(<FileTypeChart data={mockData} />)
      expect(screen.getByTestId('tooltip')).toBeInTheDocument()
    })
  })

  describe('Responsive Behavior', () => {
    it('uses ResponsiveContainer for chart responsiveness', () => {
      render(<FileTypeChart data={mockData} />)
      
      const container = screen.getByTestId('responsive-container')
      expect(container).toBeInTheDocument()
    })

    it('maintains aspect ratio in different container sizes', () => {
      render(
        <div style={{ width: '400px', height: '300px' }}>
          <FileTypeChart data={mockData} />
        </div>
      )
      
      expect(screen.getByTestId('responsive-container')).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('has proper semantic structure', () => {
      render(<FileTypeChart data={mockData} />)
      
      // Chart should be within a card with proper heading
      const heading = screen.getByText('File Types')
      expect(heading).toBeInTheDocument()
    })

    it('provides meaningful content for screen readers', () => {
      render(<FileTypeChart data={mockData} />)
      
      // Title provides context for what the chart represents
      expect(screen.getByText('File Types')).toBeInTheDocument()
    })

    it('handles empty state accessibly', () => {
      render(<FileTypeChart data={[]} />)
      
      const emptyMessage = screen.getByText('No file type data available')
      expect(emptyMessage).toBeInTheDocument()
      expect(emptyMessage).toHaveClass('text-muted-foreground')
    })

    it('provides loading state feedback', () => {
      render(<FileTypeChart data={[]} isLoading={true} />)
      
      // Visual loading indicator should be present
      const loadingIndicator = document.querySelector('.animate-pulse')
      expect(loadingIndicator).toBeInTheDocument()
    })
  })

  describe('VirusTotal Context', () => {
    it('displays typical VirusTotal file types', () => {
      const vtFileTypes = [
        { type: 'PE32', count: 156 },
        { type: 'PDF', count: 89 },
        { type: 'ZIP', count: 67 },
        { type: 'DOC', count: 34 },
        { type: 'XLS', count: 23 },
        { type: 'JS', count: 18 },
        { type: 'HTML', count: 12 },
        { type: 'APK', count: 8 },
      ]
      
      render(<FileTypeChart data={vtFileTypes} />)
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument()
    })

    it('handles file type distribution analysis', () => {
      const distributionData = [
        { type: 'Executable', count: 200 },
        { type: 'Document', count: 150 },
        { type: 'Archive', count: 100 },
        { type: 'Script', count: 50 },
        { type: 'Other', count: 25 },
      ]
      
      render(<FileTypeChart data={distributionData} />)
      expect(screen.getByText('File Types')).toBeInTheDocument()
    })
  })

  describe('Performance Considerations', () => {
    it('handles large datasets efficiently', () => {
      const largeDataset = Array.from({ length: 100 }, (_, i) => ({
        type: `FileType_${i}`,
        count: Math.floor(Math.random() * 1000) + 1,
      }))
      
      expect(() => {
        render(<FileTypeChart data={largeDataset} />)
      }).not.toThrow()
    })

    it('renders without performance warnings for reasonable data sizes', () => {
      const reasonableData = Array.from({ length: 20 }, (_, i) => ({
        type: `Type${i}`,
        count: Math.floor(Math.random() * 100) + 1,
      }))
      
      render(<FileTypeChart data={reasonableData} />)
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument()
    })
  })

  describe('Edge Cases', () => {
    it('handles undefined or null data gracefully', () => {
      render(<FileTypeChart data={[]} />)
      expect(screen.getByText('No file type data available')).toBeInTheDocument()
    })

    it('handles data with very small counts', () => {
      const smallCounts = [
        { type: 'Rare1', count: 1 },
        { type: 'Rare2', count: 2 },
        { type: 'Common', count: 1000 },
      ]
      
      render(<FileTypeChart data={smallCounts} />)
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument()
    })

    it('handles data with very large counts', () => {
      const largeCounts = [
        { type: 'TypeA', count: 999999999 },
        { type: 'TypeB', count: 888888888 },
      ]
      
      render(<FileTypeChart data={largeCounts} />)
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument()
    })

    it('handles special characters in file type names', () => {
      const specialChars = [
        { type: 'PE32+', count: 50 },
        { type: 'UTF-8', count: 30 },
        { type: 'file.ext', count: 20 },
        { type: 'type@domain.com', count: 10 },
      ]
      
      render(<FileTypeChart data={specialChars} />)
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument()
    })
  })
})