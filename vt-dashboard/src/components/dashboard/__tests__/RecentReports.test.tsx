import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import { RecentReports } from '../RecentReports'
import { Report } from '@/types'

// Mock react-router-dom
const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    Link: ({ children, to, className }: any) => (
      <a href={to} className={className} data-testid="link">
        {children}
      </a>
    )
  }
})

// Mock UI components
vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div data-testid="card">{children}</div>,
  CardContent: ({ children, className }: any) => <div className={className} data-testid="card-content">{children}</div>,
  CardHeader: ({ children, className }: any) => <div className={className} data-testid="card-header">{children}</div>,
  CardTitle: ({ children, className }: any) => <h3 className={className} data-testid="card-title">{children}</h3>
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children, variant, className }: any) => (
    <span data-testid="badge" data-variant={variant} className={className}>
      {children}
    </span>
  )
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, variant, size, asChild, ...props }: any) => 
    asChild ? <div data-testid="button-as-child" data-variant={variant} data-size={size}>{children}</div> 
    : <button data-testid="button" data-variant={variant} data-size={size} {...props}>{children}</button>
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children, className }: any) => <div className={className} data-testid="scroll-area">{children}</div>
}))

vi.mock('@/components/ui/table', () => ({
  Table: ({ children }: any) => <table data-testid="table">{children}</table>,
  TableBody: ({ children }: any) => <tbody data-testid="table-body">{children}</tbody>,
  TableCell: ({ children, colSpan, className }: any) => (
    <td data-testid="table-cell" colSpan={colSpan} className={className}>{children}</td>
  ),
  TableHead: ({ children, className }: any) => <th data-testid="table-head" className={className}>{children}</th>,
  TableHeader: ({ children }: any) => <thead data-testid="table-header">{children}</thead>,
  TableRow: ({ children, className }: any) => <tr data-testid="table-row" className={className}>{children}</tr>
}))

vi.mock('@/components/ui/occurrence-column', () => ({
  OccurrenceColumn: ({ report, variant, onSearchTrigger }: any) => (
    <div 
      data-testid="occurrence-column" 
      data-variant={variant} 
      onClick={() => onSearchTrigger({ report_id: report.report_uuid, type: 'test' })}
    >
      Occurrence Data
    </div>
  )
}))

// Mock utility functions
vi.mock('@/lib/utils', () => ({
  formatDate: (date: string) => `Formatted: ${date}`,
  formatBytes: (bytes: number) => `${bytes}B`,
  truncateHash: (hash: string, length: number) => hash.substring(0, length),
  getVerdictBadgeVariant: (verdict: string) => verdict === 'malicious' ? 'destructive' : 'secondary'
}))

// Mock lucide-react
vi.mock('lucide-react', () => ({
  FileText: (props: any) => <div data-testid="file-text-icon" {...props} />,
  ExternalLink: (props: any) => <div data-testid="external-link-icon" {...props} />
}))

// Helper to render component with router
const renderWithRouter = (component: React.ReactElement) => {
  return render(<BrowserRouter>{component}</BrowserRouter>)
}

describe('RecentReports', () => {
  const mockReport: Report = {
    report_uuid: 'test-uuid-123',
    file_hash: 'abcdef1234567890',
    sha256: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    meaningful_name: 'test-file.exe',
    names: ['test-file.exe', 'sample.exe'],
    size: 1024000,
    index_time: '2023-12-01T10:00:00Z',
    last_analysis_stats: {
      malicious: 5,
      suspicious: 2,
      harmless: 30,
      undetected: 15
    }
  }

  const mockReports = [mockReport, { ...mockReport, report_uuid: 'test-uuid-456' }]

  describe('Component Rendering', () => {
    it('renders the component with title and icon', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      expect(screen.getByTestId('card')).toBeInTheDocument()
      expect(screen.getByTestId('card-title')).toBeInTheDocument()
      expect(screen.getByText('Recent Reports')).toBeInTheDocument()
      expect(screen.getByTestId('file-text-icon')).toBeInTheDocument()
    })

    it('renders view all button', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      expect(screen.getByTestId('button-as-child')).toBeInTheDocument()
      expect(screen.getByText('View All')).toBeInTheDocument()
      expect(screen.getByTestId('external-link-icon')).toBeInTheDocument()
    })

    it('renders table structure', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      expect(screen.getByTestId('table')).toBeInTheDocument()
      expect(screen.getByTestId('table-header')).toBeInTheDocument()
      expect(screen.getByTestId('table-body')).toBeInTheDocument()
    })

    it('renders table headers', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      expect(screen.getByText('Hash')).toBeInTheDocument()
      expect(screen.getByText('File Name')).toBeInTheDocument()
      expect(screen.getByText('Size')).toBeInTheDocument()
      expect(screen.getByText('Verdict')).toBeInTheDocument()
      expect(screen.getByText('Occurrence')).toBeInTheDocument()
      expect(screen.getByText('Date')).toBeInTheDocument()
    })
  })

  describe('Loading State', () => {
    it('displays loading skeletons when isLoading is true', () => {
      renderWithRouter(<RecentReports reports={[]} isLoading={true} />)
      
      expect(screen.getByText('Recent Reports')).toBeInTheDocument()
      
      const loadingSkeletons = document.querySelectorAll('.animate-pulse')
      expect(loadingSkeletons.length).toBeGreaterThan(0)
    })

    it('does not render table when loading', () => {
      renderWithRouter(<RecentReports reports={[]} isLoading={true} />)
      
      expect(screen.queryByTestId('table')).not.toBeInTheDocument()
    })

    it('renders 5 loading skeleton rows', () => {
      renderWithRouter(<RecentReports reports={[]} isLoading={true} />)
      
      const skeletonRows = document.querySelectorAll('.space-y-3 > div')
      expect(skeletonRows).toHaveLength(5)
    })
  })

  describe('Empty State', () => {
    it('displays "No reports found" message when reports array is empty', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      expect(screen.getByText('No reports found')).toBeInTheDocument()
    })

    it('renders empty state in table row with correct colspan', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      const emptyCell = screen.getByText('No reports found').closest('td')
      expect(emptyCell).toHaveAttribute('colSpan', '6')
    })
  })

  describe('Report Data Display', () => {
    it('renders report data correctly', () => {
      renderWithRouter(<RecentReports reports={[mockReport]} />)
      
      expect(screen.getByText('abcdef123456')).toBeInTheDocument() // Truncated hash
      expect(screen.getByText('test-file.exe')).toBeInTheDocument()
      expect(screen.getByText('1024000B')).toBeInTheDocument() // Formatted size
      expect(screen.getByText('Formatted: 2023-12-01T10:00:00Z')).toBeInTheDocument() // Formatted date
    })

    it('displays meaningful name over names array', () => {
      renderWithRouter(<RecentReports reports={[mockReport]} />)
      
      expect(screen.getByText('test-file.exe')).toBeInTheDocument()
    })

    it('falls back to first name when meaningful_name is not available', () => {
      const reportWithoutMeaningfulName = {
        ...mockReport,
        meaningful_name: undefined,
        names: ['fallback-name.exe']
      }
      
      renderWithRouter(<RecentReports reports={[reportWithoutMeaningfulName]} />)
      
      expect(screen.getByText('fallback-name.exe')).toBeInTheDocument()
    })

    it('shows "Unknown" when neither meaningful_name nor names are available', () => {
      const reportWithoutName = {
        ...mockReport,
        meaningful_name: undefined,
        names: undefined
      }
      
      renderWithRouter(<RecentReports reports={[reportWithoutName]} />)
      
      expect(screen.getByText('Unknown')).toBeInTheDocument()
    })

    it('shows "N/A" for size when size is not available', () => {
      const reportWithoutSize = { ...mockReport, size: undefined }
      
      renderWithRouter(<RecentReports reports={[reportWithoutSize]} />)
      
      expect(screen.getByText('N/A')).toBeInTheDocument()
    })
  })

  describe('Verdict Calculation', () => {
    it('determines malicious verdict when malicious count > 0', () => {
      renderWithRouter(<RecentReports reports={[mockReport]} />)
      
      const badge = screen.getByTestId('badge')
      expect(badge).toHaveAttribute('data-variant', 'destructive')
      expect(badge).toHaveTextContent('malicious')
    })

    it('determines suspicious verdict when only suspicious count > 0', () => {
      const suspiciousReport = {
        ...mockReport,
        last_analysis_stats: {
          malicious: 0,
          suspicious: 2,
          harmless: 30,
          undetected: 15
        }
      }
      
      renderWithRouter(<RecentReports reports={[suspiciousReport]} />)
      
      const badge = screen.getByTestId('badge')
      expect(badge).toHaveTextContent('suspicious')
    })

    it('determines clean verdict when only harmless count > 0', () => {
      const cleanReport = {
        ...mockReport,
        last_analysis_stats: {
          malicious: 0,
          suspicious: 0,
          harmless: 30,
          undetected: 0
        }
      }
      
      renderWithRouter(<RecentReports reports={[cleanReport]} />)
      
      const badge = screen.getByTestId('badge')
      expect(badge).toHaveTextContent('clean')
    })

    it('determines undetected verdict when only undetected count > 0', () => {
      const undetectedReport = {
        ...mockReport,
        last_analysis_stats: {
          malicious: 0,
          suspicious: 0,
          harmless: 0,
          undetected: 15
        }
      }
      
      renderWithRouter(<RecentReports reports={[undetectedReport]} />)
      
      const badge = screen.getByTestId('badge')
      expect(badge).toHaveTextContent('undetected')
    })

    it('handles unknown verdict when no stats are available', () => {
      const reportWithoutStats = { ...mockReport, last_analysis_stats: undefined }
      
      renderWithRouter(<RecentReports reports={[reportWithoutStats]} />)
      
      const badge = screen.getByTestId('badge')
      expect(badge).toHaveTextContent('unknown')
    })
  })

  describe('Navigation', () => {
    it('creates correct links for report details', () => {
      renderWithRouter(<RecentReports reports={[mockReport]} />)
      
      const reportLink = document.querySelector('a[href="/reports/test-uuid-123"]')
      expect(reportLink).toBeInTheDocument()
    })

    it('creates correct link for "View All" button', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      const viewAllLink = document.querySelector('a[href="/reports"]')
      expect(viewAllLink).toBeInTheDocument()
    })

    it('handles occurrence search navigation', () => {
      renderWithRouter(<RecentReports reports={[mockReport]} />)
      
      const occurrenceColumn = screen.getByTestId('occurrence-column')
      fireEvent.click(occurrenceColumn)
      
      expect(mockNavigate).toHaveBeenCalledWith(
        expect.stringContaining('/search?occurrence_search=')
      )
    })
  })

  describe('Table Display', () => {
    it('limits display to 10 reports', () => {
      const manyReports = Array.from({ length: 15 }, (_, i) => ({
        ...mockReport,
        report_uuid: `test-uuid-${i}`
      }))
      
      renderWithRouter(<RecentReports reports={manyReports} />)
      
      const tableRows = screen.getAllByTestId('table-row')
      // Should have header row + 10 data rows
      expect(tableRows.length).toBe(11)
    })

    it('renders occurrence column for each report', () => {
      renderWithRouter(<RecentReports reports={mockReports} />)
      
      const occurrenceColumns = screen.getAllByTestId('occurrence-column')
      expect(occurrenceColumns).toHaveLength(2)
      
      occurrenceColumns.forEach(column => {
        expect(column).toHaveAttribute('data-variant', 'compact')
      })
    })

    it('applies hover styles to table rows', () => {
      renderWithRouter(<RecentReports reports={[mockReport]} />)
      
      const dataRows = screen.getAllByTestId('table-row')
      const reportRow = dataRows.find(row => row.textContent?.includes('test-file.exe'))
      
      expect(reportRow).toHaveClass('hover:bg-muted/50')
    })
  })

  describe('Scroll Area', () => {
    it('renders scroll area with correct height', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      const scrollArea = screen.getByTestId('scroll-area')
      expect(scrollArea).toHaveClass('h-80')
    })
  })

  describe('Accessibility', () => {
    it('provides semantic table structure', () => {
      renderWithRouter(<RecentReports reports={[mockReport]} />)
      
      expect(screen.getByTestId('table')).toBeInTheDocument()
      expect(screen.getByTestId('table-header')).toBeInTheDocument()
      expect(screen.getByTestId('table-body')).toBeInTheDocument()
    })

    it('provides proper heading hierarchy', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      const title = screen.getByTestId('card-title')
      expect(title.tagName).toBe('H3')
    })
  })

  describe('Hash Display', () => {
    it('prefers file_hash over sha256', () => {
      const reportWithBothHashes = {
        ...mockReport,
        file_hash: 'file_hash_value',
        sha256: 'sha256_value_longer'
      }
      
      renderWithRouter(<RecentReports reports={[reportWithBothHashes]} />)
      
      expect(screen.getByText('file_hash_v')).toBeInTheDocument() // Truncated file_hash
    })

    it('falls back to sha256 when file_hash is not available', () => {
      const reportWithSha256Only = {
        ...mockReport,
        file_hash: undefined,
        sha256: 'sha256_value_only'
      }
      
      renderWithRouter(<RecentReports reports={[reportWithSha256Only]} />)
      
      expect(screen.getByText('sha256_value')).toBeInTheDocument() // Truncated sha256
    })
  })

  describe('Component Props', () => {
    it('uses default value for isLoading prop', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      // Should not show loading state when isLoading is not provided
      expect(screen.queryByText('animate-pulse')).not.toBeInTheDocument()
      expect(screen.getByTestId('table')).toBeInTheDocument()
    })
  })

  describe('Layout Classes', () => {
    it('applies correct CSS classes to card header', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      const cardHeader = screen.getByTestId('card-header')
      expect(cardHeader).toHaveClass('flex', 'flex-row', 'items-center', 'justify-between')
    })

    it('applies correct CSS classes to card content', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      const cardContent = screen.getByTestId('card-content')
      expect(cardContent).toHaveClass('p-0')
    })

    it('applies correct CSS classes to title', () => {
      renderWithRouter(<RecentReports reports={[]} />)
      
      const title = screen.getByTestId('card-title')
      expect(title).toHaveClass('flex', 'items-center', 'space-x-2')
    })
  })
})