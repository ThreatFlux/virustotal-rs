import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@/test/utils/test-utils'
import { 
  Table, 
  TableHeader, 
  TableBody, 
  TableFooter, 
  TableHead, 
  TableRow, 
  TableCell, 
  TableCaption 
} from '../table'

describe('Table Components', () => {
  describe('Table', () => {
    it('renders with wrapper div and correct styling', () => {
      render(
        <Table data-testid="table">
          <TableBody>
            <TableRow>
              <TableCell>Test</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      
      const wrapper = screen.getByTestId('table').parentElement
      expect(wrapper).toHaveClass('relative', 'w-full', 'overflow-auto')
      
      const table = screen.getByTestId('table')
      expect(table.tagName).toBe('TABLE')
      expect(table).toHaveClass('w-full', 'caption-bottom', 'text-sm')
    })

    it('forwards ref correctly', () => {
      const ref = vi.fn()
      render(<Table ref={ref}><TableBody><TableRow><TableCell>Test</TableCell></TableRow></TableBody></Table>)
      
      expect(ref).toHaveBeenCalledWith(expect.any(HTMLTableElement))
    })

    it('applies custom className', () => {
      render(
        <Table className="custom-table" data-testid="table">
          <TableBody>
            <TableRow>
              <TableCell>Test</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      
      const table = screen.getByTestId('table')
      expect(table).toHaveClass('custom-table')
      expect(table).toHaveClass('w-full') // Should maintain default classes
    })
  })

  describe('TableHeader', () => {
    it('renders as thead with correct styling', () => {
      render(
        <Table>
          <TableHeader data-testid="header">
            <TableRow>
              <TableHead>Header</TableHead>
            </TableRow>
          </TableHeader>
        </Table>
      )
      
      const header = screen.getByTestId('header')
      expect(header.tagName).toBe('THEAD')
      expect(header).toHaveClass('[&_tr]:border-b')
    })

    it('applies custom className', () => {
      render(
        <Table>
          <TableHeader className="custom-header" data-testid="header">
            <TableRow>
              <TableHead>Header</TableHead>
            </TableRow>
          </TableHeader>
        </Table>
      )
      
      const header = screen.getByTestId('header')
      expect(header).toHaveClass('custom-header')
    })
  })

  describe('TableBody', () => {
    it('renders as tbody with correct styling', () => {
      render(
        <Table>
          <TableBody data-testid="body">
            <TableRow>
              <TableCell>Body</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      
      const body = screen.getByTestId('body')
      expect(body.tagName).toBe('TBODY')
      expect(body).toHaveClass('[&_tr:last-child]:border-0')
    })
  })

  describe('TableFooter', () => {
    it('renders as tfoot with correct styling', () => {
      render(
        <Table>
          <TableFooter data-testid="footer">
            <TableRow>
              <TableCell>Footer</TableCell>
            </TableRow>
          </TableFooter>
        </Table>
      )
      
      const footer = screen.getByTestId('footer')
      expect(footer.tagName).toBe('TFOOT')
      expect(footer).toHaveClass('border-t', 'bg-muted/50', 'font-medium')
    })
  })

  describe('TableRow', () => {
    it('renders as tr with correct styling', () => {
      render(
        <Table>
          <TableBody>
            <TableRow data-testid="row">
              <TableCell>Cell</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      
      const row = screen.getByTestId('row')
      expect(row.tagName).toBe('TR')
      expect(row).toHaveClass('border-b', 'transition-colors', 'hover:bg-muted/50')
    })

    it('supports selection state', () => {
      render(
        <Table>
          <TableBody>
            <TableRow data-state="selected" data-testid="row">
              <TableCell>Cell</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      
      const row = screen.getByTestId('row')
      expect(row).toHaveAttribute('data-state', 'selected')
      expect(row).toHaveClass('data-[state=selected]:bg-muted')
    })
  })

  describe('TableHead', () => {
    it('renders as th with correct styling', () => {
      render(
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead data-testid="head">Column Header</TableHead>
            </TableRow>
          </TableHeader>
        </Table>
      )
      
      const head = screen.getByTestId('head')
      expect(head.tagName).toBe('TH')
      expect(head).toHaveClass('h-12', 'px-4', 'text-left', 'align-middle', 'font-medium', 'text-muted-foreground')
    })

    it('supports sorting attributes', () => {
      render(
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead 
                data-testid="sortable-head" 
                aria-sort="ascending"
                onClick={() => {}}
              >
                Sortable Column
              </TableHead>
            </TableRow>
          </TableHeader>
        </Table>
      )
      
      const head = screen.getByTestId('sortable-head')
      expect(head).toHaveAttribute('aria-sort', 'ascending')
    })
  })

  describe('TableCell', () => {
    it('renders as td with correct styling', () => {
      render(
        <Table>
          <TableBody>
            <TableRow>
              <TableCell data-testid="cell">Cell Content</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      
      const cell = screen.getByTestId('cell')
      expect(cell.tagName).toBe('TD')
      expect(cell).toHaveClass('p-4', 'align-middle')
    })

    it('applies custom className', () => {
      render(
        <Table>
          <TableBody>
            <TableRow>
              <TableCell className="custom-cell" data-testid="cell">Content</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      
      const cell = screen.getByTestId('cell')
      expect(cell).toHaveClass('custom-cell')
      expect(cell).toHaveClass('p-4') // Should maintain default classes
    })

    it('supports interactive content', () => {
      render(
        <Table>
          <TableBody>
            <TableRow>
              <TableCell>
                <button>Action</button>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      
      expect(screen.getByRole('button', { name: 'Action' })).toBeInTheDocument()
    })
  })

  describe('TableCaption', () => {
    it('renders as caption with correct styling', () => {
      render(
        <Table>
          <TableCaption data-testid="caption">Table description</TableCaption>
          <TableBody>
            <TableRow>
              <TableCell>Cell</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      
      const caption = screen.getByTestId('caption')
      expect(caption.tagName).toBe('CAPTION')
      expect(caption).toHaveClass('mt-4', 'text-sm', 'text-muted-foreground')
    })
  })

  describe('Complete Table Structure', () => {
    it('renders a full table with all components', () => {
      render(
        <Table data-testid="full-table">
          <TableCaption>A list of recent reports</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>File Name</TableHead>
              <TableHead>Hash</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow>
              <TableCell>malware.exe</TableCell>
              <TableCell>abc123...</TableCell>
              <TableCell>Malicious</TableCell>
              <TableCell>
                <button>View</button>
              </TableCell>
            </TableRow>
            <TableRow>
              <TableCell>document.pdf</TableCell>
              <TableCell>def456...</TableCell>
              <TableCell>Clean</TableCell>
              <TableCell>
                <button>View</button>
              </TableCell>
            </TableRow>
          </TableBody>
          <TableFooter>
            <TableRow>
              <TableCell colSpan={4}>Total: 2 files</TableCell>
            </TableRow>
          </TableFooter>
        </Table>
      )

      // Check table structure
      expect(screen.getByTestId('full-table')).toBeInTheDocument()
      expect(screen.getByText('A list of recent reports')).toBeInTheDocument()
      
      // Check headers
      expect(screen.getByText('File Name')).toBeInTheDocument()
      expect(screen.getByText('Hash')).toBeInTheDocument()
      expect(screen.getByText('Status')).toBeInTheDocument()
      expect(screen.getByText('Actions')).toBeInTheDocument()
      
      // Check data rows
      expect(screen.getByText('malware.exe')).toBeInTheDocument()
      expect(screen.getByText('document.pdf')).toBeInTheDocument()
      expect(screen.getByText('Malicious')).toBeInTheDocument()
      expect(screen.getByText('Clean')).toBeInTheDocument()
      
      // Check footer
      expect(screen.getByText('Total: 2 files')).toBeInTheDocument()
      
      // Check interactive elements
      const buttons = screen.getAllByText('View')
      expect(buttons).toHaveLength(2)
    })

    it('maintains proper semantic structure', () => {
      render(
        <Table role="table" aria-label="Reports table">
          <TableCaption>Recent malware analysis reports</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead scope="col">File</TableHead>
              <TableHead scope="col">Result</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow>
              <TableHead scope="row">test.exe</TableHead>
              <TableCell>Malicious</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )

      const table = screen.getByRole('table')
      expect(table).toHaveAttribute('aria-label', 'Reports table')
      
      const columnHeaders = screen.getAllByRole('columnheader')
      expect(columnHeaders).toHaveLength(2)
      expect(columnHeaders[0]).toHaveAttribute('scope', 'col')
      
      const rowHeader = screen.getByRole('rowheader')
      expect(rowHeader).toHaveAttribute('scope', 'row')
    })

    it('supports sortable columns', () => {
      const handleSort = vi.fn()
      
      render(
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead 
                role="button"
                tabIndex={0}
                onClick={handleSort}
                onKeyDown={(e) => e.key === 'Enter' && handleSort()}
                aria-sort="none"
              >
                Sortable Column
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow>
              <TableCell>Data</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )

      const sortableHeader = screen.getByRole('button', { name: 'Sortable Column' })
      expect(sortableHeader).toHaveAttribute('aria-sort', 'none')
      expect(sortableHeader).toHaveAttribute('tabIndex', '0')
    })

    it('supports responsive design with overflow', () => {
      render(
        <Table data-testid="responsive-table">
          <TableHeader>
            <TableRow>
              <TableHead>Column 1</TableHead>
              <TableHead>Column 2</TableHead>
              <TableHead>Column 3</TableHead>
              <TableHead>Column 4</TableHead>
              <TableHead>Column 5</TableHead>
            </TableRow>
          </TableHeader>
        </Table>
      )

      const wrapper = screen.getByTestId('responsive-table').parentElement
      expect(wrapper).toHaveClass('overflow-auto')
    })
  })
})