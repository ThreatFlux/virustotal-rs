import React from 'react'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AnalysisDisplay } from '../AnalysisDisplay'

// Mock PrismJS
vi.mock('prismjs', () => ({
  default: {
    highlightAll: vi.fn(),
  },
}))

// Mock window.open
Object.defineProperty(window, 'open', {
  value: vi.fn(),
  writable: true,
})

// Mock clipboard
Object.assign(navigator, {
  clipboard: {
    writeText: vi.fn().mockImplementation(() => Promise.resolve()),
  },
})

describe('AnalysisDisplay', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('No Analysis Data', () => {
    it('renders message when no analysis data is available', () => {
      const emptyReport = {}
      
      render(<AnalysisDisplay report={emptyReport} />)
      
      expect(screen.getByText('No special analysis data available for this file')).toBeInTheDocument()
    })

    it('renders message when all analysis fields are undefined', () => {
      const reportWithUndefined = {
        pe_info: undefined,
        pdf_info: undefined,
        office_info: undefined,
        androguard: undefined,
        bundle_info: undefined,
        exiftool: undefined,
        trid: undefined,
        detectiteasy: undefined,
      }
      
      render(<AnalysisDisplay report={reportWithUndefined} />)
      
      expect(screen.getByText('No special analysis data available for this file')).toBeInTheDocument()
    })
  })

  describe('PE Information Analysis', () => {
    const mockPEInfo = {
      entry_point: 0x1000,
      machine_type: 332, // x86
      timestamp: 1609459200, // 2021-01-01
      imphash: '1234567890abcdef1234567890abcdef',
      rich_header_hash: 'abcdef1234567890abcdef1234567890',
      packers: ['UPX', 'PECompact'],
      signature_info: {
        subject: 'Test Company Inc.',
        issuer: 'Test CA',
      },
      sections: [
        {
          name: '.text',
          virtual_size: 4096,
          raw_size: 4096,
          entropy: 6.2,
          md5: 'abc123def456',
        },
        {
          name: '.data',
          virtual_size: 2048,
          raw_size: 2048,
          entropy: 8.1, // High entropy (suspicious)
          md5: 'def456abc123',
        }
      ],
      import_list: [
        {
          library_name: 'kernel32.dll',
          imported_functions: ['CreateFileA', 'ReadFile', 'VirtualAlloc'] // VirtualAlloc is suspicious
        },
        {
          library_name: 'ntdll.dll',
          imported_functions: ['NtQueryInformationProcess'] // Anti-debug function
        }
      ],
      exports: ['Export1', 'Export2', 'Export3'],
      resources: [
        { type: 'RT_ICON', size: 1024 },
        { type: 'RT_VERSION', size: 512 },
      ],
      overlay: {
        size: 2048,
        md5: 'overlay123hash',
      }
    }

    it('renders PE analysis card with correct title', () => {
      const report = { pe_info: mockPEInfo, type_tag: 'peexe' }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Portable Executable Analysis')).toBeInTheDocument()
    })

    it('displays PE badges correctly', () => {
      const report = { pe_info: mockPEInfo, type_tag: 'pedll' }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('DLL')).toBeInTheDocument()
      expect(screen.getByText('PACKED')).toBeInTheDocument()
      expect(screen.getByText('SIGNED')).toBeInTheDocument()
      expect(screen.getByText('OVERLAY')).toBeInTheDocument()
    })

    it('detects driver files correctly', () => {
      const driverPE = {
        ...mockPEInfo,
        import_list: [
          {
            library_name: 'ntoskrnl.exe',
            imported_functions: ['IoCreateDevice']
          }
        ]
      }
      const report = { pe_info: driverPE }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('DRIVER')).toBeInTheDocument()
    })

    it('displays machine type correctly', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('x86 (32-bit)')).toBeInTheDocument()
    })

    it('displays different machine types', () => {
      const x64Report = { pe_info: { ...mockPEInfo, machine_type: 34404 } }
      const armReport = { pe_info: { ...mockPEInfo, machine_type: 452 } }
      const arm64Report = { pe_info: { ...mockPEInfo, machine_type: 43620 } }
      const unknownReport = { pe_info: { ...mockPEInfo, machine_type: 9999 } }
      
      const { rerender } = render(<AnalysisDisplay report={x64Report} />)
      expect(screen.getByText('x64 (64-bit)')).toBeInTheDocument()
      
      rerender(<AnalysisDisplay report={armReport} />)
      expect(screen.getByText('ARM')).toBeInTheDocument()
      
      rerender(<AnalysisDisplay report={arm64Report} />)
      expect(screen.getByText('ARM64')).toBeInTheDocument()
      
      rerender(<AnalysisDisplay report={unknownReport} />)
      expect(screen.getByText('Unknown (9999)')).toBeInTheDocument()
    })

    it('formats timestamp correctly', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      // Should format Unix timestamp as locale string
      expect(screen.getByText(/2021/)).toBeInTheDocument()
    })

    it('displays hash values', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('1234567890abcdef1234567890abcdef')).toBeInTheDocument()
      expect(screen.getByText('abcdef1234567890abcdef1234567890')).toBeInTheDocument()
    })

    it('highlights suspicious imports', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Contains suspicious API imports (process injection, hooking)')).toBeInTheDocument()
    })

    it('highlights anti-debugging techniques', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Contains anti-debugging techniques')).toBeInTheDocument()
    })

    it('highlights packed executables', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Packed/Obfuscated: UPX, PECompact')).toBeInTheDocument()
    })

    it('displays sections with entropy highlighting', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('.text')).toBeInTheDocument()
      expect(screen.getByText('.data')).toBeInTheDocument()
      expect(screen.getByText('6.20')).toBeInTheDocument()
      expect(screen.getByText('8.10')).toBeInTheDocument()
      
      // High entropy should be highlighted
      const highEntropyElement = screen.getByText('8.10')
      expect(highEntropyElement).toHaveClass('text-red-600')
    })

    it('displays import libraries with suspicious marking', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('kernel32.dll')).toBeInTheDocument()
      expect(screen.getByText('ntdll.dll')).toBeInTheDocument()
      
      // Should mark suspicious libraries
      const suspiciousRows = document.querySelectorAll('.bg-red-50')
      expect(suspiciousRows.length).toBeGreaterThan(0)
    })

    it('displays digital signature information', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('✓ Digitally Signed')).toBeInTheDocument()
      expect(screen.getByText('Subject: Test Company Inc.')).toBeInTheDocument()
      expect(screen.getByText('Issuer: Test CA')).toBeInTheDocument()
    })

    it('displays overlay data warning', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Overlay Data Detected')).toBeInTheDocument()
      expect(screen.getByText('Size: 2.0 KB')).toBeInTheDocument()
      expect(screen.getByText('MD5: overlay123hash')).toBeInTheDocument()
    })

    it('displays exports information', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Exported Functions (3)')).toBeInTheDocument()
      expect(screen.getByText('Export1')).toBeInTheDocument()
      expect(screen.getByText('Export2')).toBeInTheDocument()
      expect(screen.getByText('Export3')).toBeInTheDocument()
    })

    it('displays resources information', () => {
      const report = { pe_info: mockPEInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Resources (2)')).toBeInTheDocument()
      expect(screen.getByText('RT_ICON')).toBeInTheDocument()
      expect(screen.getByText('RT_VERSION')).toBeInTheDocument()
      expect(screen.getByText('1.0 KB')).toBeInTheDocument()
      expect(screen.getByText('0.5 KB')).toBeInTheDocument()
    })
  })

  describe('Office Document Analysis', () => {
    const mockOfficeInfo = {
      summary_info: {
        title: 'Test Document',
        subject: 'Test Subject',
        author: 'Test Author',
        last_author: 'Last Author',
        creation_datetime: '2023-01-01T12:00:00Z',
        last_saved: '2023-01-02T12:00:00Z',
        application_name: 'Microsoft Office Word',
        revision_number: '1',
        word_count: 150,
      },
      document_summary_info: {
        slide_count: 10,
        paragraph_count: 25,
        note_count: 5,
        byte_count: 2048000,
        presentation_format: 'PPTX',
        code_page: 1252,
      },
      macros: [
        { name: 'AutoOpen', code_size: 1024 },
        { name: 'Document_Open', code_size: 512 },
      ],
      entries: [
        { name: 'Root Entry', clsid_literal: 'PowerPoint Document' },
        { name: 'VBA/ThisDocument', clsid_literal: 'VBA Module' },
        { name: '_VBA_PROJECT', size: 4096 },
      ]
    }

    it('renders PowerPoint document correctly', () => {
      const report = { office_info: mockOfficeInfo, type_tag: 'pptx' }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('PowerPoint Presentation Analysis')).toBeInTheDocument()
    })

    it('renders Word document correctly', () => {
      const wordOfficeInfo = {
        ...mockOfficeInfo,
        entries: [{ name: 'WordDocument', clsid_literal: 'Word Document' }]
      }
      const report = { office_info: wordOfficeInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Word Document Analysis')).toBeInTheDocument()
    })

    it('renders Excel document correctly', () => {
      const excelOfficeInfo = {
        ...mockOfficeInfo,
        entries: [{ name: 'Workbook', clsid_literal: 'Excel Workbook' }]
      }
      const report = { office_info: excelOfficeInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Excel Spreadsheet Analysis')).toBeInTheDocument()
    })

    it('displays document metadata', () => {
      const report = { office_info: mockOfficeInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Test Document')).toBeInTheDocument()
      expect(screen.getByText('Test Subject')).toBeInTheDocument()
      expect(screen.getByText('Test Author')).toBeInTheDocument()
      expect(screen.getByText('Last Author')).toBeInTheDocument()
    })

    it('displays document statistics', () => {
      const report = { office_info: mockOfficeInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('10')).toBeInTheDocument() // slide_count
      expect(screen.getByText('Slides')).toBeInTheDocument()
      expect(screen.getByText('25')).toBeInTheDocument() // paragraph_count
      expect(screen.getByText('Paragraphs')).toBeInTheDocument()
      expect(screen.getByText('150')).toBeInTheDocument() // word_count
      expect(screen.getByText('Words')).toBeInTheDocument()
    })

    it('detects and warns about VBA macros', () => {
      const report = { office_info: mockOfficeInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Security Alert')).toBeInTheDocument()
      expect(screen.getByText('Security Concerns Detected')).toBeInTheDocument()
      expect(screen.getByText('VBA Macros Found (2)')).toBeInTheDocument()
      expect(screen.getByText('AutoOpen')).toBeInTheDocument()
      expect(screen.getByText('Document_Open')).toBeInTheDocument()
    })

    it('detects VBA-related OLE entries', () => {
      const report = { office_info: mockOfficeInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('VBA/Macro OLE Entries Found')).toBeInTheDocument()
      expect(screen.getByText('VBA/ThisDocument')).toBeInTheDocument()
      expect(screen.getByText('_VBA_PROJECT')).toBeInTheDocument()
    })

    it('handles email messages', () => {
      const emailInfo = {
        entries: [
          { name: '__attach_version1.0_#00000000', size: 1024 },
          { name: '__substg1.0_37001F', size: 512 },
        ]
      }
      const report = { office_info: emailInfo, type_tag: 'outlook' }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Email Message Analysis')).toBeInTheDocument()
      expect(screen.getByText('Security Alert')).toBeInTheDocument() // Email attachments trigger security alert
    })

    it('expands and collapses OLE structure', () => {
      const report = { office_info: mockOfficeInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      const expandButton = screen.getByText(/OLE Structure \(3 entries\)/)
      expect(expandButton).toBeInTheDocument()
      
      fireEvent.click(expandButton)
      
      expect(screen.getByText('Root Entry')).toBeInTheDocument()
      expect(screen.getByText('VBA/ThisDocument')).toBeInTheDocument()
      expect(screen.getByText('_VBA_PROJECT')).toBeInTheDocument()
    })
  })

  describe('PDF Analysis', () => {
    const mockPDFInfo = {
      num_pages: 5,
      num_objects: 150,
      num_streams: 25,
      num_endstream: 25,
      num_obj: 150,
      num_endobj: 150,
      num_js: 2, // Suspicious
      num_launch: 1, // Suspicious
      num_jbig2decode: 0,
      header: '%PDF-1.7',
      js: ['function malicious() { /* code */ }', 'eval(unescape("%75%6e%65%73%63%61%70%65"))'],
    }

    it('renders PDF analysis card', () => {
      const report = { pdf_info: mockPDFInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('PDF Document Analysis')).toBeInTheDocument()
    })

    it('displays PDF statistics', () => {
      const report = { pdf_info: mockPDFInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('5')).toBeInTheDocument() // pages
      expect(screen.getByText('150')).toBeInTheDocument() // objects
      expect(screen.getByText('25')).toBeInTheDocument() // streams
    })

    it('detects and warns about suspicious PDF elements', () => {
      const report = { pdf_info: mockPDFInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Suspicious Elements Detected')).toBeInTheDocument()
      expect(screen.getByText('JavaScript')).toBeInTheDocument()
      expect(screen.getByText('2 script(s)')).toBeInTheDocument()
      expect(screen.getByText('Launch Action')).toBeInTheDocument()
      expect(screen.getByText('1')).toBeInTheDocument()
    })

    it('displays PDF header version', () => {
      const report = { pdf_info: mockPDFInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('%PDF-1.7')).toBeInTheDocument()
    })

    it('displays JavaScript content', () => {
      const report = { pdf_info: mockPDFInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('JavaScript Code')).toBeInTheDocument()
      expect(screen.getByText(/function malicious/)).toBeInTheDocument()
    })
  })

  describe('Android Analysis', () => {
    const mockAndroidInfo = {
      package_name: 'com.example.testapp',
      main_activity: 'com.example.testapp.MainActivity',
      permissions: [
        'android.permission.INTERNET',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.DANGEROUS_PERMISSION',
      ],
      activities: [
        'com.example.testapp.MainActivity',
        'com.example.testapp.SecondActivity',
      ]
    }

    it('renders Android analysis card', () => {
      const report = { androguard: mockAndroidInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Android Analysis')).toBeInTheDocument()
    })

    it('displays package name and main activity', () => {
      const report = { androguard: mockAndroidInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('com.example.testapp')).toBeInTheDocument()
      expect(screen.getByText('com.example.testapp.MainActivity')).toBeInTheDocument()
    })

    it('displays permissions with danger highlighting', () => {
      const report = { androguard: mockAndroidInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Permissions (3)')).toBeInTheDocument()
      expect(screen.getByText('android.permission.INTERNET')).toBeInTheDocument()
      expect(screen.getByText('android.permission.DANGEROUS_PERMISSION')).toBeInTheDocument()
      
      // Dangerous permission should be highlighted
      const dangerousPermission = screen.getByText('android.permission.DANGEROUS_PERMISSION')
      expect(dangerousPermission.closest('.badge')).toHaveClass('bg-destructive')
    })

    it('displays activities list', () => {
      const report = { androguard: mockAndroidInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('com.example.testapp.MainActivity')).toBeInTheDocument()
      expect(screen.getByText('com.example.testapp.SecondActivity')).toBeInTheDocument()
    })
  })

  describe('EXIF Data Analysis', () => {
    const mockExifData = {
      FileType: 'JPEG',
      ImageSize: '1920x1080',
      Megapixels: '2.1',
      BitDepth: '8',
      ColorType: 'RGB',
      Make: 'Canon',
      Model: 'EOS 5D Mark IV',
      DateTimeOriginal: '2023:01:01 12:00:00',
      GPSLatitude: '40.7128 N',
      GPSLongitude: '74.0060 W',
      Software: 'Adobe Photoshop CC',
      XResolution: '300',
      YResolution: '300',
    }

    it('renders image metadata card', () => {
      const report = { exiftool: mockExifData, type_tag: 'jpeg' }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Image Metadata')).toBeInTheDocument()
      expect(screen.getByText('JPEG')).toBeInTheDocument()
    })

    it('displays image properties', () => {
      const report = { exiftool: mockExifData, type_tag: 'jpeg' }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('1920x1080')).toBeInTheDocument()
      expect(screen.getByText('2.1 MP')).toBeInTheDocument()
      expect(screen.getByText('8 bit')).toBeInTheDocument()
      expect(screen.getByText('RGB')).toBeInTheDocument()
    })

    it('displays camera information', () => {
      const report = { exiftool: mockExifData, type_tag: 'jpeg' }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Camera Information')).toBeInTheDocument()
      expect(screen.getByText('Canon')).toBeInTheDocument()
      expect(screen.getByText('EOS 5D Mark IV')).toBeInTheDocument()
    })

    it('warns about GPS location data', () => {
      const report = { exiftool: mockExifData, type_tag: 'jpeg' }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('GPS Location Data Detected')).toBeInTheDocument()
      expect(screen.getByText('This image contains geographical location information')).toBeInTheDocument()
    })

    it('categorizes EXIF fields properly', () => {
      const report = { exiftool: mockExifData, type_tag: 'jpeg' }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Image Properties')).toBeInTheDocument()
      expect(screen.getByText('Camera Settings')).toBeInTheDocument()
      expect(screen.getByText('GPS Location')).toBeInTheDocument()
    })
  })

  describe('Bundle Information Analysis', () => {
    const mockBundleInfo = {
      type: 'XLSX',
      num_children: 15,
      num_files: 12,
      uncompressed_size: 2048000,
      extensions: {
        'xml': 8,
        'rels': 4,
        'txt': 1,
      },
      file_types: {
        'XML': 10,
        'Text': 2,
      },
      lowest_datetime: '2023-01-01 10:00:00',
      highest_datetime: '2023-01-02 15:30:00',
      contained_files: [
        {
          name: 'xl/workbook.xml',
          sha256: 'abc123def456',
        },
        {
          name: 'xl/worksheets/sheet1.xml',
          sha256: 'def456abc123',
        }
      ]
    }

    it('renders Office Open XML bundle correctly', () => {
      const report = { bundle_info: mockBundleInfo, type_tag: 'xlsx' }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Office Open XML Structure')).toBeInTheDocument()
      expect(screen.getByText('XML-based')).toBeInTheDocument()
      expect(screen.getByText('Excel 2007+')).toBeInTheDocument()
    })

    it('displays bundle statistics', () => {
      const report = { bundle_info: mockBundleInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('15')).toBeInTheDocument() // num_children
      expect(screen.getByText('Components')).toBeInTheDocument()
      expect(screen.getByText('12')).toBeInTheDocument() // num_files
      expect(screen.getByText('Files')).toBeInTheDocument()
      expect(screen.getByText('2000.0 KB')).toBeInTheDocument() // uncompressed_size
    })

    it('displays XML components for Office files', () => {
      const report = { bundle_info: mockBundleInfo, type_tag: 'xlsx' }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('XML Components')).toBeInTheDocument()
      expect(screen.getByText('.xml (8)')).toBeInTheDocument()
      expect(screen.getByText('.rels (4)')).toBeInTheDocument()
    })

    it('displays contained files', () => {
      const report = { bundle_info: mockBundleInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Document Components')).toBeInTheDocument()
      expect(screen.getByText('xl/workbook.xml')).toBeInTheDocument()
      expect(screen.getByText('xl/worksheets/sheet1.xml')).toBeInTheDocument()
      expect(screen.getByText('SHA256: abc123def456...')).toBeInTheDocument()
    })

    it('displays date information', () => {
      const report = { bundle_info: mockBundleInfo }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Created:')).toBeInTheDocument()
      expect(screen.getByText('Modified:')).toBeInTheDocument()
      expect(screen.getByText('2023-01-01 10:00:00')).toBeInTheDocument()
      expect(screen.getByText('2023-01-02 15:30:00')).toBeInTheDocument()
    })
  })

  describe('TrID Analysis', () => {
    const mockTrIDData = [
      { file_type: 'Portable Executable', extension: 'exe', probability: 95.5 },
      { file_type: 'Windows Library', extension: 'dll', probability: 3.2 },
      { file_type: 'Generic Binary', extension: 'bin', probability: 1.3 },
    ]

    it('renders TrID analysis card', () => {
      const report = { trid: mockTrIDData }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('TrID File Type Analysis')).toBeInTheDocument()
    })

    it('displays file type probabilities', () => {
      const report = { trid: mockTrIDData }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Portable Executable')).toBeInTheDocument()
      expect(screen.getByText('exe')).toBeInTheDocument()
      expect(screen.getByText('95.5%')).toBeInTheDocument()
      
      expect(screen.getByText('Windows Library')).toBeInTheDocument()
      expect(screen.getByText('dll')).toBeInTheDocument()
      expect(screen.getByText('3.2%')).toBeInTheDocument()
    })

    it('displays probability bars', () => {
      const report = { trid: mockTrIDData }
      
      render(<AnalysisDisplay report={report} />)
      
      const progressBars = document.querySelectorAll('.bg-primary')
      expect(progressBars.length).toBe(3)
      
      // First bar should have 95.5% width
      expect(progressBars[0]).toHaveStyle('width: 95.5%')
    })

    it('handles TrID data without extensions', () => {
      const dataWithoutExt = [
        { file_type: 'Unknown Format', probability: 50.0 }
      ]
      const report = { trid: dataWithoutExt }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Unknown Format')).toBeInTheDocument()
      expect(screen.getByText('N/A')).toBeInTheDocument()
    })
  })

  describe('Detect It Easy Analysis', () => {
    const mockDetectItEasy = {
      values: [
        { name: 'Microsoft Visual C++', version: '2019', type: 'Compiler' },
        { name: 'UPX', version: '3.96', type: 'Packer' },
        { name: '.NET Framework', version: '4.8', type: 'Runtime' },
      ]
    }

    it('renders Detect It Easy analysis card', () => {
      const report = { detectiteasy: mockDetectItEasy }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Detect It Easy Analysis')).toBeInTheDocument()
    })

    it('displays detection items with versions', () => {
      const report = { detectiteasy: mockDetectItEasy }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Microsoft Visual C++')).toBeInTheDocument()
      expect(screen.getByText('Version: 2019')).toBeInTheDocument()
      expect(screen.getByText('UPX')).toBeInTheDocument()
      expect(screen.getByText('Version: 3.96')).toBeInTheDocument()
    })

    it('displays detection types as badges', () => {
      const report = { detectiteasy: mockDetectItEasy }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Compiler')).toBeInTheDocument()
      expect(screen.getByText('Packer')).toBeInTheDocument()
      expect(screen.getByText('Runtime')).toBeInTheDocument()
    })

    it('handles items without version', () => {
      const dataWithoutVersion = {
        values: [{ name: 'Unknown Tool', type: 'Tool' }]
      }
      const report = { detectiteasy: dataWithoutVersion }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Unknown Tool')).toBeInTheDocument()
      expect(screen.queryByText('Version:')).not.toBeInTheDocument()
    })
  })

  describe('Multiple Analysis Types', () => {
    it('renders multiple analysis sections together', () => {
      const report = {
        pe_info: { entry_point: 0x1000 },
        pdf_info: { num_pages: 5 },
        exiftool: { FileType: 'JPEG' },
        type_tag: 'peexe'
      }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Portable Executable Analysis')).toBeInTheDocument()
      expect(screen.getByText('PDF Document Analysis')).toBeInTheDocument()
      expect(screen.getByText('Image Metadata')).toBeInTheDocument()
    })

    it('handles mixed file types gracefully', () => {
      const report = {
        pe_info: { entry_point: 0x1000 },
        office_info: { summary_info: { title: 'Test' } },
        bundle_info: { type: 'ZIP' },
      }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Portable Executable Analysis')).toBeInTheDocument()
      expect(screen.getByText('Office Document Analysis')).toBeInTheDocument()
      expect(screen.getByText('Bundle Information')).toBeInTheDocument()
    })
  })

  describe('Error Handling', () => {
    it('handles corrupted PE data gracefully', () => {
      const corruptedPE = {
        pe_info: {
          entry_point: null,
          machine_type: undefined,
          sections: null,
        }
      }
      
      render(<AnalysisDisplay report={corruptedPE} />)
      
      expect(screen.getByText('Portable Executable Analysis')).toBeInTheDocument()
      expect(screen.getByText('0x00000000')).toBeInTheDocument() // null entry point handling
    })

    it('handles missing nested objects gracefully', () => {
      const reportWithNulls = {
        office_info: {
          summary_info: null,
          document_summary_info: undefined,
          entries: [],
        }
      }
      
      render(<AnalysisDisplay report={reportWithNulls} />)
      
      expect(screen.getByText('Office Document Analysis')).toBeInTheDocument()
      // Should not crash with missing nested data
    })

    it('handles empty arrays gracefully', () => {
      const reportWithEmptyArrays = {
        pe_info: {
          import_list: [],
          exports: [],
          sections: [],
          resources: [],
        }
      }
      
      render(<AnalysisDisplay report={reportWithEmptyArrays} />)
      
      expect(screen.getByText('Portable Executable Analysis')).toBeInTheDocument()
      // Should not display sections for empty arrays
      expect(screen.queryByText('Import Libraries')).not.toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('provides proper heading structure', () => {
      const report = {
        pe_info: { entry_point: 0x1000 },
        pdf_info: { num_pages: 5 },
      }
      
      render(<AnalysisDisplay report={report} />)
      
      const headings = screen.getAllByRole('heading')
      expect(headings.length).toBeGreaterThan(0)
      
      expect(screen.getByRole('heading', { name: /Portable Executable Analysis/ })).toBeInTheDocument()
      expect(screen.getByRole('heading', { name: /PDF Document Analysis/ })).toBeInTheDocument()
    })

    it('provides proper table structure for screen readers', () => {
      const report = {
        trid: [{ file_type: 'Test', extension: 'test', probability: 100 }]
      }
      
      render(<AnalysisDisplay report={report} />)
      
      const table = screen.getByRole('table')
      expect(table).toBeInTheDocument()
      
      const headers = screen.getAllByRole('columnheader')
      expect(headers.length).toBe(3)
      expect(screen.getByText('File Type')).toBeInTheDocument()
      expect(screen.getByText('Extension')).toBeInTheDocument()
      expect(screen.getByText('Probability')).toBeInTheDocument()
    })

    it('provides meaningful labels for data fields', () => {
      const report = {
        pe_info: {
          entry_point: 0x1000,
          machine_type: 332,
          timestamp: 1609459200,
        }
      }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Entry Point')).toBeInTheDocument()
      expect(screen.getByText('Machine Type')).toBeInTheDocument()
      expect(screen.getByText('Timestamp')).toBeInTheDocument()
    })
  })

  describe('Responsive Design', () => {
    it('uses responsive grid layouts', () => {
      const report = {
        pe_info: {
          entry_point: 0x1000,
          machine_type: 332,
          timestamp: 1609459200,
        }
      }
      
      render(<AnalysisDisplay report={report} />)
      
      const gridElements = document.querySelectorAll('.md\\:grid-cols-3, .md\\:grid-cols-2')
      expect(gridElements.length).toBeGreaterThan(0)
    })

    it('handles mobile layout for long text', () => {
      const report = {
        pe_info: {
          import_list: [
            {
              library_name: 'very-long-library-name-that-might-overflow.dll',
              imported_functions: ['LongFunctionNameThatMightCauseLayoutIssues']
            }
          ]
        }
      }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('very-long-library-name-that-might-overflow.dll')).toBeInTheDocument()
      
      // Should have responsive classes
      const responsiveElements = document.querySelectorAll('.sm\\:flex-row, .break-all')
      expect(responsiveElements.length).toBeGreaterThan(0)
    })
  })

  describe('Interactive Elements', () => {
    it('expands collapsible sections', () => {
      const report = {
        office_info: {
          entries: [
            { name: 'Entry1', size: 1024 },
            { name: 'Entry2', size: 2048 },
          ]
        }
      }
      
      render(<AnalysisDisplay report={report} />)
      
      const expandButton = screen.getByText(/OLE Structure/)
      fireEvent.click(expandButton)
      
      expect(screen.getByText('Entry1')).toBeInTheDocument()
      expect(screen.getByText('Entry2')).toBeInTheDocument()
    })

    it('collapses expanded sections', () => {
      const report = {
        office_info: {
          entries: [{ name: 'Entry1', size: 1024 }]
        }
      }
      
      render(<AnalysisDisplay report={report} />)
      
      const expandButton = screen.getByText(/OLE Structure/)
      
      // Expand
      fireEvent.click(expandButton)
      expect(screen.getByText('Entry1')).toBeInTheDocument()
      
      // Collapse
      fireEvent.click(expandButton)
      expect(screen.queryByText('Entry1')).not.toBeInTheDocument()
    })
  })

  describe('Edge Cases and Performance', () => {
    it('handles very large import lists efficiently', () => {
      const largeImportList = Array.from({ length: 100 }, (_, i) => ({
        library_name: `library${i}.dll`,
        imported_functions: [`Function${i}A`, `Function${i}B`]
      }))
      
      const report = {
        pe_info: {
          import_list: largeImportList
        }
      }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Import Libraries (100)')).toBeInTheDocument()
      expect(screen.getByText('library0.dll')).toBeInTheDocument()
      expect(screen.getByText('library99.dll')).toBeInTheDocument()
    })

    it('handles large section lists with proper scrolling', () => {
      const largeSectionList = Array.from({ length: 50 }, (_, i) => ({
        name: `.section${i}`,
        virtual_size: 4096 * (i + 1),
        raw_size: 4096 * (i + 1),
        entropy: Math.random() * 8,
        md5: `hash${i.toString().padStart(3, '0')}`,
      }))
      
      const report = {
        pe_info: {
          sections: largeSectionList
        }
      }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('PE Sections (50)')).toBeInTheDocument()
      expect(screen.getByText('.section0')).toBeInTheDocument()
      expect(screen.getByText('.section49')).toBeInTheDocument()
    })

    it('limits resource display to prevent performance issues', () => {
      const manyResources = Array.from({ length: 20 }, (_, i) => ({
        type: `RT_TYPE${i}`,
        size: 1024 * (i + 1)
      }))
      
      const report = {
        pe_info: {
          resources: manyResources
        }
      }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('Resources (20)')).toBeInTheDocument()
      expect(screen.getByText('RT_TYPE0')).toBeInTheDocument()
      expect(screen.getByText('RT_TYPE4')).toBeInTheDocument()
      expect(screen.getByText('...and 15 more resources')).toBeInTheDocument()
      expect(screen.queryByText('RT_TYPE19')).not.toBeInTheDocument()
    })

    it('handles malformed data gracefully', () => {
      const malformedReport = {
        pe_info: {
          sections: [
            { name: null, entropy: 'not-a-number' },
            { virtual_size: 'not-a-number' },
          ]
        }
      }
      
      render(<AnalysisDisplay report={malformedReport} />)
      
      expect(screen.getByText('Portable Executable Analysis')).toBeInTheDocument()
      // Should not crash with malformed data
    })
  })

  describe('Date and Number Formatting', () => {
    it('formats timestamps correctly', () => {
      const report = {
        pe_info: {
          timestamp: 1609459200 // 2021-01-01
        }
      }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText(/2021/)).toBeInTheDocument()
    })

    it('formats large numbers with locale formatting', () => {
      const report = {
        pe_info: {
          sections: [
            {
              name: '.text',
              virtual_size: 1234567,
              raw_size: 1234567,
              entropy: 6.0,
            }
          ]
        }
      }
      
      render(<AnalysisDisplay report={report} />)
      
      // Should format large numbers with commas
      expect(screen.getByText('1,234,567')).toBeInTheDocument()
    })

    it('handles missing timestamps gracefully', () => {
      const report = {
        pe_info: {
          timestamp: null
        }
      }
      
      render(<AnalysisDisplay report={report} />)
      
      expect(screen.getByText('N/A')).toBeInTheDocument()
    })
  })
})