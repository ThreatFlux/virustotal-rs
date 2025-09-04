import React from 'react'
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { BrowserRouter } from 'react-router-dom'
import type { Report, OccurrenceData, OccurrenceSearchContext } from '@/types'

// Mock occurrence service at the module level
vi.mock('@/services/occurrence', () => ({
  calculateOccurrenceData: vi.fn(),
  getOccurrenceDescription: vi.fn(),
  getOccurrencePriority: vi.fn(),
}))

// Mock navigation
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: vi.fn(),
  }
})

// Import component after mocks
import { OccurrenceColumn } from '../occurrence-column'
// Import mocked functions for testing
import { calculateOccurrenceData, getOccurrenceDescription, getOccurrencePriority } from '@/services/occurrence'
import { useNavigate } from 'react-router-dom'

const mockCalculateOccurrenceData = vi.mocked(calculateOccurrenceData)
const mockGetOccurrenceDescription = vi.mocked(getOccurrenceDescription)
const mockGetOccurrencePriority = vi.mocked(getOccurrencePriority)
const mockNavigate = vi.mocked(useNavigate)

const mockReport: Report = {
  report_uuid: 'test-uuid-123',
  file_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  meaningful_name: 'test-file.exe',
  upload_timestamp: '2023-01-01T12:00:00Z',
  submitter_country: 'US',
  detection_ratio: {
    malicious: 5,
    suspicious: 2,
    undetected: 63,
    harmless: 0,
  },
}

const mockOccurrenceData: OccurrenceData = {
  file_hash: mockReport.file_hash,
  similar_files_count: 15,
  yara_matches: 3,
  sigma_matches: 2,
  times_submitted: 8,
  first_seen: '2023-01-01T10:00:00Z',
  last_seen: '2023-01-01T15:00:00Z',
  related_campaigns: ['APT29', 'Lazarus'],
  sandbox_analyses: 12,
  unique_submitters: 5,
  submission_countries: ['US', 'DE', 'JP'],
  detection_history: {
    trend: 'increasing',
    first_detection: '2023-01-01T11:00:00Z',
    peak_detections: 8,
  },
}

const renderWithRouter = (component: React.ReactElement) => {
  return render(<BrowserRouter>{component}</BrowserRouter>)
}

describe('OccurrenceColumn', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetOccurrenceDescription.mockReturnValue('High-priority threat with multiple campaign associations')
    mockGetOccurrencePriority.mockReturnValue(75)
  })

  describe('Loading State', () => {
    it('shows loading spinner while fetching data', async () => {
      mockCalculateOccurrenceData.mockImplementation(() => new Promise(() => {})) // Never resolves

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      expect(screen.getByTestId('loader-2')).toBeInTheDocument()
      expect(document.querySelector('.animate-spin')).toBeInTheDocument()
    })

    it('calls calculateOccurrenceData with report on mount', () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      expect(mockCalculateOccurrenceData).toHaveBeenCalledWith(mockReport)
    })

    it('refetches data when report hash changes', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      const { rerender } = renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(mockCalculateOccurrenceData).toHaveBeenCalledTimes(1)
      })

      const newReport = { ...mockReport, file_hash: 'different-hash' }
      rerender(
        <BrowserRouter>
          <OccurrenceColumn report={newReport} />
        </BrowserRouter>
      )

      expect(mockCalculateOccurrenceData).toHaveBeenCalledTimes(2)
      expect(mockCalculateOccurrenceData).toHaveBeenLastCalledWith(newReport)
    })
  })

  describe('Error State', () => {
    it('shows error icon when calculateOccurrenceData fails', async () => {
      mockCalculateOccurrenceData.mockRejectedValue(new Error('Service unavailable'))

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('alert-triangle')).toBeInTheDocument()
      })
    })

    it('shows error tooltip with failure message', async () => {
      mockCalculateOccurrenceData.mockRejectedValue(new Error('Service unavailable'))

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('alert-triangle')).toBeInTheDocument()
      })

      const alertIcon = screen.getByTestId('alert-triangle')
      fireEvent.mouseOver(alertIcon)

      await waitFor(() => {
        expect(screen.getByText('Failed to load occurrence data')).toBeInTheDocument()
      })
    })

    it('shows error when occurrenceData is null', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(null)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('alert-triangle')).toBeInTheDocument()
      })
    })
  })

  describe('Main Indicator Priority', () => {
    it('prioritizes campaigns over other indicators', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('shield')).toBeInTheDocument()
        expect(screen.getByText('2')).toBeInTheDocument() // 2 campaigns
      })
    })

    it('prioritizes rule matches when no campaigns', async () => {
      const dataWithoutCampaigns = { ...mockOccurrenceData, related_campaigns: [] }
      mockCalculateOccurrenceData.mockResolvedValue(dataWithoutCampaigns)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('file-text')).toBeInTheDocument()
        expect(screen.getByText('5')).toBeInTheDocument() // 3 YARA + 2 Sigma
      })
    })

    it('prioritizes similar files when no campaigns or rules', async () => {
      const dataWithSimilarFiles = {
        ...mockOccurrenceData,
        related_campaigns: [],
        yara_matches: 0,
        sigma_matches: 0,
      }
      mockCalculateOccurrenceData.mockResolvedValue(dataWithSimilarFiles)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('users')).toBeInTheDocument()
        expect(screen.getByText('15')).toBeInTheDocument() // similar files count
      })
    })

    it('prioritizes submissions when no other indicators', async () => {
      const dataWithSubmissions = {
        ...mockOccurrenceData,
        related_campaigns: [],
        yara_matches: 0,
        sigma_matches: 0,
        similar_files_count: 1, // Only 1 (itself)
      }
      mockCalculateOccurrenceData.mockResolvedValue(dataWithSubmissions)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('trending-up')).toBeInTheDocument()
        expect(screen.getByText('8')).toBeInTheDocument() // times submitted
      })
    })

    it('shows first seen when no other indicators', async () => {
      const dataFirstSeen = {
        ...mockOccurrenceData,
        related_campaigns: [],
        yara_matches: 0,
        sigma_matches: 0,
        similar_files_count: 1,
        times_submitted: 1,
      }
      mockCalculateOccurrenceData.mockResolvedValue(dataFirstSeen)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('clock')).toBeInTheDocument()
        expect(screen.getByText('0')).toBeInTheDocument()
      })
    })
  })

  describe('Compact Variant', () => {
    it('renders compact variant without dropdown', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} variant="compact" />)

      await waitFor(() => {
        expect(screen.getByTestId('shield')).toBeInTheDocument()
        expect(screen.getByText('2')).toBeInTheDocument()
      })

      // Should not have dropdown chevron
      expect(screen.queryByTestId('chevron-down')).not.toBeInTheDocument()
    })

    it('shows tooltip in compact variant by default', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} variant="compact" />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        fireEvent.mouseOver(button)
      })

      await waitFor(() => {
        expect(screen.getByText('2 campaign(s)')).toBeInTheDocument()
        expect(screen.getByText('High-priority threat with multiple campaign associations')).toBeInTheDocument()
        expect(screen.getByText('Click to search for similar files')).toBeInTheDocument()
      })
    })

    it('hides tooltip when showTooltip is false', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} variant="compact" showTooltip={false} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        fireEvent.mouseOver(button)
      })

      // Tooltip should not appear
      expect(screen.queryByText('2 campaign(s)')).not.toBeInTheDocument()
    })

    it('handles click in compact variant for campaigns', async () => {
      const mockOnSearchTrigger = vi.fn()
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(
        <OccurrenceColumn 
          report={mockReport} 
          variant="compact" 
          onSearchTrigger={mockOnSearchTrigger}
        />
      )

      await waitFor(() => {
        const button = screen.getByRole('button')
        fireEvent.click(button)
      })

      expect(mockOnSearchTrigger).toHaveBeenCalledWith({
        search_type: 'campaign_related',
        base_hash: mockReport.file_hash,
        base_name: mockReport.meaningful_name,
        filters: expect.objectContaining({
          similarity_threshold: 0.7,
          include_suspicious: true,
          min_detections: 1,
        }),
        metadata: {
          display_name: 'Campaign Related Files',
          search_description: 'Files related to campaigns: APT29, Lazarus',
        },
      })
    })

    it('handles click in compact variant for rule matches', async () => {
      const mockOnSearchTrigger = vi.fn()
      const dataWithRules = { ...mockOccurrenceData, related_campaigns: [] }
      mockCalculateOccurrenceData.mockResolvedValue(dataWithRules)

      renderWithRouter(
        <OccurrenceColumn 
          report={mockReport} 
          variant="compact" 
          onSearchTrigger={mockOnSearchTrigger}
        />
      )

      await waitFor(() => {
        const button = screen.getByRole('button')
        fireEvent.click(button)
      })

      expect(mockOnSearchTrigger).toHaveBeenCalledWith({
        search_type: 'yara_matches',
        base_hash: mockReport.file_hash,
        base_name: mockReport.meaningful_name,
        filters: expect.anything(),
        metadata: {
          display_name: 'YARA/Sigma Matches',
          search_description: 'Files matching similar detection rules',
        },
      })
    })

    it('handles click in compact variant for similar files', async () => {
      const mockOnSearchTrigger = vi.fn()
      const dataWithSimilar = {
        ...mockOccurrenceData,
        related_campaigns: [],
        yara_matches: 0,
        sigma_matches: 0,
      }
      mockCalculateOccurrenceData.mockResolvedValue(dataWithSimilar)

      renderWithRouter(
        <OccurrenceColumn 
          report={mockReport} 
          variant="compact" 
          onSearchTrigger={mockOnSearchTrigger}
        />
      )

      await waitFor(() => {
        const button = screen.getByRole('button')
        fireEvent.click(button)
      })

      expect(mockOnSearchTrigger).toHaveBeenCalledWith({
        search_type: 'similar_files',
        base_hash: mockReport.file_hash,
        base_name: mockReport.meaningful_name,
        filters: expect.anything(),
        metadata: {
          display_name: 'Similar Files',
          search_description: 'Files similar to test-file.exe',
        },
      })
    })
  })

  describe('Full Variant (Default)', () => {
    it('renders dropdown menu with chevron', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('chevron-down')).toBeInTheDocument()
      })
    })

    it('opens dropdown menu on click', async () => {
      const user = userEvent.setup()
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        expect(screen.getByText(`Occurrence Data for ${mockReport.meaningful_name}`)).toBeInTheDocument()
      })
    })

    it('shows all available search options in dropdown', async () => {
      const user = userEvent.setup()
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        expect(screen.getByText('Similar Files')).toBeInTheDocument()
        expect(screen.getByText('Rule Matches')).toBeInTheDocument()
        expect(screen.getByText('Campaign Related')).toBeInTheDocument()
        expect(screen.getByText('Similar Behavior')).toBeInTheDocument()
        expect(screen.getByText('Submitted 8 times')).toBeInTheDocument()
      })
    })

    it('shows detailed information for each option', async () => {
      const user = userEvent.setup()
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        expect(screen.getByText('15 files found')).toBeInTheDocument()
        expect(screen.getByText('3 YARA, 2 Sigma')).toBeInTheDocument()
        expect(screen.getByText('2 campaign(s)')).toBeInTheDocument()
        expect(screen.getByText('12 analyses')).toBeInTheDocument()
      })
    })

    it('handles dropdown menu item clicks', async () => {
      const user = userEvent.setup()
      const mockOnSearchTrigger = vi.fn()
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(
        <OccurrenceColumn 
          report={mockReport} 
          onSearchTrigger={mockOnSearchTrigger}
        />
      )

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        const similarFilesItem = screen.getByText('Similar Files')
        return user.click(similarFilesItem)
      })

      expect(mockOnSearchTrigger).toHaveBeenCalledWith({
        search_type: 'similar_files',
        base_hash: mockReport.file_hash,
        base_name: mockReport.meaningful_name,
        filters: expect.anything(),
        metadata: {
          display_name: 'Similar Files',
          search_description: `Files similar to ${mockReport.file_hash}`,
        },
      })
    })

    it('only shows dropdown items for available data', async () => {
      const user = userEvent.setup()
      const limitedData: OccurrenceData = {
        file_hash: mockReport.file_hash,
        similar_files_count: 1, // Only itself
        yara_matches: 0,
        sigma_matches: 0,
        times_submitted: 3,
        first_seen: '2023-01-01T10:00:00Z',
        last_seen: '2023-01-01T15:00:00Z',
        related_campaigns: [],
        sandbox_analyses: 0,
        unique_submitters: 1,
        submission_countries: ['US'],
        detection_history: {
          trend: 'stable',
          first_detection: '2023-01-01T11:00:00Z',
          peak_detections: 1,
        },
      }
      mockCalculateOccurrenceData.mockResolvedValue(limitedData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        // Only submission info should be shown
        expect(screen.getByText('Submitted 3 times')).toBeInTheDocument()
        
        // Other options should not be present
        expect(screen.queryByText('Similar Files')).not.toBeInTheDocument()
        expect(screen.queryByText('Rule Matches')).not.toBeInTheDocument()
        expect(screen.queryByText('Campaign Related')).not.toBeInTheDocument()
        expect(screen.queryByText('Similar Behavior')).not.toBeInTheDocument()
      })
    })
  })

  describe('High Priority Badge', () => {
    it('shows high priority badge when priority > 50', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)
      mockGetOccurrencePriority.mockReturnValue(75) // High priority

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByText('High')).toBeInTheDocument()
      })
    })

    it('hides priority badge when priority <= 50', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)
      mockGetOccurrencePriority.mockReturnValue(30) // Low priority

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.queryByText('High')).not.toBeInTheDocument()
      })
    })

    it('does not show priority badge in compact variant', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)
      mockGetOccurrencePriority.mockReturnValue(75)

      renderWithRouter(<OccurrenceColumn report={mockReport} variant="compact" />)

      await waitFor(() => {
        expect(screen.queryByText('High')).not.toBeInTheDocument()
      })
    })
  })

  describe('Navigation Integration', () => {
    it('navigates to search page when no onSearchTrigger provided', async () => {
      const user = userEvent.setup()
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        const similarFilesItem = screen.getByText('Similar Files')
        return user.click(similarFilesItem)
      })

      expect(mockNavigate).toHaveBeenCalledWith(
        expect.stringContaining('/search?occurrence_search=')
      )

      // Verify the search parameters are encoded correctly
      const callArgs = mockNavigate.mock.calls[0][0] as string
      expect(callArgs).toMatch(/\/search\?occurrence_search=/)
    })

    it('encodes search context properly in URL', async () => {
      const user = userEvent.setup()
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        const campaignItem = screen.getByText('Campaign Related')
        return user.click(campaignItem)
      })

      const callArgs = mockNavigate.mock.calls[0][0] as string
      expect(callArgs).toContain('/search?occurrence_search=')
      
      // Extract and decode the search parameter
      const urlParams = new URLSearchParams(callArgs.split('?')[1])
      const encodedSearch = urlParams.get('occurrence_search')
      expect(encodedSearch).toBeTruthy()
      
      const decodedSearch = JSON.parse(decodeURIComponent(encodedSearch!))
      expect(decodedSearch.search_type).toBe('campaign_related')
      expect(decodedSearch.base_hash).toBe(mockReport.file_hash)
    })
  })

  describe('Date Formatting', () => {
    it('formats first seen date correctly', async () => {
      const user = userEvent.setup()
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        const firstSeenDate = new Date(mockOccurrenceData.first_seen).toLocaleDateString()
        expect(screen.getByText(`First: ${firstSeenDate}`)).toBeInTheDocument()
      })
    })
  })

  describe('Error Handling', () => {
    it('handles string errors from service', async () => {
      mockCalculateOccurrenceData.mockRejectedValue('Service error')

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('alert-triangle')).toBeInTheDocument()
      })
    })

    it('handles unknown errors gracefully', async () => {
      mockCalculateOccurrenceData.mockRejectedValue(null)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('alert-triangle')).toBeInTheDocument()
      })
    })

    it('logs errors to console', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      const testError = new Error('Test error')
      mockCalculateOccurrenceData.mockRejectedValue(testError)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalledWith('Error loading occurrence data:', testError)
      })

      consoleSpy.mockRestore()
    })
  })

  describe('Report Fallbacks', () => {
    it('handles report without meaningful_name', async () => {
      const user = userEvent.setup()
      const reportWithoutName = { ...mockReport, meaningful_name: undefined }
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={reportWithoutName} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        expect(screen.getByText('Occurrence Data for File')).toBeInTheDocument()
      })
    })

    it('uses file hash when meaningful_name is not available for search description', async () => {
      const user = userEvent.setup()
      const mockOnSearchTrigger = vi.fn()
      const reportWithoutName = { ...mockReport, meaningful_name: undefined }
      const dataWithSimilar = {
        ...mockOccurrenceData,
        related_campaigns: [],
        yara_matches: 0,
        sigma_matches: 0,
      }
      mockCalculateOccurrenceData.mockResolvedValue(dataWithSimilar)

      renderWithRouter(
        <OccurrenceColumn 
          report={reportWithoutName} 
          onSearchTrigger={mockOnSearchTrigger}
        />
      )

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        const similarFilesItem = screen.getByText('Similar Files')
        return user.click(similarFilesItem)
      })

      expect(mockOnSearchTrigger).toHaveBeenCalledWith({
        search_type: 'similar_files',
        base_hash: reportWithoutName.file_hash,
        base_name: undefined,
        filters: expect.anything(),
        metadata: {
          display_name: 'Similar Files',
          search_description: `Files similar to ${reportWithoutName.file_hash}`,
        },
      })
    })
  })

  describe('Accessibility', () => {
    it('provides proper button roles', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        expect(button).toBeInTheDocument()
      })
    })

    it('supports keyboard navigation', async () => {
      const user = userEvent.setup()
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        button.focus()
        expect(button).toHaveFocus()
      })

      // Should be able to activate with keyboard
      await user.keyboard('{Enter}')

      await waitFor(() => {
        expect(screen.getByText(`Occurrence Data for ${mockReport.meaningful_name}`)).toBeInTheDocument()
      })
    })

    it('provides meaningful tooltips', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      renderWithRouter(<OccurrenceColumn report={mockReport} variant="compact" />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        fireEvent.mouseOver(button)
      })

      await waitFor(() => {
        expect(screen.getByText('2 campaign(s)')).toBeInTheDocument()
        expect(screen.getByText(/High-priority threat/)).toBeInTheDocument()
      })
    })
  })

  describe('Performance', () => {
    it('handles large campaign lists efficiently', async () => {
      const user = userEvent.setup()
      const manyCampaigns = Array.from({ length: 20 }, (_, i) => `Campaign${i}`)
      const dataWithManyCampaigns = { ...mockOccurrenceData, related_campaigns: manyCampaigns }
      mockCalculateOccurrenceData.mockResolvedValue(dataWithManyCampaigns)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        expect(screen.getByText('20 campaign(s)')).toBeInTheDocument()
      })
    })

    it('efficiently updates when report UUID changes', async () => {
      mockCalculateOccurrenceData.mockResolvedValue(mockOccurrenceData)

      const { rerender } = renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(mockCalculateOccurrenceData).toHaveBeenCalledTimes(1)
      })

      // Change report UUID (should trigger refetch due to dependencies)
      const newReport = { ...mockReport, report_uuid: 'new-uuid' }
      rerender(
        <BrowserRouter>
          <OccurrenceColumn report={newReport} />
        </BrowserRouter>
      )

      // Should still only be called once since file_hash didn't change
      expect(mockCalculateOccurrenceData).toHaveBeenCalledTimes(1)
    })
  })

  describe('Edge Cases', () => {
    it('handles zero values gracefully', async () => {
      const zeroData: OccurrenceData = {
        file_hash: mockReport.file_hash,
        similar_files_count: 0,
        yara_matches: 0,
        sigma_matches: 0,
        times_submitted: 0,
        first_seen: '2023-01-01T10:00:00Z',
        last_seen: '2023-01-01T10:00:00Z',
        related_campaigns: [],
        sandbox_analyses: 0,
        unique_submitters: 0,
        submission_countries: [],
        detection_history: {
          trend: 'stable',
          first_detection: '',
          peak_detections: 0,
        },
      }
      mockCalculateOccurrenceData.mockResolvedValue(zeroData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        expect(screen.getByTestId('clock')).toBeInTheDocument()
        expect(screen.getByText('0')).toBeInTheDocument()
      })
    })

    it('handles malformed occurrence data', async () => {
      const malformedData = {
        file_hash: mockReport.file_hash,
        similar_files_count: null,
        yara_matches: undefined,
        sigma_matches: 'not-a-number',
        related_campaigns: null,
      } as any

      mockCalculateOccurrenceData.mockResolvedValue(malformedData)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        // Should not crash and show some indicator
        expect(screen.getByRole('button')).toBeInTheDocument()
      })
    })

    it('handles very long campaign names', async () => {
      const user = userEvent.setup()
      const longCampaigns = ['Very_Long_Campaign_Name_That_Might_Cause_Layout_Issues_In_UI_Components']
      const dataWithLongCampaigns = { ...mockOccurrenceData, related_campaigns: longCampaigns }
      mockCalculateOccurrenceData.mockResolvedValue(dataWithLongCampaigns)

      renderWithRouter(<OccurrenceColumn report={mockReport} />)

      await waitFor(() => {
        const button = screen.getByRole('button')
        return user.click(button)
      })

      await waitFor(() => {
        expect(screen.getByText(/Very_Long_Campaign_Name/)).toBeInTheDocument()
      })
    })
  })
})