import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import { Summary } from '../Summary';
import * as elasticsearchService from '@/services/elasticsearch';

// Mock the elasticsearch service
vi.mock('@/services/elasticsearch', () => ({
  getDashboardStats: vi.fn(),
  fetchReports: vi.fn(),
  searchReports: vi.fn(),
}));

const mockDashboardStats = {
  total_reports: 1000,
  reports_today: 50,
  malicious_files: 200,
  suspicious_files: 150,
  clean_files: 500,
  undetected_files: 150,
  top_file_types: [
    { type: 'PE32', count: 300 },
    { type: 'PDF', count: 200 },
  ],
  detection_trends: [
    {
      date: '2023-01-01',
      malicious: 10,
      suspicious: 5,
      clean: 20,
      undetected: 8,
    },
  ],
  top_engines: [
    { engine: 'Kaspersky', detections: 100 },
    { engine: 'Bitdefender', detections: 95 },
  ],
  file_size_distribution: [
    { range: '0-1MB', count: 500 },
    { range: '1-10MB', count: 400 },
  ],
};

const mockReports = {
  reports: [
    {
      report_uuid: 'test-uuid-1',
      file_hash: 'abcd1234',
      sha256: 'abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
      meaningful_name: 'test-file.exe',
      names: ['test-file.exe'],
      type_description: 'PE32 executable',
      size: 1024000,
      last_analysis_stats: {
        malicious: 5,
        suspicious: 2,
        harmless: 10,
        undetected: 8,
      },
      last_analysis_date: '2023-12-01T10:00:00Z',
      index_time: '2023-12-01T10:00:00Z',
    },
    {
      report_uuid: 'test-uuid-2',
      file_hash: 'efgh5678',
      sha256: 'efgh5678901234abcdef5678901234abcdef5678901234abcdef5678901234ef',
      meaningful_name: 'document.pdf',
      names: ['document.pdf'],
      type_description: 'PDF document',
      size: 512000,
      last_analysis_stats: {
        malicious: 0,
        suspicious: 1,
        harmless: 15,
        undetected: 9,
      },
      last_analysis_date: '2023-12-01T11:00:00Z',
      index_time: '2023-12-01T11:00:00Z',
    },
  ],
  total: 2,
  page: 1,
  per_page: 20,
  total_pages: 1,
};

const renderSummary = () => {
  return render(
    <BrowserRouter>
      <Summary />
    </BrowserRouter>
  );
};

describe('Summary Page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the summary page with header', async () => {
    // Mock successful API responses
    vi.mocked(elasticsearchService.getDashboardStats).mockResolvedValue({
      success: true,
      data: mockDashboardStats,
    });

    vi.mocked(elasticsearchService.fetchReports).mockResolvedValue({
      success: true,
      data: mockReports,
    });

    renderSummary();

    // Check if the main header is rendered
    expect(screen.getByText('Security Summary')).toBeInTheDocument();
    expect(screen.getByText('Rule detections and threat indicators overview')).toBeInTheDocument();
  });

  it('displays loading state initially', () => {
    vi.mocked(elasticsearchService.getDashboardStats).mockImplementation(
      () => new Promise(() => {}) // Never resolves to keep loading state
    );
    
    vi.mocked(elasticsearchService.fetchReports).mockImplementation(
      () => new Promise(() => {})
    );

    renderSummary();

    // Check for loading indicators in stats cards
    expect(screen.getAllByText('...')).toBeTruthy();
  });

  it('displays error state when API fails', async () => {
    vi.mocked(elasticsearchService.getDashboardStats).mockResolvedValue({
      success: false,
      error: 'Failed to connect to Elasticsearch',
    });

    vi.mocked(elasticsearchService.fetchReports).mockResolvedValue({
      success: false,
      error: 'Connection error',
    });

    renderSummary();

    await waitFor(() => {
      expect(screen.getByText('Error loading summary')).toBeInTheDocument();
      expect(screen.getByText('Failed to connect to Elasticsearch')).toBeInTheDocument();
    });
  });

  it('displays stats cards with correct data', async () => {
    vi.mocked(elasticsearchService.getDashboardStats).mockResolvedValue({
      success: true,
      data: mockDashboardStats,
    });

    vi.mocked(elasticsearchService.fetchReports).mockResolvedValue({
      success: true,
      data: mockReports,
    });

    renderSummary();

    await waitFor(() => {
      expect(screen.getByText('Total Reports')).toBeInTheDocument();
      expect(screen.getByText('1,000')).toBeInTheDocument();
      expect(screen.getByText('Reports Today')).toBeInTheDocument();
      expect(screen.getByText('50')).toBeInTheDocument();
      expect(screen.getByText('Malicious Files')).toBeInTheDocument();
      expect(screen.getByText('200')).toBeInTheDocument();
    });
  });

  it('displays rule detections section', async () => {
    vi.mocked(elasticsearchService.getDashboardStats).mockResolvedValue({
      success: true,
      data: mockDashboardStats,
    });

    vi.mocked(elasticsearchService.fetchReports).mockResolvedValue({
      success: true,
      data: mockReports,
    });

    renderSummary();

    await waitFor(() => {
      expect(screen.getByText('Recent Rule Detections')).toBeInTheDocument();
    });
  });

  it('displays malicious indicators section', async () => {
    vi.mocked(elasticsearchService.getDashboardStats).mockResolvedValue({
      success: true,
      data: mockDashboardStats,
    });

    vi.mocked(elasticsearchService.fetchReports).mockResolvedValue({
      success: true,
      data: mockReports,
    });

    renderSummary();

    await waitFor(() => {
      expect(screen.getByText('Recent Malicious Indicators')).toBeInTheDocument();
    });
  });

  it('displays quick actions section with correct links', async () => {
    vi.mocked(elasticsearchService.getDashboardStats).mockResolvedValue({
      success: true,
      data: mockDashboardStats,
    });

    vi.mocked(elasticsearchService.fetchReports).mockResolvedValue({
      success: true,
      data: mockReports,
    });

    renderSummary();

    await waitFor(() => {
      expect(screen.getByText('Browse All Reports')).toBeInTheDocument();
      expect(screen.getByText('Advanced Search')).toBeInTheDocument();
      expect(screen.getByText('Analytics Dashboard')).toBeInTheDocument();
    });

    // Check if the links have correct hrefs
    const analyticsLink = screen.getByText('Analytics Dashboard').closest('a');
    expect(analyticsLink).toHaveAttribute('href', '/analytics');

    const reportsLink = screen.getByText('Browse All Reports').closest('a');
    expect(reportsLink).toHaveAttribute('href', '/reports');

    const searchLink = screen.getByText('Advanced Search').closest('a');
    expect(searchLink).toHaveAttribute('href', '/search');
  });

  it('shows appropriate message when no rule detections are available', async () => {
    vi.mocked(elasticsearchService.getDashboardStats).mockResolvedValue({
      success: true,
      data: mockDashboardStats,
    });

    // Mock empty reports response
    vi.mocked(elasticsearchService.fetchReports).mockResolvedValue({
      success: true,
      data: {
        ...mockReports,
        reports: [],
      },
    });

    renderSummary();

    await waitFor(() => {
      expect(screen.getByText('No recent rule detections')).toBeInTheDocument();
      expect(screen.getByText('New rule matches will appear here')).toBeInTheDocument();
    });
  });

  it('shows appropriate message when no malicious indicators are found', async () => {
    vi.mocked(elasticsearchService.getDashboardStats).mockResolvedValue({
      success: true,
      data: mockDashboardStats,
    });

    // Mock reports without malicious stats
    const cleanReports = {
      ...mockReports,
      reports: mockReports.reports.map(report => ({
        ...report,
        last_analysis_stats: {
          malicious: 0,
          suspicious: 0,
          harmless: 15,
          undetected: 10,
        },
      })),
    };

    vi.mocked(elasticsearchService.fetchReports).mockResolvedValue({
      success: true,
      data: cleanReports,
    });

    renderSummary();

    await waitFor(() => {
      expect(screen.getByText('No recent malicious indicators')).toBeInTheDocument();
      expect(screen.getByText('This is good news! No high-risk files detected recently')).toBeInTheDocument();
    });
  });
});