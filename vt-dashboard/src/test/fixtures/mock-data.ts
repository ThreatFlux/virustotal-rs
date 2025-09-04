import type { 
  Report, 
  AnalysisResult, 
  SandboxVerdict, 
  CrowdsourcedData, 
  Relationship,
  DashboardStats,
  FileAnalysis
} from '@/types'

// Helper to generate dates
const generateDate = (daysAgo: number = 0) => {
  const date = new Date()
  date.setDate(date.getDate() - daysAgo)
  return date.toISOString()
}

// Mock Reports
export const mockReports: Report[] = [
  {
    report_uuid: 'uuid-001',
    sha256: '5d41402abc4b2a76b9719d911017c592',
    sha1: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
    md5: '5d41402abc4b2a76b9719d911017c592',
    file_size: 1024576,
    file_name: 'malicious.exe',
    file_type: 'PE32',
    first_submission_date: generateDate(10),
    last_submission_date: generateDate(1),
    last_analysis_date: generateDate(1),
    times_submitted: 5,
    reputation: -100,
    community_score: 2,
    harmless: 5,
    malicious: 15,
    suspicious: 3,
    timeout: 0,
    type_unsupported: 1,
    undetected: 40,
    magic: 'PE32 executable',
    ssdeep: '12288:abc123',
    tlsh: 'T1ABC123',
    vhash: '01abc123',
    authentihash: 'auth123',
    imphash: 'imp123',
    created_at: generateDate(10),
    updated_at: generateDate(1),
  },
  {
    report_uuid: 'uuid-002',
    sha256: '7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730',
    sha1: 'b89eaac7e61417341b710b727768294d0e6a277b',
    md5: '7d865e959b2466918c9863afca942d0f',
    file_size: 2048000,
    file_name: 'document.pdf',
    file_type: 'PDF',
    first_submission_date: generateDate(5),
    last_submission_date: generateDate(0),
    last_analysis_date: generateDate(0),
    times_submitted: 2,
    reputation: 50,
    community_score: 8,
    harmless: 45,
    malicious: 0,
    suspicious: 2,
    timeout: 1,
    type_unsupported: 0,
    undetected: 15,
    magic: 'PDF document',
    ssdeep: '24576:def456',
    tlsh: 'T2DEF456',
    vhash: '02def456',
    authentihash: 'auth456',
    imphash: 'imp456',
    created_at: generateDate(5),
    updated_at: generateDate(0),
  },
  {
    report_uuid: 'uuid-003',
    sha256: '3b4c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c',
    sha1: 'c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3',
    md5: '3b4c4d5e6f7a8b9c0d1e2f3a4b5c6d7e',
    file_size: 512000,
    file_name: 'suspicious.zip',
    file_type: 'ZIP',
    first_submission_date: generateDate(3),
    last_submission_date: generateDate(0),
    last_analysis_date: generateDate(0),
    times_submitted: 1,
    reputation: -20,
    community_score: 4,
    harmless: 20,
    malicious: 5,
    suspicious: 10,
    timeout: 0,
    type_unsupported: 0,
    undetected: 30,
    magic: 'Zip archive data',
    ssdeep: '6144:ghi789',
    tlsh: 'T3GHI789',
    vhash: '03ghi789',
    authentihash: 'auth789',
    imphash: 'imp789',
    created_at: generateDate(3),
    updated_at: generateDate(0),
  },
]

// Mock Analysis Results
export const mockAnalysisResults: AnalysisResult[] = [
  {
    id: 'analysis-001',
    report_uuid: 'uuid-001',
    engine_name: 'Microsoft',
    engine_version: '1.1.23060.2',
    engine_update: '20231201',
    category: 'malicious',
    result: 'Trojan:Win32/Malware.Gen',
    method: 'heuristic',
    created_at: generateDate(1),
    updated_at: generateDate(1),
  },
  {
    id: 'analysis-002',
    report_uuid: 'uuid-001',
    engine_name: 'Kaspersky',
    engine_version: '22.0.1.28',
    engine_update: '20231201',
    category: 'malicious',
    result: 'HEUR:Trojan-Downloader.Win32.Generic',
    method: 'signature',
    created_at: generateDate(1),
    updated_at: generateDate(1),
  },
  {
    id: 'analysis-003',
    report_uuid: 'uuid-001',
    engine_name: 'BitDefender',
    engine_version: '7.90123',
    engine_update: '20231201',
    category: 'suspicious',
    result: 'Gen:Variant.Graftor.123456',
    method: 'cloud',
    created_at: generateDate(1),
    updated_at: generateDate(1),
  },
  {
    id: 'analysis-004',
    report_uuid: 'uuid-002',
    engine_name: 'Microsoft',
    engine_version: '1.1.23060.2',
    engine_update: '20231201',
    category: 'undetected',
    result: null,
    method: 'signature',
    created_at: generateDate(0),
    updated_at: generateDate(0),
  },
  {
    id: 'analysis-005',
    report_uuid: 'uuid-003',
    engine_name: 'Kaspersky',
    engine_version: '22.0.1.28',
    engine_update: '20231201',
    category: 'suspicious',
    result: 'UDS:DangerousObject.Multi.Generic',
    method: 'heuristic',
    created_at: generateDate(0),
    updated_at: generateDate(0),
  },
]

// Mock Sandbox Verdicts
export const mockSandboxVerdicts: SandboxVerdict[] = [
  {
    id: 'sandbox-001',
    report_uuid: 'uuid-001',
    sandbox_name: 'Microsoft Sysinternals',
    category: 'malicious',
    confidence: 95,
    malware_classification: ['trojan', 'downloader'],
    malware_names: ['TrojanDownloader:Win32/Tnega!rfn'],
    created_at: generateDate(1),
    updated_at: generateDate(1),
  },
  {
    id: 'sandbox-002',
    report_uuid: 'uuid-001',
    sandbox_name: 'VMRay',
    category: 'malicious',
    confidence: 88,
    malware_classification: ['trojan'],
    malware_names: ['Trojan.GenKryptor.6'],
    created_at: generateDate(1),
    updated_at: generateDate(1),
  },
  {
    id: 'sandbox-003',
    report_uuid: 'uuid-002',
    sandbox_name: 'Microsoft Sysinternals',
    category: 'clean',
    confidence: 90,
    malware_classification: [],
    malware_names: [],
    created_at: generateDate(0),
    updated_at: generateDate(0),
  },
]

// Mock Crowdsourced Data (YARA Rules)
export const mockCrowdsourcedData: CrowdsourcedData[] = [
  {
    id: 'crowd-001',
    report_uuid: 'uuid-001',
    source: 'YARA',
    positives: 8,
    total: 10,
    rule_name: 'Win32_Trojan_Generic',
    author: 'Malware Research Team',
    ruleset_name: 'Generic Malware Rules',
    ruleset_id: 'ruleset-001',
    match_count: 5,
    created_at: generateDate(1),
    updated_at: generateDate(1),
  },
  {
    id: 'crowd-002',
    report_uuid: 'uuid-001',
    source: 'YARA',
    positives: 6,
    total: 8,
    rule_name: 'Downloader_Behavior',
    author: 'Security Researcher',
    ruleset_name: 'Behavior Analysis Rules',
    ruleset_id: 'ruleset-002',
    match_count: 3,
    created_at: generateDate(1),
    updated_at: generateDate(1),
  },
  {
    id: 'crowd-003',
    report_uuid: 'uuid-003',
    source: 'YARA',
    positives: 4,
    total: 12,
    rule_name: 'Suspicious_Archive',
    author: 'Community Contributor',
    ruleset_name: 'Archive Analysis Rules',
    ruleset_id: 'ruleset-003',
    match_count: 2,
    created_at: generateDate(0),
    updated_at: generateDate(0),
  },
]

// Mock Relationships
export const mockRelationships: Relationship[] = [
  {
    id: 'rel-001',
    report_uuid: 'uuid-001',
    relation_type: 'drops',
    target_id: 'file-abc123',
    target_type: 'file',
    context: 'Runtime behavior analysis',
    created_at: generateDate(1),
    updated_at: generateDate(1),
  },
  {
    id: 'rel-002',
    report_uuid: 'uuid-001',
    relation_type: 'communicates_with',
    target_id: 'ip-192.168.1.100',
    target_type: 'ip_address',
    context: 'Network communication',
    created_at: generateDate(1),
    updated_at: generateDate(1),
  },
  {
    id: 'rel-003',
    report_uuid: 'uuid-003',
    relation_type: 'contains',
    target_id: 'file-def456',
    target_type: 'file',
    context: 'Archive content analysis',
    created_at: generateDate(0),
    updated_at: generateDate(0),
  },
]

// Mock Dashboard Stats
export const mockDashboardStats: DashboardStats = {
  total_reports: 369,
  reports_today: 12,
  malicious_files: 87,
  clean_files: 195,
  suspicious_files: 45,
  undetected_files: 42,
  top_file_types: [
    { type: 'PE32', count: 156 },
    { type: 'PDF', count: 89 },
    { type: 'ZIP', count: 67 },
    { type: 'DOC', count: 34 },
    { type: 'XLS', count: 23 },
  ],
  detection_trends: Array.from({ length: 7 }, (_, i) => ({
    date: generateDate(6 - i).split('T')[0],
    malicious: Math.floor(Math.random() * 20) + 5,
    suspicious: Math.floor(Math.random() * 15) + 3,
    clean: Math.floor(Math.random() * 30) + 10,
    undetected: Math.floor(Math.random() * 25) + 8,
  })),
  top_engines: [
    { engine: 'Microsoft', detections: 145 },
    { engine: 'Kaspersky', detections: 132 },
    { engine: 'BitDefender', detections: 128 },
    { engine: 'Avast', detections: 121 },
    { engine: 'ESET', detections: 119 },
  ],
  file_size_distribution: [
    { range: '0-1MB', count: 123 },
    { range: '1-10MB', count: 156 },
    { range: '10-100MB', count: 67 },
    { range: '100MB+', count: 23 },
  ],
}

// Mock File Analysis (Combined data)
export const mockFileAnalysis: FileAnalysis = {
  report: mockReports[0],
  analysis_results: mockAnalysisResults.filter(result => result.report_uuid === 'uuid-001'),
  sandbox_verdicts: mockSandboxVerdicts.filter(verdict => verdict.report_uuid === 'uuid-001'),
  crowdsourced_data: mockCrowdsourcedData.filter(data => data.report_uuid === 'uuid-001'),
  relationships: mockRelationships.filter(rel => rel.report_uuid === 'uuid-001'),
  risk_score: {
    score: 85,
    level: 'Critical',
  },
}

// Factory functions for creating test data
export const createMockReport = (overrides: Partial<Report> = {}): Report => ({
  ...mockReports[0],
  report_uuid: `uuid-${Date.now()}`,
  sha256: `${Date.now().toString(16).padStart(64, '0')}`,
  ...overrides,
})

export const createMockAnalysisResult = (overrides: Partial<AnalysisResult> = {}): AnalysisResult => ({
  ...mockAnalysisResults[0],
  id: `analysis-${Date.now()}`,
  ...overrides,
})

export const createMockSandboxVerdict = (overrides: Partial<SandboxVerdict> = {}): SandboxVerdict => ({
  ...mockSandboxVerdicts[0],
  id: `sandbox-${Date.now()}`,
  ...overrides,
})

export const createMockCrowdsourcedData = (overrides: Partial<CrowdsourcedData> = {}): CrowdsourcedData => ({
  ...mockCrowdsourcedData[0],
  id: `crowd-${Date.now()}`,
  ...overrides,
})

export const createMockRelationship = (overrides: Partial<Relationship> = {}): Relationship => ({
  ...mockRelationships[0],
  id: `rel-${Date.now()}`,
  ...overrides,
})

// Test data for specific scenarios
export const getMaliciousReport = (): Report => 
  createMockReport({ 
    malicious: 25, 
    suspicious: 5, 
    harmless: 10, 
    undetected: 20,
    reputation: -150 
  })

export const getCleanReport = (): Report => 
  createMockReport({ 
    malicious: 0, 
    suspicious: 1, 
    harmless: 50, 
    undetected: 9,
    reputation: 80 
  })

export const getSuspiciousReport = (): Report => 
  createMockReport({ 
    malicious: 3, 
    suspicious: 12, 
    harmless: 25, 
    undetected: 20,
    reputation: -30 
  })

// Chart data for testing
export const mockChartData = [
  { name: 'Malicious', value: 87, color: '#ef4444' },
  { name: 'Suspicious', value: 45, color: '#f97316' },
  { name: 'Clean', value: 195, color: '#22c55e' },
  { name: 'Undetected', value: 42, color: '#6b7280' },
]

export const mockTrendData = mockDashboardStats.detection_trends.map(trend => ({
  date: trend.date,
  Malicious: trend.malicious,
  Suspicious: trend.suspicious,
  Clean: trend.clean,
  Undetected: trend.undetected,
}))