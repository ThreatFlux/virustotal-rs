import React from 'react'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SigmaRuleViewer } from '../SigmaRuleViewer'

// PrismJS is already mocked globally in test-setup.ts

// Mock clipboard API
Object.assign(navigator, {
  clipboard: {
    writeText: vi.fn().mockImplementation(() => Promise.resolve()),
  },
})

// Mock fetch for GitHub API
global.fetch = vi.fn()

const mockFetch = vi.mocked(fetch)

// Mock window.open
Object.defineProperty(window, 'open', {
  value: vi.fn(),
  writable: true,
})

// Sample Sigma rules for testing
const mockSigmaRules = [
  {
    rule_name: 'Windows_PowerShell_Suspicious_Command',
    author: 'Security Analyst',
    description: 'Detects suspicious PowerShell command execution patterns',
    source: 'https://github.com/sigma-rules/sigma',
    ruleset_name: 'powershell_suspicious',
    ruleset_id: 'sigma-001',
    level: 'high',
    status: 'stable',
    tags: ['attack.execution', 'attack.t1059.001'],
  },
  {
    rule_name: 'Process_Creation_Anomaly',
    author: 'Detection Team',
    description: 'Identifies anomalous process creation patterns',
    source: 'https://github.com/detection-team/sigma-rules',
    ruleset_name: 'process_anomalies',
    ruleset_id: 'sigma-002',
    level: 'medium',
    status: 'test',
    tags: ['attack.defense_evasion'],
  },
  {
    rule_name: 'Network_Connection_Baseline',
    author: 'Network Team',
    description: 'Baseline rule for network connection monitoring',
    source: 'https://github.com/network-team/detection-rules',
    ruleset_name: 'network_baseline',
    ruleset_id: 'sigma-003',
    level: 'informational',
    status: 'stable',
    tags: ['network.monitoring'],
  },
]

const mockCriticalRule = {
  rule_name: 'Critical_Malware_Detection',
  author: 'SOC Team',
  description: 'Detects critical malware attack patterns',
  level: 'critical',
  status: 'stable',
  tags: ['attack.malware', 'attack.persistence'],
}

const sampleSigmaRuleContent = `title: Windows PowerShell Suspicious Command
id: 12345678-1234-1234-1234-123456789012
status: stable
description: Detects suspicious PowerShell command execution patterns
author: Security Analyst
date: 2023/01/01
modified: 2023/12/01
references:
    - https://attack.mitre.org/techniques/T1059/001/
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'IEX'
            - 'DownloadString'
    condition: selection
falsepositives:
    - Legitimate administrative scripts
level: high`

describe('SigmaRuleViewer', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetch.mockClear()
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('Rendering', () => {
    it('renders nothing when no rules provided', () => {
      const { container } = render(<SigmaRuleViewer rules={[]} fileHash="test-hash" />)
      expect(container.firstChild).toBeNull()
    })

    it('renders Sigma rule card with correct title', () => {
      render(<SigmaRuleViewer rules={mockSigmaRules} fileHash="test-hash" />)
      
      expect(screen.getByText('Sigma Rule Detections')).toBeInTheDocument()
      expect(screen.getByText('3 rules')).toBeInTheDocument()
    })

    it('renders single rule with correct count', () => {
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      expect(screen.getByText('1 rule')).toBeInTheDocument()
    })

    it('displays all rule names', () => {
      render(<SigmaRuleViewer rules={mockSigmaRules} fileHash="test-hash" />)
      
      expect(screen.getByText('Windows_PowerShell_Suspicious_Command')).toBeInTheDocument()
      expect(screen.getByText('Process_Creation_Anomaly')).toBeInTheDocument()
      expect(screen.getByText('Network_Connection_Baseline')).toBeInTheDocument()
    })

    it('displays rule metadata when available', () => {
      render(<SigmaRuleViewer rules={mockSigmaRules} fileHash="test-hash" />)
      
      expect(screen.getByText('By: Security Analyst')).toBeInTheDocument()
      expect(screen.getByText('By: Detection Team')).toBeInTheDocument()
      expect(screen.getByText('Detects suspicious PowerShell command execution patterns')).toBeInTheDocument()
    })

    it('displays rule level badges', () => {
      render(<SigmaRuleViewer rules={mockSigmaRules} fileHash="test-hash" />)
      
      expect(screen.getByText('HIGH')).toBeInTheDocument() // high level rule
      expect(screen.getByText('MEDIUM')).toBeInTheDocument() // medium level rule
    })

    it('displays rule tags when available', () => {
      render(<SigmaRuleViewer rules={mockSigmaRules} fileHash="test-hash" />)
      
      expect(screen.getByText('attack.execution')).toBeInTheDocument()
      expect(screen.getByText('attack.t1059.001')).toBeInTheDocument()
      expect(screen.getByText('attack.defense_evasion')).toBeInTheDocument()
    })

    it('limits displayed tags to first 3', () => {
      const ruleWithManyTags = {
        rule_name: 'Rule_With_Many_Tags',
        tags: ['tag1', 'tag2', 'tag3', 'tag4', 'tag5'],
      }
      
      render(<SigmaRuleViewer rules={[ruleWithManyTags]} fileHash="test-hash" />)
      
      expect(screen.getByText('tag1')).toBeInTheDocument()
      expect(screen.getByText('tag2')).toBeInTheDocument()
      expect(screen.getByText('tag3')).toBeInTheDocument()
      expect(screen.queryByText('tag4')).not.toBeInTheDocument()
    })
  })

  describe('Risk Level Classification', () => {
    it('assigns high risk to critical and high level rules', () => {
      const highRiskRules = [
        { rule_name: 'Critical_Rule', level: 'critical' },
        { rule_name: 'High_Rule', level: 'high' },
      ]
      
      render(<SigmaRuleViewer rules={highRiskRules} fileHash="test-hash" />)
      
      const highBadges = screen.getAllByText('HIGH')
      expect(highBadges).toHaveLength(2)
    })

    it('assigns medium risk to medium level rules', () => {
      const mediumRiskRules = [
        { rule_name: 'Medium_Rule', level: 'medium' },
        { rule_name: 'Suspicious_Rule', description: 'Detects suspicious activity' },
      ]
      
      render(<SigmaRuleViewer rules={mediumRiskRules} fileHash="test-hash" />)
      
      const mediumBadges = screen.getAllByText('MEDIUM')
      expect(mediumBadges).toHaveLength(2)
    })

    it('assigns low risk to low and informational level rules', () => {
      const lowRiskRules = [
        { rule_name: 'Low_Rule', level: 'low' },
        { rule_name: 'Info_Rule', level: 'informational' },
      ]
      
      render(<SigmaRuleViewer rules={lowRiskRules} fileHash="test-hash" />)
      
      expect(screen.queryByText('HIGH')).not.toBeInTheDocument()
      expect(screen.queryByText('MEDIUM')).not.toBeInTheDocument()
    })

    it('falls back to name/description analysis for risk level', () => {
      const rulesWithoutLevel = [
        { rule_name: 'Malware_Detection', description: 'Detects malicious activity' },
        { rule_name: 'Attack_Pattern', description: 'Identifies attack patterns' },
        { rule_name: 'Anomaly_Check', description: 'Checks for anomalies' },
      ]
      
      render(<SigmaRuleViewer rules={rulesWithoutLevel} fileHash="test-hash" />)
      
      const highBadges = screen.getAllByText('HIGH')
      expect(highBadges).toHaveLength(2) // malware and attack
      
      const mediumBadges = screen.getAllByText('MEDIUM')
      expect(mediumBadges).toHaveLength(1) // anomaly
    })
  })

  describe('Dialog Interaction', () => {
    it('opens dialog when view rule button is clicked', async () => {
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
        expect(screen.getByText('Windows_PowerShell_Suspicious_Command')).toBeInTheDocument()
      })
    })

    it('displays all rule metadata in dialog', async () => {
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText('Author: Security Analyst')).toBeInTheDocument()
        expect(screen.getByText('Level: high')).toBeInTheDocument()
        expect(screen.getByText('Status: stable')).toBeInTheDocument()
        expect(screen.getByText('Ruleset: powershell_suspicious')).toBeInTheDocument()
      })
    })

    it('applies proper badge variant for rule level', async () => {
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        const levelBadge = screen.getByText('Level: high')
        expect(levelBadge.closest('.badge')).toHaveClass('bg-destructive') // destructive variant
      })
    })
  })

  describe('GitHub Integration', () => {
    it('fetches rule content from GitHub successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleSigmaRuleContent),
      } as Response)
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/title: Windows PowerShell Suspicious Command/)).toBeInTheDocument()
      })
    })

    it('tries multiple Sigma-specific paths', async () => {
      // Mock failed attempts for first few paths, then success
      mockFetch
        .mockResolvedValueOnce({ ok: false, status: 404 } as Response)
        .mockResolvedValueOnce({ ok: false, status: 404 } as Response)
        .mockResolvedValueOnce({ ok: false, status: 404 } as Response)
        .mockResolvedValueOnce({
          ok: true,
          text: () => Promise.resolve(sampleSigmaRuleContent),
        } as Response)
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/title: Windows PowerShell Suspicious Command/)).toBeInTheDocument()
      })
      
      expect(mockFetch).toHaveBeenCalledTimes(4)
    })

    it('extracts specific rule from multi-rule file', async () => {
      const multiRuleContent = `title: First Rule
id: 11111111-1111-1111-1111-111111111111
description: First rule

---

title: Windows PowerShell Suspicious Command
id: 22222222-2222-2222-2222-222222222222
description: Detects suspicious PowerShell command execution patterns

---

title: Third Rule
id: 33333333-3333-3333-3333-333333333333
description: Third rule`
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(multiRuleContent),
      } as Response)
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/title: Windows PowerShell Suspicious Command/)).toBeInTheDocument()
        expect(screen.queryByText('title: First Rule')).not.toBeInTheDocument()
      })
    })

    it('generates placeholder when GitHub fetch fails', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'))
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText('Failed to fetch rule from GitHub')).toBeInTheDocument()
        expect(screen.getByText(/title: Windows_PowerShell_Suspicious_Command/)).toBeInTheDocument()
      })
    })

    it('opens GitHub link when view on GitHub button is clicked', async () => {
      const windowOpenSpy = vi.spyOn(window, 'open').mockImplementation(() => null)
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })
      
      const githubButton = screen.getByText('View on GitHub')
      fireEvent.click(githubButton)
      
      expect(windowOpenSpy).toHaveBeenCalledWith(mockSigmaRules[0].source, '_blank')
    })
  })

  describe('Copy Functionality', () => {
    it('copies rule content to clipboard', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleSigmaRuleContent),
      } as Response)
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/title: Windows PowerShell Suspicious Command/)).toBeInTheDocument()
      })
      
      const copyButton = screen.getByText('Copy Rule')
      fireEvent.click(copyButton)
      
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(sampleSigmaRuleContent)
      
      await waitFor(() => {
        expect(screen.getByText('Copied!')).toBeInTheDocument()
      })
    })

    it('disables copy button when no content is loaded', async () => {
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })
      
      // Initially disabled while loading
      const copyButton = screen.getByRole('button', { name: /copy rule/i })
      expect(copyButton).toBeDisabled()
    })

    it('handles clipboard errors gracefully', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      vi.mocked(navigator.clipboard.writeText).mockRejectedValueOnce(new Error('Clipboard error'))
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleSigmaRuleContent),
      } as Response)
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText('Copy Rule')).toBeInTheDocument()
      })
      
      const copyButton = screen.getByText('Copy Rule')
      fireEvent.click(copyButton)
      
      expect(consoleSpy).toHaveBeenCalledWith('Failed to copy:', expect.any(Error))
      consoleSpy.mockRestore()
    })
  })

  describe('High Risk Warning', () => {
    it('displays warning for critical and high level rules', () => {
      render(<SigmaRuleViewer rules={[mockCriticalRule]} fileHash="test-hash" />)
      
      expect(screen.getByText('HIGH')).toBeInTheDocument()
      expect(screen.getByText(/High-severity Sigma rules detected/)).toBeInTheDocument()
    })

    it('does not display warning for medium and low level rules only', () => {
      const lowRiskRules = [
        { rule_name: 'Info_Rule', level: 'informational' },
        { rule_name: 'Low_Rule', level: 'low' },
      ]
      
      render(<SigmaRuleViewer rules={lowRiskRules} fileHash="test-hash" />)
      
      expect(screen.queryByText(/High-severity Sigma rules detected/)).not.toBeInTheDocument()
    })

    it('displays warning when mixed levels include high risk', () => {
      const mixedRules = [
        mockSigmaRules[1], // medium risk
        mockSigmaRules[2], // low risk
        mockCriticalRule,  // high risk
      ]
      
      render(<SigmaRuleViewer rules={mixedRules} fileHash="test-hash" />)
      
      expect(screen.getByText(/High-severity Sigma rules detected/)).toBeInTheDocument()
    })
  })

  describe('Rule Grouping', () => {
    it('groups rules by source', () => {
      const rulesWithDifferentSources = [
        { rule_name: 'Rule1', source: 'https://github.com/team1/sigma-rules' },
        { rule_name: 'Rule2', source: 'https://github.com/team1/sigma-rules' },
        { rule_name: 'Rule3', source: 'https://github.com/team2/detection-rules' },
      ]
      
      render(<SigmaRuleViewer rules={rulesWithDifferentSources} fileHash="test-hash" />)
      
      expect(screen.getByText('https://github.com/team1/sigma-rules')).toBeInTheDocument()
      expect(screen.getByText('https://github.com/team2/detection-rules')).toBeInTheDocument()
    })

    it('handles rules without source', () => {
      const rulesWithoutSource = [
        { rule_name: 'Rule1' },
        { rule_name: 'Rule2' },
      ]
      
      render(<SigmaRuleViewer rules={rulesWithoutSource} fileHash="test-hash" />)
      
      expect(screen.getByText('Unknown Source')).toBeInTheDocument()
    })
  })

  describe('Placeholder Generation', () => {
    it('generates proper Sigma YAML placeholder', () => {
      const ruleWithoutGithub = {
        rule_name: 'Local_Sigma_Rule',
        author: 'Local Author',
        description: 'Local Sigma rule description',
        level: 'medium',
        status: 'experimental',
        tags: ['custom.tag'],
        source: 'local-repository',
        ruleset_id: 'local-001',
      }
      
      render(<SigmaRuleViewer rules={[ruleWithoutGithub]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      expect(screen.getByText(/title: Local_Sigma_Rule/)).toBeInTheDocument()
      expect(screen.getByText(/author: Local Author/)).toBeInTheDocument()
      expect(screen.getByText(/level: medium/)).toBeInTheDocument()
      expect(screen.getByText(/status: experimental/)).toBeInTheDocument()
    })

    it('handles missing metadata in placeholder', () => {
      const minimalRule = { rule_name: 'Minimal_Rule' }
      
      render(<SigmaRuleViewer rules={[minimalRule]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      expect(screen.getByText(/title: Minimal_Rule/)).toBeInTheDocument()
      expect(screen.getByText(/author: Unknown/)).toBeInTheDocument()
      expect(screen.getByText(/level: medium/)).toBeInTheDocument() // default level
    })
  })

  describe('Loading States', () => {
    it('displays loading spinner while fetching rule content', async () => {
      mockFetch.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 1000)))
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })
      
      expect(document.querySelector('.animate-spin')).toBeInTheDocument()
    })

    it('clears error state when starting new fetch', async () => {
      // First request fails
      mockFetch.mockRejectedValueOnce(new Error('First error'))
      
      render(<SigmaRuleViewer rules={mockSigmaRules} fileHash="test-hash" />)
      
      const firstViewButton = screen.getAllByRole('button', { name: /view rule/i })[0]
      fireEvent.click(firstViewButton)
      
      await waitFor(() => {
        expect(screen.getByText('Failed to fetch rule from GitHub')).toBeInTheDocument()
      })
      
      // Second request succeeds
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleSigmaRuleContent),
      } as Response)
      
      const secondViewButton = screen.getAllByRole('button', { name: /view rule/i })[1]
      fireEvent.click(secondViewButton)
      
      await waitFor(() => {
        expect(screen.queryByText('Failed to fetch rule from GitHub')).not.toBeInTheDocument()
        expect(screen.getByText(/title: Windows PowerShell Suspicious Command/)).toBeInTheDocument()
      })
    })
  })

  describe('Accessibility', () => {
    it('provides proper ARIA labels and roles', () => {
      render(<SigmaRuleViewer rules={mockSigmaRules} fileHash="test-hash" />)
      
      expect(screen.getByRole('heading', { name: /Sigma Rule Detections/ })).toBeInTheDocument()
      
      const viewButtons = screen.getAllByRole('button')
      expect(viewButtons.length).toBe(3) // One for each rule
    })

    it('maintains proper dialog accessibility', async () => {
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        const dialog = screen.getByRole('dialog')
        expect(dialog).toBeInTheDocument()
        expect(dialog).toHaveAttribute('aria-modal', 'true')
      })
      
      // Dialog should have proper heading
      expect(screen.getByRole('heading', { name: 'Windows_PowerShell_Suspicious_Command' })).toBeInTheDocument()
    })

    it('provides descriptive button text for screen readers', () => {
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      expect(screen.getByText('View Rule')).toBeInTheDocument()
    })
  })

  describe('Responsive Design', () => {
    it('adapts layout for mobile screens', () => {
      render(<SigmaRuleViewer rules={mockSigmaRules} fileHash="test-hash" />)
      
      // Should have responsive classes
      const ruleContainers = document.querySelectorAll('.sm\\:flex-row')
      expect(ruleContainers.length).toBeGreaterThan(0)
      
      // Tags should wrap properly
      const tagContainers = document.querySelectorAll('.flex-wrap')
      expect(tagContainers.length).toBeGreaterThan(0)
    })

    it('handles dialog sizing responsively', async () => {
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        const dialogContent = document.querySelector('[role="dialog"]')
        expect(dialogContent).toHaveClass('w-[95vw]', 'max-w-4xl')
      })
    })
  })

  describe('Keyboard Navigation', () => {
    it('supports keyboard navigation for rule buttons', async () => {
      const user = userEvent.setup()
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      
      await user.tab()
      expect(viewButton).toHaveFocus()
      
      await user.keyboard('{Enter}')
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })
    })

    it('supports keyboard navigation within dialog', async () => {
      const user = userEvent.setup()
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleSigmaRuleContent),
      } as Response)
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })
      
      // Should be able to tab to buttons within dialog
      const githubButton = screen.getByText('View on GitHub')
      const copyButton = screen.getByText('Copy Rule')
      
      expect(githubButton).toBeInTheDocument()
      expect(copyButton).toBeInTheDocument()
    })
  })

  describe('Error Handling', () => {
    it('handles non-GitHub sources gracefully', () => {
      const nonGithubRule = {
        rule_name: 'Local_Rule',
        source: 'local-repository',
      }
      
      render(<SigmaRuleViewer rules={[nonGithubRule]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      expect(screen.getByText(/Unable to fetch actual rule content/)).toBeInTheDocument()
    })

    it('handles malformed GitHub URLs', () => {
      const badUrlRule = {
        rule_name: 'Bad_URL_Rule',
        source: 'github.com/incomplete-url',
      }
      
      render(<SigmaRuleViewer rules={[badUrlRule]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      expect(screen.getByText(/Unable to fetch actual rule content/)).toBeInTheDocument()
    })

    it('handles empty fetch responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(''),
      } as Response)
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/Unable to fetch actual rule content/)).toBeInTheDocument()
      })
    })
  })

  describe('Performance', () => {
    it('handles large number of rules efficiently', () => {
      const manyRules = Array.from({ length: 50 }, (_, i) => ({
        rule_name: `Sigma_Rule_${i}`,
        author: `Author ${i}`,
        level: i % 3 === 0 ? 'high' : i % 3 === 1 ? 'medium' : 'low',
        source: `https://github.com/repo${i % 5}/sigma-rules`,
      }))
      
      const { container } = render(<SigmaRuleViewer rules={manyRules} fileHash="test-hash" />)
      
      expect(screen.getByText('50 rules')).toBeInTheDocument()
      expect(container.querySelectorAll('.p-3').length).toBe(50)
    })

    it('efficiently processes rules with many tags', () => {
      const rulesWithManyTags = Array.from({ length: 10 }, (_, i) => ({
        rule_name: `Tagged_Rule_${i}`,
        tags: Array.from({ length: 20 }, (_, j) => `tag.${i}.${j}`),
      }))
      
      render(<SigmaRuleViewer rules={rulesWithManyTags} fileHash="test-hash" />)
      
      // Should only show first 3 tags per rule
      expect(screen.getAllByText(/tag\.0\.0/).length).toBe(1)
      expect(screen.getAllByText(/tag\.0\.1/).length).toBe(1)
      expect(screen.getAllByText(/tag\.0\.2/).length).toBe(1)
      expect(screen.queryByText(/tag\.0\.3/)).not.toBeInTheDocument()
    })
  })

  describe('PrismJS Integration', () => {
    it('highlights Sigma YAML syntax properly', async () => {
      // Clear the mock to track calls from this test
      vi.clearAllMocks()
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleSigmaRuleContent),
      } as Response)
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/title: Windows PowerShell Suspicious Command/)).toBeInTheDocument()
      })
      
      expect(global.Prism.highlightAll).toHaveBeenCalled()
    })

    it('uses sigma language class for syntax highlighting', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleSigmaRuleContent),
      } as Response)
      
      render(<SigmaRuleViewer rules={[mockSigmaRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        const codeElement = document.querySelector('code.language-sigma')
        expect(codeElement).toBeInTheDocument()
      })
    })
  })

  describe('Edge Cases', () => {
    it('handles rules with empty arrays gracefully', () => {
      const ruleWithEmptyArrays = {
        rule_name: 'Empty_Arrays_Rule',
        tags: [],
      }
      
      render(<SigmaRuleViewer rules={[ruleWithEmptyArrays]} fileHash="test-hash" />)
      
      expect(screen.getByText('Empty_Arrays_Rule')).toBeInTheDocument()
      expect(screen.queryByText('tags')).not.toBeInTheDocument()
    })

    it('handles null and undefined values gracefully', () => {
      const ruleWithNulls = {
        rule_name: 'Null_Values_Rule',
        author: null,
        description: undefined,
        tags: null,
      }
      
      render(<SigmaRuleViewer rules={[ruleWithNulls as any]} fileHash="test-hash" />)
      
      expect(screen.getByText('Null_Values_Rule')).toBeInTheDocument()
      expect(screen.queryByText('By:')).not.toBeInTheDocument()
    })
  })
})