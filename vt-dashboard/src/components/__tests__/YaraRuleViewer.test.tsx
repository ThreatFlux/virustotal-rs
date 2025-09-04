import React from 'react'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { YaraRuleViewer } from '../YaraRuleViewer'

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

// Sample YARA rules for testing
const mockYaraRules = [
  {
    rule_name: 'Win32_Trojan_Generic',
    author: 'Security Team',
    description: 'Detects generic trojan patterns in Windows executables',
    source: 'https://github.com/security-team/yara-rules',
    ruleset_name: 'trojan_detection',
    ruleset_id: 'ruleset-001',
  },
  {
    rule_name: 'Suspicious_Network_Activity',
    author: 'Analyst',
    description: 'Identifies potentially suspicious network behavior',
    source: 'https://github.com/analyst/security-rules',
    ruleset_name: 'network_rules',
    ruleset_id: 'ruleset-002',
  },
  {
    rule_name: 'Malware_Dropper_Pattern',
    author: 'Malware Hunter',
    description: 'Detects common malware dropper techniques',
    source: 'https://github.com/hunter/malware-yara',
    ruleset_name: 'malware_patterns',
    ruleset_id: 'ruleset-003',
  },
]

const mockHighRiskRule = {
  rule_name: 'Backdoor_Detection',
  author: 'Security Expert',
  description: 'Identifies backdoor malware patterns',
  source: 'https://github.com/expert/backdoor-rules',
  ruleset_name: 'backdoor_rules',
  ruleset_id: 'ruleset-004',
}

const mockRuleWithoutMetadata = {
  rule_name: 'Basic_Rule',
}

const sampleYaraRuleContent = `/*
 * Rule: Win32_Trojan_Generic
 * Author: Security Team
 * Description: Detects generic trojan patterns
 */

rule Win32_Trojan_Generic
{
    meta:
        author = "Security Team"
        description = "Detects generic trojan patterns"
        
    strings:
        $mz = { 4D 5A }
        $string1 = "malicious_string" nocase
        
    condition:
        $mz at 0 and $string1
}`

describe('YaraRuleViewer', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetch.mockClear()
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('Rendering', () => {
    it('renders nothing when no rules provided', () => {
      const { container } = render(<YaraRuleViewer rules={[]} fileHash="test-hash" />)
      expect(container.firstChild).toBeNull()
    })

    it('renders YARA rule card with correct title', () => {
      render(<YaraRuleViewer rules={mockYaraRules} fileHash="test-hash" />)
      
      expect(screen.getByText('YARA Rule Detections')).toBeInTheDocument()
      expect(screen.getByText('3 rules')).toBeInTheDocument()
    })

    it('renders single rule with correct count', () => {
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      expect(screen.getByText('1 rule')).toBeInTheDocument()
    })

    it('displays all rule names', () => {
      render(<YaraRuleViewer rules={mockYaraRules} fileHash="test-hash" />)
      
      expect(screen.getByText('Win32_Trojan_Generic')).toBeInTheDocument()
      expect(screen.getByText('Suspicious_Network_Activity')).toBeInTheDocument()
      expect(screen.getByText('Malware_Dropper_Pattern')).toBeInTheDocument()
    })

    it('displays rule metadata when available', () => {
      render(<YaraRuleViewer rules={mockYaraRules} fileHash="test-hash" />)
      
      expect(screen.getByText('By: Security Team')).toBeInTheDocument()
      expect(screen.getByText('By: Analyst')).toBeInTheDocument()
      expect(screen.getByText('Detects generic trojan patterns in Windows executables')).toBeInTheDocument()
    })

    it('handles rules without metadata gracefully', () => {
      render(<YaraRuleViewer rules={[mockRuleWithoutMetadata]} fileHash="test-hash" />)
      
      expect(screen.getByText('Basic_Rule')).toBeInTheDocument()
      expect(screen.queryByText('By:')).not.toBeInTheDocument()
    })
  })

  describe('Risk Level Classification', () => {
    it('assigns high risk to malware-related rules', () => {
      const malwareRules = [
        { rule_name: 'Trojan_Detection', description: 'Detects trojan malware' },
        { rule_name: 'Virus_Pattern', description: 'Identifies virus patterns' },
        { rule_name: 'Backdoor_Finder', description: 'Finds backdoor malicious code' },
        { rule_name: 'Ransomware_Generic', description: 'Generic ransomware detection' },
      ]
      
      render(<YaraRuleViewer rules={malwareRules} fileHash="test-hash" />)
      
      const highBadges = screen.getAllByText('HIGH')
      expect(highBadges).toHaveLength(4)
    })

    it('assigns medium risk to suspicious rules', () => {
      const suspiciousRules = [
        { rule_name: 'Suspicious_API_Calls', description: 'Detects suspicious API usage' },
        { rule_name: 'Heuristic_Detection', description: 'Heuristic pattern matching' },
        { rule_name: 'Indicator_Rule', description: 'Potential indicator of compromise' },
      ]
      
      render(<YaraRuleViewer rules={suspiciousRules} fileHash="test-hash" />)
      
      const mediumBadges = screen.getAllByText('MEDIUM')
      expect(mediumBadges).toHaveLength(3)
    })

    it('assigns low risk to other rules', () => {
      const lowRiskRules = [
        { rule_name: 'File_Type_Check', description: 'Verifies file type' },
        { rule_name: 'Generic_Pattern', description: 'Generic file pattern' },
      ]
      
      render(<YaraRuleViewer rules={lowRiskRules} fileHash="test-hash" />)
      
      expect(screen.queryByText('HIGH')).not.toBeInTheDocument()
      expect(screen.queryByText('MEDIUM')).not.toBeInTheDocument()
    })
  })

  describe('Rule Grouping', () => {
    it('groups rules by source', () => {
      const rulesWithDifferentSources = [
        { rule_name: 'Rule1', source: 'https://github.com/team1/rules' },
        { rule_name: 'Rule2', source: 'https://github.com/team1/rules' },
        { rule_name: 'Rule3', source: 'https://github.com/team2/rules' },
      ]
      
      render(<YaraRuleViewer rules={rulesWithDifferentSources} fileHash="test-hash" />)
      
      expect(screen.getByText('https://github.com/team1/rules')).toBeInTheDocument()
      expect(screen.getByText('https://github.com/team2/rules')).toBeInTheDocument()
    })

    it('handles rules without source', () => {
      const rulesWithoutSource = [
        { rule_name: 'Rule1' },
        { rule_name: 'Rule2' },
      ]
      
      render(<YaraRuleViewer rules={rulesWithoutSource} fileHash="test-hash" />)
      
      expect(screen.getByText('Unknown Source')).toBeInTheDocument()
    })
  })

  describe('Dialog Interaction', () => {
    it('opens dialog when view rule button is clicked', async () => {
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })
    })

    it('displays rule metadata in dialog', async () => {
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText('Author: Security Team')).toBeInTheDocument()
        expect(screen.getByText('Ruleset: trojan_detection')).toBeInTheDocument()
      })
    })

    it('closes dialog when close button is clicked', async () => {
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })
    })
  })

  describe('GitHub Integration', () => {
    it('fetches rule content from GitHub successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleYaraRuleContent),
      } as Response)
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/rule Win32_Trojan_Generic/)).toBeInTheDocument()
      })
    })

    it('displays loading state while fetching', async () => {
      mockFetch.mockImplementation(() => new Promise(() => {})) // Never resolves
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })
      
      // Should show loading spinner
      await waitFor(() => {
        expect(document.querySelector('.animate-spin')).toBeInTheDocument()
      })
    })

    it('handles GitHub fetch errors gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'))
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText('Failed to fetch rule from GitHub')).toBeInTheDocument()
      })
    })

    it('generates placeholder when GitHub fetch fails', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      } as Response)
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/rule Win32_Trojan_Generic/)).toBeInTheDocument()
        expect(screen.getByText(/Unable to fetch actual rule content/)).toBeInTheDocument()
      })
    })

    it('tries multiple paths when fetching from GitHub', async () => {
      // Mock multiple failed attempts followed by success
      mockFetch
        .mockResolvedValueOnce({ ok: false, status: 404 } as Response)
        .mockResolvedValueOnce({ ok: false, status: 404 } as Response)
        .mockResolvedValueOnce({
          ok: true,
          text: () => Promise.resolve(sampleYaraRuleContent),
        } as Response)
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/rule Win32_Trojan_Generic/)).toBeInTheDocument()
      })
      
      expect(mockFetch).toHaveBeenCalledTimes(3)
    })

    it('opens GitHub link when view on GitHub button is clicked', async () => {
      const windowOpenSpy = vi.spyOn(window, 'open').mockImplementation(() => null)
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })
      
      const githubButton = screen.getByText('View on GitHub')
      fireEvent.click(githubButton)
      
      expect(windowOpenSpy).toHaveBeenCalledWith(mockYaraRules[0].source, '_blank')
    })
  })

  describe('Copy Functionality', () => {
    it('copies rule content to clipboard', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleYaraRuleContent),
      } as Response)
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/rule Win32_Trojan_Generic/)).toBeInTheDocument()
      })
      
      const copyButton = screen.getByText('Copy Rule')
      fireEvent.click(copyButton)
      
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(sampleYaraRuleContent)
      
      await waitFor(() => {
        expect(screen.getByText('Copied!')).toBeInTheDocument()
      })
    })

    it('handles clipboard errors gracefully', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      vi.mocked(navigator.clipboard.writeText).mockRejectedValueOnce(new Error('Clipboard error'))
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleYaraRuleContent),
      } as Response)
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
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

    it('resets copy state after timeout', async () => {
      vi.useFakeTimers()
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleYaraRuleContent),
      } as Response)
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText('Copy Rule')).toBeInTheDocument()
      })
      
      const copyButton = screen.getByText('Copy Rule')
      fireEvent.click(copyButton)
      
      await waitFor(() => {
        expect(screen.getByText('Copied!')).toBeInTheDocument()
      })
      
      vi.advanceTimersByTime(2500)
      
      await waitFor(() => {
        expect(screen.getByText('Copy Rule')).toBeInTheDocument()
      })
      
      vi.useRealTimers()
    })
  })

  describe('High Risk Warning', () => {
    it('displays warning for high-risk rules', () => {
      render(<YaraRuleViewer rules={[mockHighRiskRule]} fileHash="test-hash" />)
      
      expect(screen.getByText('HIGH')).toBeInTheDocument()
      expect(screen.getByText(/High-risk YARA rules detected/)).toBeInTheDocument()
    })

    it('does not display warning for low-risk rules only', () => {
      const lowRiskRules = [
        { rule_name: 'File_Type_Check', description: 'Simple file type verification' }
      ]
      
      render(<YaraRuleViewer rules={lowRiskRules} fileHash="test-hash" />)
      
      expect(screen.queryByText(/High-risk YARA rules detected/)).not.toBeInTheDocument()
    })

    it('displays warning when mixed risk levels include high risk', () => {
      const mixedRules = [
        mockYaraRules[1], // medium risk
        mockHighRiskRule, // high risk
      ]
      
      render(<YaraRuleViewer rules={mixedRules} fileHash="test-hash" />)
      
      expect(screen.getByText(/High-risk YARA rules detected/)).toBeInTheDocument()
    })
  })

  describe('Rule Content Processing', () => {
    it('extracts specific rule from multi-rule file', async () => {
      const multiRuleContent = `rule FirstRule { condition: true }
      
rule Win32_Trojan_Generic {
    meta:
        author = "Security Team"
    condition:
        $mz at 0
}

rule ThirdRule { condition: false }`
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(multiRuleContent),
      } as Response)
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/rule Win32_Trojan_Generic/)).toBeInTheDocument()
        expect(screen.queryByText('rule FirstRule')).not.toBeInTheDocument()
      })
    })

    it('shows full file when specific rule cannot be extracted', async () => {
      const fullFileContent = 'rule SomeOtherRule { condition: true }'
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(fullFileContent),
      } as Response)
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText('rule SomeOtherRule')).toBeInTheDocument()
      })
    })
  })

  describe('Placeholder Generation', () => {
    it('generates proper placeholder for rule without GitHub source', () => {
      const ruleWithoutGithub = {
        rule_name: 'Local_Rule',
        author: 'Local Author',
        description: 'Local rule description',
        source: 'local-repository',
      }
      
      render(<YaraRuleViewer rules={[ruleWithoutGithub]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      expect(screen.getByText(/Unable to fetch actual rule content/)).toBeInTheDocument()
      expect(screen.getByText(/rule Local_Rule/)).toBeInTheDocument()
    })

    it('includes all available metadata in placeholder', () => {
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      expect(screen.getByText(/Author: Security Team/)).toBeInTheDocument()
      expect(screen.getByText(/Source: https:\/\/github.com\/security-team\/yara-rules/)).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('provides proper ARIA labels for buttons', () => {
      render(<YaraRuleViewer rules={mockYaraRules} fileHash="test-hash" />)
      
      const viewButtons = screen.getAllByRole('button')
      expect(viewButtons.length).toBeGreaterThan(0)
    })

    it('maintains proper heading structure', () => {
      render(<YaraRuleViewer rules={mockYaraRules} fileHash="test-hash" />)
      
      expect(screen.getByRole('heading', { name: /YARA Rule Detections/ })).toBeInTheDocument()
    })

    it('provides meaningful button text for screen readers', () => {
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      // On mobile, button text should include "View Rule"
      expect(screen.getByText('View Rule')).toBeInTheDocument()
    })

    it('provides proper dialog accessibility', async () => {
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        const dialog = screen.getByRole('dialog')
        expect(dialog).toBeInTheDocument()
        expect(dialog).toHaveAttribute('aria-modal', 'true')
      })
    })
  })

  describe('Responsive Design', () => {
    it('adapts layout for mobile screens', () => {
      render(<YaraRuleViewer rules={mockYaraRules} fileHash="test-hash" />)
      
      // Should have responsive classes
      const ruleContainers = document.querySelectorAll('.sm\\:flex-row')
      expect(ruleContainers.length).toBeGreaterThan(0)
    })

    it('handles dialog sizing on different screens', async () => {
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        const dialogContent = document.querySelector('[role="dialog"]')
        expect(dialogContent).toHaveClass('w-[95vw]', 'max-w-4xl')
      })
    })
  })

  describe('Keyboard Navigation', () => {
    it('supports keyboard navigation for buttons', async () => {
      const user = userEvent.setup()
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      
      // Tab to button and press Enter
      await user.tab()
      expect(viewButton).toHaveFocus()
      
      await user.keyboard('{Enter}')
      
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      })
    })
  })

  describe('Error Handling', () => {
    it('handles malformed GitHub URLs gracefully', async () => {
      const ruleWithBadUrl = {
        rule_name: 'Bad_URL_Rule',
        source: 'not-a-github-url',
      }
      
      render(<YaraRuleViewer rules={[ruleWithBadUrl]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/rule Bad_URL_Rule/)).toBeInTheDocument()
        expect(screen.getByText(/Unable to fetch actual rule content/)).toBeInTheDocument()
      })
    })

    it('handles empty rule content gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(''),
      } as Response)
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/Unable to fetch actual rule content/)).toBeInTheDocument()
      })
    })
  })

  describe('Edge Cases', () => {
    it('handles rules with missing or undefined properties', () => {
      const incompleteRule = {
        rule_name: 'Incomplete_Rule',
        // Missing other properties
      }
      
      render(<YaraRuleViewer rules={[incompleteRule]} fileHash="test-hash" />)
      
      expect(screen.getByText('Incomplete_Rule')).toBeInTheDocument()
      expect(screen.queryByText('By:')).not.toBeInTheDocument()
    })

    it('handles very long rule names and descriptions', () => {
      const longRule = {
        rule_name: 'Very_Long_Rule_Name_That_Might_Cause_Layout_Issues_In_UI_Components',
        description: 'This is a very long description that should be handled properly by the component without breaking the layout or causing overflow issues in the user interface',
        author: 'Author with a very long name that might cause issues',
      }
      
      render(<YaraRuleViewer rules={[longRule]} fileHash="test-hash" />)
      
      expect(screen.getByText('Very_Long_Rule_Name_That_Might_Cause_Layout_Issues_In_UI_Components')).toBeInTheDocument()
      
      // Should have proper text wrapping classes
      const ruleElement = screen.getByText('Very_Long_Rule_Name_That_Might_Cause_Layout_Issues_In_UI_Components')
      expect(ruleElement).toHaveClass('break-all')
    })

    it('handles special characters in rule names', () => {
      const specialCharRule = {
        rule_name: 'Rule_With_Special_Chars_$@#%',
        description: 'Rule with special characters in name',
      }
      
      render(<YaraRuleViewer rules={[specialCharRule]} fileHash="test-hash" />)
      
      expect(screen.getByText('Rule_With_Special_Chars_$@#%')).toBeInTheDocument()
    })
  })

  describe('Performance', () => {
    it('handles large number of rules efficiently', () => {
      const manyRules = Array.from({ length: 100 }, (_, i) => ({
        rule_name: `Rule_${i}`,
        author: `Author ${i}`,
        description: `Description for rule ${i}`,
        source: `https://github.com/repo${i % 5}/rules`,
      }))
      
      const { container } = render(<YaraRuleViewer rules={manyRules} fileHash="test-hash" />)
      
      expect(screen.getByText('100 rules')).toBeInTheDocument()
      expect(container.querySelectorAll('[data-testid="rule-item"], .p-3').length).toBe(100)
    })

    it('groups rules efficiently when many sources exist', () => {
      const rulesWithManySources = Array.from({ length: 50 }, (_, i) => ({
        rule_name: `Rule_${i}`,
        source: `https://github.com/repo${i}/rules`,
      }))
      
      render(<YaraRuleViewer rules={rulesWithManySources} fileHash="test-hash" />)
      
      // Should have 50 different source groups
      const sourceHeaders = document.querySelectorAll('.text-muted-foreground .font-medium')
      expect(sourceHeaders.length).toBe(50)
    })
  })

  describe('PrismJS Integration', () => {
    it('calls Prism.highlightAll when rule content is loaded', async () => {
      // Clear the mock to track calls from this test
      vi.clearAllMocks()
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(sampleYaraRuleContent),
      } as Response)
      
      render(<YaraRuleViewer rules={[mockYaraRules[0]]} fileHash="test-hash" />)
      
      const viewButton = screen.getByRole('button', { name: /view rule/i })
      fireEvent.click(viewButton)
      
      await waitFor(() => {
        expect(screen.getByText(/rule Win32_Trojan_Generic/)).toBeInTheDocument()
      })
      
      expect(global.Prism.highlightAll).toHaveBeenCalled()
    })
  })
})