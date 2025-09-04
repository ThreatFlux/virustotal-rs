import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { DetectionRulesViewer } from '../DetectionRulesViewer'

// Mock the YaraRuleViewer and SigmaRuleViewer components
vi.mock('../YaraRuleViewer', () => ({
  YaraRuleViewer: ({ rules, fileHash }: any) => (
    <div data-testid="yara-rule-viewer" data-filehash={fileHash}>
      YARA Rules Component ({rules.length} rules)
    </div>
  )
}))

vi.mock('../SigmaRuleViewer', () => ({
  SigmaRuleViewer: ({ rules, fileHash }: any) => (
    <div data-testid="sigma-rule-viewer" data-filehash={fileHash}>
      Sigma Rules Component ({rules.length} rules)
    </div>
  )
}))

// Mock UI components
vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div data-testid="card">{children}</div>,
  CardContent: ({ children }: any) => <div data-testid="card-content">{children}</div>,
  CardHeader: ({ children }: any) => <div data-testid="card-header">{children}</div>,
  CardTitle: ({ children, className }: any) => <h3 className={className} data-testid="card-title">{children}</h3>
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children, variant }: any) => <span data-testid="badge" data-variant={variant}>{children}</span>
}))

vi.mock('@/components/ui/tabs', () => ({
  Tabs: ({ children, defaultValue }: any) => <div data-testid="tabs" data-default={defaultValue}>{children}</div>,
  TabsContent: ({ children, value }: any) => <div data-testid="tabs-content" data-value={value}>{children}</div>,
  TabsList: ({ children }: any) => <div data-testid="tabs-list">{children}</div>,
  TabsTrigger: ({ children, value }: any) => <button data-testid="tabs-trigger" data-value={value}>{children}</button>
}))

describe('DetectionRulesViewer', () => {
  const mockFileHash = 'test-file-hash-123'
  
  const mockYaraRule = {
    data_type: 'yara',
    data: {
      rule_name: 'Test YARA Rule',
      author: 'Security Team',
      description: 'Test YARA rule description',
      source: 'internal',
      ruleset_name: 'malware_detection',
      ruleset_id: 'md_001'
    }
  }

  const mockSigmaRule = {
    data_type: 'sigma',
    data: {
      rule_name: 'Test Sigma Rule',
      author: 'Blue Team',
      description: 'Test Sigma rule description',
      source: 'github',
      level: 'high',
      status: 'experimental',
      tags: ['attack.t1055', 'attack.defense_evasion']
    }
  }

  const mockYaraRuleNoData = {
    data_type: 'yara',
    rule_name: 'Direct YARA Rule',
    author: 'Direct Author',
    description: 'Direct description',
    source: 'direct'
  }

  describe('Component Rendering', () => {
    it('returns null when no rules are provided', () => {
      const { container } = render(
        <DetectionRulesViewer crowdsourcedData={[]} fileHash={mockFileHash} />
      )
      
      expect(container.firstChild).toBeNull()
    })

    it('returns null when crowdsourced data is empty', () => {
      const { container } = render(
        <DetectionRulesViewer crowdsourcedData={[]} fileHash={mockFileHash} />
      )
      
      expect(container.firstChild).toBeNull()
    })

    it('returns null when no YARA or Sigma rules are found', () => {
      const nonRuleData = [
        { data_type: 'other', some_data: 'value' },
        { data_type: 'unknown', other_field: 'test' }
      ]
      
      const { container } = render(
        <DetectionRulesViewer crowdsourcedData={nonRuleData} fileHash={mockFileHash} />
      )
      
      expect(container.firstChild).toBeNull()
    })
  })

  describe('YARA Rules Only', () => {
    it('renders YaraRuleViewer directly when only YARA rules exist', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockYaraRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('yara-rule-viewer')).toBeInTheDocument()
      expect(screen.getByText('YARA Rules Component (1 rules)')).toBeInTheDocument()
      expect(screen.getByTestId('yara-rule-viewer')).toHaveAttribute('data-filehash', mockFileHash)
    })

    it('handles YARA rules with data in different formats', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockYaraRule, mockYaraRuleNoData]} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('yara-rule-viewer')).toBeInTheDocument()
      expect(screen.getByText('YARA Rules Component (2 rules)')).toBeInTheDocument()
    })

    it('handles YARA rules with missing or undefined properties', () => {
      const incompleteYaraRule = {
        data_type: 'yara',
        data: {
          rule_name: 'Incomplete Rule'
          // Missing other properties
        }
      }
      
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[incompleteYaraRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('yara-rule-viewer')).toBeInTheDocument()
      expect(screen.getByText('YARA Rules Component (1 rules)')).toBeInTheDocument()
    })
  })

  describe('Sigma Rules Only', () => {
    it('renders SigmaRuleViewer directly when only Sigma rules exist', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockSigmaRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('sigma-rule-viewer')).toBeInTheDocument()
      expect(screen.getByText('Sigma Rules Component (1 rules)')).toBeInTheDocument()
      expect(screen.getByTestId('sigma-rule-viewer')).toHaveAttribute('data-filehash', mockFileHash)
    })

    it('handles multiple Sigma rules', () => {
      const multipleSigmaRules = [mockSigmaRule, { ...mockSigmaRule, data: { ...mockSigmaRule.data, rule_name: 'Second Sigma Rule' } }]
      
      render(
        <DetectionRulesViewer 
          crowdsourcedData={multipleSigmaRules} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('sigma-rule-viewer')).toBeInTheDocument()
      expect(screen.getByText('Sigma Rules Component (2 rules)')).toBeInTheDocument()
    })
  })

  describe('Mixed Rules (Tabs)', () => {
    const mixedRules = [mockYaraRule, mockSigmaRule]

    it('renders tabs when both YARA and Sigma rules exist', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={mixedRules} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('card')).toBeInTheDocument()
      expect(screen.getByTestId('tabs')).toBeInTheDocument()
      expect(screen.getByTestId('tabs-list')).toBeInTheDocument()
    })

    it('displays correct card title and badges', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={mixedRules} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByText('Detection Rules')).toBeInTheDocument()
      expect(screen.getByText('1 YARA')).toBeInTheDocument()
      expect(screen.getByText('1 Sigma')).toBeInTheDocument()
    })

    it('renders tab triggers for both rule types', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={mixedRules} 
          fileHash={mockFileHash} 
        />
      )
      
      const tabTriggers = screen.getAllByTestId('tabs-trigger')
      expect(tabTriggers).toHaveLength(2)
      
      // Check for YARA tab
      const yaraTab = tabTriggers.find(tab => tab.getAttribute('data-value') === 'yara')
      expect(yaraTab).toBeInTheDocument()
      expect(yaraTab).toHaveTextContent('(1)')
      
      // Check for Sigma tab
      const sigmaTab = tabTriggers.find(tab => tab.getAttribute('data-value') === 'sigma')
      expect(sigmaTab).toBeInTheDocument()
      expect(sigmaTab).toHaveTextContent('(1)')
    })

    it('renders tab content for both rule types', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={mixedRules} 
          fileHash={mockFileHash} 
        />
      )
      
      const tabContents = screen.getAllByTestId('tabs-content')
      expect(tabContents).toHaveLength(2)
      
      // Check for YARA content
      const yaraContent = tabContents.find(content => content.getAttribute('data-value') === 'yara')
      expect(yaraContent).toBeInTheDocument()
      expect(yaraContent).toContainElement(screen.getByTestId('yara-rule-viewer'))
      
      // Check for Sigma content
      const sigmaContent = tabContents.find(content => content.getAttribute('data-value') === 'sigma')
      expect(sigmaContent).toBeInTheDocument()
      expect(sigmaContent).toContainElement(screen.getByTestId('sigma-rule-viewer'))
    })

    it('defaults to YARA tab when YARA rules are present', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={mixedRules} 
          fileHash={mockFileHash} 
        />
      )
      
      const tabs = screen.getByTestId('tabs')
      expect(tabs).toHaveAttribute('data-default', 'yara')
    })

    it('defaults to Sigma tab when only Sigma rules are present in mixed scenario', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockSigmaRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      // This should render SigmaRuleViewer directly, not tabs
      expect(screen.getByTestId('sigma-rule-viewer')).toBeInTheDocument()
      expect(screen.queryByTestId('tabs')).not.toBeInTheDocument()
    })
  })

  describe('Data Processing', () => {
    it('correctly extracts YARA rule data from nested data property', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockYaraRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('yara-rule-viewer')).toBeInTheDocument()
    })

    it('correctly extracts YARA rule data from top-level properties', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockYaraRuleNoData]} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('yara-rule-viewer')).toBeInTheDocument()
    })

    it('correctly extracts Sigma rule data with all properties', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockSigmaRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('sigma-rule-viewer')).toBeInTheDocument()
    })

    it('handles rules with unknown or missing rule names', () => {
      const ruleWithoutName = {
        data_type: 'yara',
        data: {
          author: 'Test Author'
          // Missing rule_name
        }
      }
      
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[ruleWithoutName]} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('yara-rule-viewer')).toBeInTheDocument()
    })
  })

  describe('Badge Display', () => {
    it('shows correct badge counts for multiple rules', () => {
      const multipleRules = [
        mockYaraRule,
        { ...mockYaraRule, data: { ...mockYaraRule.data, rule_name: 'Second YARA' } },
        mockSigmaRule,
        { ...mockSigmaRule, data: { ...mockSigmaRule.data, rule_name: 'Second Sigma' } },
        { ...mockSigmaRule, data: { ...mockSigmaRule.data, rule_name: 'Third Sigma' } }
      ]
      
      render(
        <DetectionRulesViewer 
          crowdsourcedData={multipleRules} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByText('2 YARA')).toBeInTheDocument()
      expect(screen.getByText('3 Sigma')).toBeInTheDocument()
    })

    it('applies secondary variant to badges', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockYaraRule, mockSigmaRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      const badges = screen.getAllByTestId('badge')
      badges.forEach(badge => {
        expect(badge).toHaveAttribute('data-variant', 'secondary')
      })
    })
  })

  describe('Responsive Design', () => {
    it('includes responsive classes for tab triggers', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockYaraRule, mockSigmaRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      const tabTriggers = screen.getAllByTestId('tabs-trigger')
      expect(tabTriggers.length).toBeGreaterThan(0)
    })

    it('includes responsive grid for tabs list', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockYaraRule, mockSigmaRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      const tabsList = screen.getByTestId('tabs-list')
      expect(tabsList).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('provides proper semantic structure with card layout', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockYaraRule, mockSigmaRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('card')).toBeInTheDocument()
      expect(screen.getByTestId('card-header')).toBeInTheDocument()
      expect(screen.getByTestId('card-content')).toBeInTheDocument()
      expect(screen.getByTestId('card-title')).toBeInTheDocument()
    })

    it('includes proper heading structure', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockYaraRule, mockSigmaRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      const title = screen.getByTestId('card-title')
      expect(title.tagName).toBe('H3')
    })
  })

  describe('Edge Cases', () => {
    it('handles empty data property gracefully', () => {
      const emptyDataRule = {
        data_type: 'yara',
        data: {}
      }
      
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[emptyDataRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('yara-rule-viewer')).toBeInTheDocument()
    })

    it('handles null data property gracefully', () => {
      const nullDataRule = {
        data_type: 'sigma',
        data: null
      }
      
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[nullDataRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      expect(screen.getByTestId('sigma-rule-viewer')).toBeInTheDocument()
    })

    it('handles mixed valid and invalid rules', () => {
      const mixedData = [
        mockYaraRule,
        { data_type: 'invalid' },
        mockSigmaRule,
        { data_type: 'yara', data: null }
      ]
      
      render(
        <DetectionRulesViewer 
          crowdsourcedData={mixedData} 
          fileHash={mockFileHash} 
        />
      )
      
      // Should show tabs with 2 YARA and 1 Sigma
      expect(screen.getByText('2 YARA')).toBeInTheDocument()
      expect(screen.getByText('1 Sigma')).toBeInTheDocument()
    })
  })

  describe('FileHash Prop Passing', () => {
    it('passes fileHash to YaraRuleViewer', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockYaraRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      const yaraViewer = screen.getByTestId('yara-rule-viewer')
      expect(yaraViewer).toHaveAttribute('data-filehash', mockFileHash)
    })

    it('passes fileHash to SigmaRuleViewer', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockSigmaRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      const sigmaViewer = screen.getByTestId('sigma-rule-viewer')
      expect(sigmaViewer).toHaveAttribute('data-filehash', mockFileHash)
    })

    it('passes fileHash to both viewers in tabbed layout', () => {
      render(
        <DetectionRulesViewer 
          crowdsourcedData={[mockYaraRule, mockSigmaRule]} 
          fileHash={mockFileHash} 
        />
      )
      
      const yaraViewer = screen.getByTestId('yara-rule-viewer')
      const sigmaViewer = screen.getByTestId('sigma-rule-viewer')
      
      expect(yaraViewer).toHaveAttribute('data-filehash', mockFileHash)
      expect(sigmaViewer).toHaveAttribute('data-filehash', mockFileHash)
    })
  })
})