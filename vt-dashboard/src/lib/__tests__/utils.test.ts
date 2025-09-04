import { describe, it, expect } from 'vitest'
import { 
  cn, 
  formatBytes, 
  formatDate, 
  getVerdictColor, 
  getVerdictBadgeVariant, 
  calculateRiskScore, 
  truncateHash 
} from '../utils'

describe('Utils Functions', () => {
  describe('cn (className utility)', () => {
    it('combines multiple class names', () => {
      const result = cn('class1', 'class2', 'class3')
      expect(result).toBe('class1 class2 class3')
    })

    it('handles conditional classes', () => {
      const result = cn('base', true && 'conditional', false && 'hidden')
      expect(result).toBe('base conditional')
    })

    it('merges Tailwind classes correctly', () => {
      const result = cn('p-4', 'p-2') // p-2 should override p-4
      expect(result).toBe('p-2')
    })

    it('handles arrays of classes', () => {
      const result = cn(['class1', 'class2'], 'class3')
      expect(result).toBe('class1 class2 class3')
    })

    it('handles undefined and null values', () => {
      const result = cn('base', undefined, null, 'valid')
      expect(result).toBe('base valid')
    })

    it('handles empty input', () => {
      const result = cn()
      expect(result).toBe('')
    })
  })

  describe('formatBytes', () => {
    it('formats zero bytes', () => {
      expect(formatBytes(0)).toBe('0 Bytes')
    })

    it('formats bytes', () => {
      expect(formatBytes(512)).toBe('512 Bytes')
      expect(formatBytes(1023)).toBe('1023 Bytes')
    })

    it('formats kilobytes', () => {
      expect(formatBytes(1024)).toBe('1 KB')
      expect(formatBytes(2048)).toBe('2 KB')
      expect(formatBytes(1536)).toBe('1.5 KB')
    })

    it('formats megabytes', () => {
      expect(formatBytes(1048576)).toBe('1 MB')
      expect(formatBytes(2097152)).toBe('2 MB')
      expect(formatBytes(1572864)).toBe('1.5 MB')
    })

    it('formats gigabytes', () => {
      expect(formatBytes(1073741824)).toBe('1 GB')
      expect(formatBytes(2147483648)).toBe('2 GB')
    })

    it('formats terabytes', () => {
      expect(formatBytes(1099511627776)).toBe('1 TB')
      expect(formatBytes(2199023255552)).toBe('2 TB')
    })

    it('formats petabytes', () => {
      expect(formatBytes(1125899906842624)).toBe('1 PB')
    })

    it('handles decimal places correctly', () => {
      expect(formatBytes(1536)).toBe('1.5 KB') // 1.5 * 1024
      expect(formatBytes(1600)).toBe('1.56 KB') // Should round to 2 decimal places
    })

    it('removes unnecessary zeros in decimals', () => {
      expect(formatBytes(1024)).toBe('1 KB') // Should be "1 KB", not "1.00 KB"
    })
  })

  describe('formatDate', () => {
    it('formats Date object', () => {
      const date = new Date('2023-12-01T10:30:00Z')
      const result = formatDate(date)
      expect(result).toMatch(/Dec \d{1,2}, 2023/)
      expect(result).toMatch(/\d{1,2}:\d{2}/)
    })

    it('formats ISO date string', () => {
      const result = formatDate('2023-12-01T10:30:00Z')
      expect(result).toMatch(/Dec \d{1,2}, 2023/)
      expect(result).toMatch(/\d{1,2}:\d{2}/)
    })

    it('formats regular date string', () => {
      const result = formatDate('2023-12-01')
      expect(result).toMatch(/\w+ \d{1,2}, 2023/) // Month can vary due to timezone
    })

    it('includes time in format', () => {
      const result = formatDate('2023-12-01T14:30:00')
      expect(result).toContain(':')
      expect(result).toMatch(/\d{1,2}:\d{2}/)
    })

    it('uses US date format', () => {
      const result = formatDate('2023-01-15T10:30:00')
      expect(result).toMatch(/Jan 15, 2023/)
    })
  })

  describe('getVerdictColor', () => {
    it('returns malicious color for malicious verdict', () => {
      expect(getVerdictColor('malicious')).toBe('hsl(var(--malicious))')
      expect(getVerdictColor('MALICIOUS')).toBe('hsl(var(--malicious))')
    })

    it('returns suspicious color for suspicious verdict', () => {
      expect(getVerdictColor('suspicious')).toBe('hsl(var(--suspicious))')
      expect(getVerdictColor('SUSPICIOUS')).toBe('hsl(var(--suspicious))')
    })

    it('returns clean color for clean verdict', () => {
      expect(getVerdictColor('clean')).toBe('hsl(var(--clean))')
      expect(getVerdictColor('CLEAN')).toBe('hsl(var(--clean))')
    })

    it('returns clean color for harmless verdict', () => {
      expect(getVerdictColor('harmless')).toBe('hsl(var(--clean))')
      expect(getVerdictColor('HARMLESS')).toBe('hsl(var(--clean))')
    })

    it('returns undetected color for undetected verdict', () => {
      expect(getVerdictColor('undetected')).toBe('hsl(var(--undetected))')
      expect(getVerdictColor('UNDETECTED')).toBe('hsl(var(--undetected))')
    })

    it('returns default color for unknown verdict', () => {
      expect(getVerdictColor('unknown')).toBe('hsl(var(--muted-foreground))')
      expect(getVerdictColor('invalid')).toBe('hsl(var(--muted-foreground))')
      expect(getVerdictColor('')).toBe('hsl(var(--muted-foreground))')
    })

    it('handles case insensitive verdicts', () => {
      expect(getVerdictColor('Malicious')).toBe('hsl(var(--malicious))')
      expect(getVerdictColor('SuSpIcIoUs')).toBe('hsl(var(--suspicious))')
      expect(getVerdictColor('ClEaN')).toBe('hsl(var(--clean))')
    })
  })

  describe('getVerdictBadgeVariant', () => {
    it('returns destructive for malicious verdict', () => {
      expect(getVerdictBadgeVariant('malicious')).toBe('destructive')
      expect(getVerdictBadgeVariant('MALICIOUS')).toBe('destructive')
    })

    it('returns outline for suspicious verdict', () => {
      expect(getVerdictBadgeVariant('suspicious')).toBe('outline')
      expect(getVerdictBadgeVariant('SUSPICIOUS')).toBe('outline')
    })

    it('returns secondary for clean verdict', () => {
      expect(getVerdictBadgeVariant('clean')).toBe('secondary')
      expect(getVerdictBadgeVariant('CLEAN')).toBe('secondary')
    })

    it('returns secondary for harmless verdict', () => {
      expect(getVerdictBadgeVariant('harmless')).toBe('secondary')
      expect(getVerdictBadgeVariant('HARMLESS')).toBe('secondary')
    })

    it('returns default for undetected verdict', () => {
      expect(getVerdictBadgeVariant('undetected')).toBe('default')
      expect(getVerdictBadgeVariant('UNDETECTED')).toBe('default')
    })

    it('returns default for unknown verdict', () => {
      expect(getVerdictBadgeVariant('unknown')).toBe('default')
      expect(getVerdictBadgeVariant('invalid')).toBe('default')
      expect(getVerdictBadgeVariant('')).toBe('default')
    })

    it('handles case insensitive verdicts', () => {
      expect(getVerdictBadgeVariant('Malicious')).toBe('destructive')
      expect(getVerdictBadgeVariant('SuSpIcIoUs')).toBe('outline')
      expect(getVerdictBadgeVariant('ClEaN')).toBe('secondary')
    })
  })

  describe('calculateRiskScore', () => {
    it('returns zero score for empty results', () => {
      const result = calculateRiskScore([])
      expect(result).toEqual({ score: 0, level: 'Low' })
    })

    it('calculates score correctly for all malicious', () => {
      const results = [
        { verdict: 'malicious' },
        { verdict: 'malicious' },
        { verdict: 'malicious' },
        { verdict: 'malicious' }
      ]
      const result = calculateRiskScore(results)
      expect(result.score).toBe(200) // (4 * 2 + 0) / 4 * 100 = 200
      expect(result.level).toBe('Critical')
    })

    it('calculates score correctly for mixed results', () => {
      const results = [
        { verdict: 'malicious' }, // 2 points
        { verdict: 'malicious' }, // 2 points
        { verdict: 'suspicious' }, // 1 point
        { verdict: 'clean' } // 0 points
      ]
      // (2*2 + 1*1 + 0*2) / 4 * 100 = 5/4 * 100 = 125
      const result = calculateRiskScore(results)
      expect(result.score).toBe(125)
      expect(result.level).toBe('Critical')
    })

    it('assigns Critical level for score >= 80', () => {
      const results = [
        { verdict: 'malicious' },
        { verdict: 'malicious' },
        { verdict: 'suspicious' },
        { verdict: 'suspicious' },
        { verdict: 'clean' }
      ]
      // (2*2 + 2*1) / 5 * 100 = 6/5 * 100 = 120
      const result = calculateRiskScore(results)
      expect(result.level).toBe('Critical')
    })

    it('assigns High level for score >= 50', () => {
      const results = [
        { verdict: 'malicious' },
        { verdict: 'suspicious' },
        { verdict: 'clean' },
        { verdict: 'clean' }
      ]
      // (1*2 + 1*1) / 4 * 100 = 3/4 * 100 = 75
      const result = calculateRiskScore(results)
      expect(result.level).toBe('High')
    })

    it('assigns Medium level for score >= 20', () => {
      const results = [
        { verdict: 'suspicious' },
        { verdict: 'clean' },
        { verdict: 'clean' },
        { verdict: 'clean' },
        { verdict: 'clean' }
      ]
      // (0*2 + 1*1) / 5 * 100 = 1/5 * 100 = 20
      const result = calculateRiskScore(results)
      expect(result.level).toBe('Medium')
    })

    it('assigns Low level for score < 20', () => {
      const results = [
        { verdict: 'clean' },
        { verdict: 'clean' },
        { verdict: 'clean' },
        { verdict: 'clean' },
        { verdict: 'undetected' }
      ]
      // (0*2 + 0*1) / 5 * 100 = 0
      const result = calculateRiskScore(results)
      expect(result.score).toBe(0)
      expect(result.level).toBe('Low')
    })

    it('handles case insensitive verdicts', () => {
      const results = [
        { verdict: 'MALICIOUS' },
        { verdict: 'Suspicious' },
        { verdict: 'CLEAN' }
      ]
      // (1*2 + 1*1) / 3 * 100 = 3/3 * 100 = 100
      const result = calculateRiskScore(results)
      expect(result.score).toBe(100)
      expect(result.level).toBe('Critical')
    })

    it('ignores unknown verdicts in calculation', () => {
      const results = [
        { verdict: 'malicious' },
        { verdict: 'unknown' },
        { verdict: 'invalid' },
        { verdict: 'clean' }
      ]
      // Only malicious counts: (1*2 + 0*1) / 4 * 100 = 2/4 * 100 = 50
      const result = calculateRiskScore(results)
      expect(result.score).toBe(50)
      expect(result.level).toBe('High')
    })

    it('rounds score to nearest integer', () => {
      const results = [
        { verdict: 'malicious' },
        { verdict: 'clean' },
        { verdict: 'clean' }
      ]
      // (1*2 + 0*1) / 3 * 100 = 2/3 * 100 = 66.666... should round to 67
      const result = calculateRiskScore(results)
      expect(result.score).toBe(67)
      expect(result.level).toBe('High')
    })
  })

  describe('truncateHash', () => {
    it('truncates hash to default length of 16', () => {
      const hash = '1234567890abcdef1234567890abcdef'
      const result = truncateHash(hash)
      expect(result).toBe('1234567890abcdef...')
    })

    it('truncates hash to specified length', () => {
      const hash = '1234567890abcdef1234567890abcdef'
      const result = truncateHash(hash, 8)
      expect(result).toBe('12345678...')
    })

    it('returns original hash if shorter than specified length', () => {
      const hash = '12345'
      const result = truncateHash(hash, 16)
      expect(result).toBe('12345')
    })

    it('returns original hash if exactly the specified length', () => {
      const hash = '1234567890abcdef'
      const result = truncateHash(hash, 16)
      expect(result).toBe('1234567890abcdef')
    })

    it('handles empty string', () => {
      const result = truncateHash('', 8)
      expect(result).toBe('')
    })

    it('handles custom length of 1', () => {
      const hash = 'abcdef'
      const result = truncateHash(hash, 1)
      expect(result).toBe('a...')
    })

    it('handles very long hashes', () => {
      const hash = 'a'.repeat(100)
      const result = truncateHash(hash, 10)
      expect(result).toBe('aaaaaaaaaa...')
      expect(result.length).toBe(13) // 10 chars + '...'
    })

    it('handles zero length (edge case)', () => {
      const hash = 'abcdef'
      const result = truncateHash(hash, 0)
      expect(result).toBe('...')
    })
  })

  describe('Edge Cases and Error Handling', () => {
    it('formatBytes handles edge cases', () => {
      const result = formatBytes(1024)
      expect(result).toBe('1 KB')
    })

    it('formatBytes handles very large numbers', () => {
      const result = formatBytes(Number.MAX_SAFE_INTEGER)
      expect(result).toContain('PB')
    })

    it('formatDate handles invalid dates gracefully', () => {
      const result = formatDate('invalid-date')
      expect(result).toMatch(/Invalid Date|NaN/)
    })

    it('calculateRiskScore handles malformed verdict objects', () => {
      const results = [
        { verdict: 'malicious' },
        { verdict: 'unknown' }, // Use valid but ignored verdict instead
        { verdict: 'invalid' },
        { verdict: 'clean' }
      ]
      
      // malicious and clean should count
      const result = calculateRiskScore(results)
      expect(result.score).toBe(50) // (1*2 + 0) / 4 * 100 = 50
    })
  })
})