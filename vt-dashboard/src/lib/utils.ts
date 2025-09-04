import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function formatDate(date: string | Date): string {
  const d = new Date(date);
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

export function formatRelativeTime(date: string | Date): string {
  const d = new Date(date);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);
  const diffWeek = Math.floor(diffDay / 7);
  const diffMonth = Math.floor(diffDay / 30);
  const diffYear = Math.floor(diffDay / 365);

  if (diffSec < 60) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHour < 24) return `${diffHour}h ago`;
  if (diffDay < 7) return `${diffDay}d ago`;
  if (diffWeek < 4) return `${diffWeek}w ago`;
  if (diffMonth < 12) return `${diffMonth}mo ago`;
  return `${diffYear}y ago`;
}

export function getVerdictColor(verdict: string): string {
  switch (verdict.toLowerCase()) {
    case 'malicious':
      return 'hsl(var(--malicious))';
    case 'suspicious':
      return 'hsl(var(--suspicious))';
    case 'clean':
    case 'harmless':
      return 'hsl(var(--clean))';
    case 'undetected':
      return 'hsl(var(--undetected))';
    default:
      return 'hsl(var(--muted-foreground))';
  }
}

export function getVerdictBadgeVariant(verdict: string): "default" | "destructive" | "secondary" | "outline" {
  switch (verdict.toLowerCase()) {
    case 'malicious':
      return 'destructive';
    case 'suspicious':
      return 'outline';
    case 'clean':
    case 'harmless':
      return 'secondary';
    case 'undetected':
    default:
      return 'default';
  }
}

export function calculateRiskScore(analysisResults: Array<{ verdict: string }>): {
  score: number;
  level: 'Low' | 'Medium' | 'High' | 'Critical';
} {
  const total = analysisResults.length;
  if (total === 0) return { score: 0, level: 'Low' };

  const malicious = analysisResults.filter(r => r.verdict.toLowerCase() === 'malicious').length;
  const suspicious = analysisResults.filter(r => r.verdict.toLowerCase() === 'suspicious').length;
  
  const score = Math.round(((malicious * 2 + suspicious) / total) * 100);
  
  let level: 'Low' | 'Medium' | 'High' | 'Critical';
  if (score >= 80) level = 'Critical';
  else if (score >= 50) level = 'High';
  else if (score >= 20) level = 'Medium';
  else level = 'Low';

  return { score, level };
}

export function truncateHash(hash: string, length: number = 16): string {
  if (!hash) return '';
  if (hash.length <= length) return hash;
  return `${hash.substring(0, length)}...`;
}