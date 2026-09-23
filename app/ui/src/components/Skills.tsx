// SPDX-License-Identifier: Apache-2.0
// Skills.tsx — Agent skill-surface scanner redesigned as a security audit report.
// Auto-discovers every installed AI agent's skills/plugins/rules/MCP configs
// across the host and scans them for prompt injection + supply-chain risk.
// Driven by the daemon's /api/v1/skill-scan/auto endpoint via store.scanSkillsAuto().

import { useState, useMemo } from 'react';
import {
  useStore,
  type SkillScanResult,
  type SkillRootResult,
  type PatternFinding,
} from '../store';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { cn } from '../lib/utils';
import {
  Package,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ScanLine,
  Loader2,
  AlertTriangle,
  CheckCircle,
  Info,
  ChevronDown,
  ChevronRight,
  FileWarning,
  Shield,
  Crosshair,
  Eye,
  FileCode,
  Gauge,
  Ban,
  CircleAlert,
  FolderOpen,
} from 'lucide-react';

// ── Types & Constants ─────────────────────────────────────────────────────────

type RiskLevel = 'clean' | 'low' | 'medium' | 'high' | 'critical';
type Severity = 'critical' | 'high' | 'medium' | 'low';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

const RISK_META: Record<
  RiskLevel,
  {
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    color: string;
    badge: string;
  }
> = {
  clean: {
    label: 'Clean',
    icon: CheckCircle,
    color: 'text-emerald-400',
    badge: 'border-emerald-500/30 text-emerald-400',
  },
  low: { label: 'Low', icon: Info, color: 'text-sky-400', badge: 'border-sky-500/30 text-sky-400' },
  medium: {
    label: 'Medium',
    icon: AlertTriangle,
    color: 'text-amber-400',
    badge: 'border-amber-500/30 text-amber-400',
  },
  high: {
    label: 'High',
    icon: ShieldAlert,
    color: 'text-orange-400',
    badge: 'border-orange-500/30 text-orange-400',
  },
  critical: {
    label: 'Critical',
    icon: ShieldX,
    color: 'text-red-400',
    badge: 'border-red-500/30 text-red-400',
  },
};

const SEVERITY_BAR_COLORS: Record<string, string> = {
  low: 'bg-sky-400',
  medium: 'bg-amber-400',
  high: 'bg-orange-400',
  critical: 'bg-red-400',
};

const SEVERITY_CONFIG: Record<
  Severity,
  {
    label: string;
    color: string;
    bg: string;
    border: string;
    icon: React.ComponentType<{ className?: string }>;
    defaultExpanded: boolean;
  }
> = {
  critical: {
    label: 'CRITICAL',
    color: 'text-red-600',
    bg: 'bg-red-50',
    border: 'border-red-200',
    icon: ShieldX,
    defaultExpanded: true,
  },
  high: {
    label: 'HIGH',
    color: 'text-orange-600',
    bg: 'bg-orange-50',
    border: 'border-orange-200',
    icon: ShieldAlert,
    defaultExpanded: true,
  },
  medium: {
    label: 'MEDIUM',
    color: 'text-amber-600',
    bg: 'bg-amber-50',
    border: 'border-amber-200',
    icon: AlertTriangle,
    defaultExpanded: false,
  },
  low: {
    label: 'LOW',
    color: 'text-green-600',
    bg: 'bg-green-50',
    border: 'border-green-200',
    icon: Info,
    defaultExpanded: false,
  },
};

const CATEGORY_LABELS: Record<string, string> = {
  prompt_injection: 'Prompt Injection',
  data_exfiltration: 'Data Exfiltration',
  privilege_escalation: 'Privilege Escalation',
  code_execution: 'Code Execution',
  credential_theft: 'Credential Theft',
  supply_chain: 'Supply Chain',
  sandbox_escape: 'Sandbox Escape',
  information_disclosure: 'Info Disclosure',
};

const CATEGORY_COLORS: Record<string, string> = {
  prompt_injection: 'bg-purple-100 text-purple-700 border-purple-200',
  data_exfiltration: 'bg-red-100 text-red-700 border-red-200',
  privilege_escalation: 'bg-amber-100 text-amber-700 border-amber-200',
  code_execution: 'bg-orange-100 text-orange-700 border-orange-200',
  credential_theft: 'bg-rose-100 text-rose-700 border-rose-200',
  supply_chain: 'bg-blue-100 text-blue-700 border-blue-200',
  sandbox_escape: 'bg-indigo-100 text-indigo-700 border-indigo-200',
  information_disclosure: 'bg-cyan-100 text-cyan-700 border-cyan-200',
};

// Category colors mapped to highest severity for chip tinting
const CATEGORY_SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-300',
  high: 'bg-orange-100 text-orange-700 border-orange-300',
  medium: 'bg-amber-100 text-amber-700 border-amber-300',
  low: 'bg-green-100 text-green-700 border-green-300',
};

const RULE_ID_COLORS: Record<string, string> = {
  P: 'bg-purple-100 text-purple-700 border-purple-300',
  E: 'bg-red-100 text-red-700 border-red-300',
  AST: 'bg-orange-100 text-orange-700 border-orange-300',
  S: 'bg-blue-100 text-blue-700 border-blue-300',
  C: 'bg-rose-100 text-rose-700 border-rose-300',
  I: 'bg-cyan-100 text-cyan-700 border-cyan-300',
};

function getRuleIdColor(ruleId: string): string {
  for (const [prefix, color] of Object.entries(RULE_ID_COLORS)) {
    if (ruleId.startsWith(prefix)) return color;
  }
  return 'bg-gray-100 text-gray-700 border-gray-300';
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function norm(raw: string): RiskLevel {
  const l = (raw || '').toLowerCase();
  return (['critical', 'high', 'medium', 'low'].includes(l) ? l : 'clean') as RiskLevel;
}

// Risk is driven by the WORST finding present, never by how many there are.
//
// The previous version summed `severity_base * confidence` across every finding
// and capped at 100, so any large legitimate directory saturated to CRITICAL:
// 381 low-severity hits in an agent's own config read as "DO NOT INSTALL".
// Volume is reported separately, as a count, and can never cross a severity
// boundary on its own. This matches the daemon, which already aggregates with
// `worst` in scanner/skill_surface.rs.
function worstSeverity(findings: PatternFinding[]): Severity | null {
  for (const sev of SEVERITY_ORDER) {
    if (findings.some((f) => f.severity === sev)) return sev;
  }
  return null;
}

function computeRiskLevel(findings: PatternFinding[]): RiskLevel {
  const worst = worstSeverity(findings);
  if (!worst) return 'clean';
  return worst; // 'critical' | 'high' | 'medium' | 'low' are all RiskLevel members
}

/// A 0-100 number for the gauge only. The severity band fixes the range and
/// volume moves the needle inside it, so a thousand low findings can never
/// render as anything but "low".
const SEVERITY_BAND: Record<Severity, [number, number]> = {
  low: [10, 24],
  medium: [35, 49],
  high: [60, 79],
  critical: [85, 100],
};

function computeRiskScore(findings: PatternFinding[]): number {
  const worst = worstSeverity(findings);
  if (!worst) return 0;
  const [floor, ceil] = SEVERITY_BAND[worst];
  // How many findings share the worst severity, damped so it saturates slowly
  // and stays strictly inside the band.
  const atWorst = findings.filter((f) => f.severity === worst).length;
  const volume = Math.min(1, Math.log10(atWorst + 1) / 2); // 1 hit ≈ 0.15, 100 ≈ 1
  return Math.round(floor + (ceil - floor) * volume);
}

function riskScoreLevel(score: number): RiskLevel {
  if (score === 0) return 'clean';
  if (score < 30) return 'low';
  if (score < 55) return 'medium';
  if (score < 85) return 'high';
  return 'critical';
}

/// Two different questions, two different vocabularies.
///
/// "DO NOT INSTALL" is advice about a candidate you have not installed yet. For
/// a surface that is already installed and running — an agent's own config —
/// it is nonsense, and it trains people to ignore the scanner. An installed
/// surface gets review wording instead.
export type ScanMode = 'installed' | 'candidate';

function recommendationBadge(
  level: RiskLevel,
  mode: ScanMode,
): { label: string; color: string; bg: string } {
  const clean = { label: mode === 'candidate' ? 'SAFE' : 'CLEAN', color: 'text-emerald-700', bg: 'bg-emerald-100' };
  if (level === 'clean' || level === 'low') return clean;
  if (level === 'medium') {
    return mode === 'candidate'
      ? { label: 'CAUTION', color: 'text-amber-700', bg: 'bg-amber-100' }
      : { label: 'ATTENTION', color: 'text-amber-700', bg: 'bg-amber-100' };
  }
  return mode === 'candidate'
    ? { label: 'DO NOT INSTALL', color: 'text-red-700', bg: 'bg-red-100' }
    : { label: 'REVIEW', color: 'text-red-700', bg: 'bg-red-100' };
}

function gaugeColor(score: number): string {
  if (score < 30) return '#10b981'; // emerald
  if (score < 55) return '#f59e0b'; // amber
  if (score < 85) return '#ef4444'; // red
  return '#991b1b'; // dark red
}

function getHighestSeverity(findings: PatternFinding[]): Severity {
  for (const sev of SEVERITY_ORDER) {
    if (findings.some((f) => f.severity === sev)) return sev;
  }
  return 'low';
}

// ── Risk Score Gauge (SVG arc) ────────────────────────────────────────────────

function RiskGauge({ score, size = 80 }: { score: number; size?: number }) {
  const radius = (size - 10) / 2;
  const circumference = Math.PI * radius; // half circle
  const filled = (score / 100) * circumference;
  const color = gaugeColor(score);
  const level = riskScoreLevel(score);

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size / 2 + 10} viewBox={`0 0 ${size} ${size / 2 + 10}`}>
        {/* Background arc */}
        <path
          d={`M 5 ${size / 2 + 5} A ${radius} ${radius} 0 0 1 ${size - 5} ${size / 2 + 5}`}
          fill="none"
          stroke="currentColor"
          className="text-muted/30"
          strokeWidth="6"
          strokeLinecap="round"
        />
        {/* Filled arc */}
        <path
          d={`M 5 ${size / 2 + 5} A ${radius} ${radius} 0 0 1 ${size - 5} ${size / 2 + 5}`}
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
        />
        {/* Score text */}
        <text
          x={size / 2}
          y={size / 2}
          textAnchor="middle"
          className="fill-foreground font-mono font-semibold"
          fontSize="18"
        >
          {score}
        </text>
        <text
          x={size / 2}
          y={size / 2 + 10}
          textAnchor="middle"
          className="fill-muted-foreground"
          fontSize="8"
        >
          / 100
        </text>
      </svg>
      <span
        className={cn(
          'text-[10px] font-semibold uppercase tracking-wider mt-0.5',
          RISK_META[level].color,
        )}
      >
        {RISK_META[level].label}
      </span>
    </div>
  );
}

// ── Finding Card ──────────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: PatternFinding }) {
  const [expanded, setExpanded] = useState(false);
  const confidencePct = Math.round(finding.confidence * 100);

  return (
    <div className="rounded-lg border bg-card overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2.5 px-4 py-3 text-xs hover:bg-muted/10 transition-colors text-left"
      >
        {/* Rule ID badge with category color */}
        <Badge
          variant="outline"
          className={cn(
            'text-[10px] font-mono shrink-0 font-semibold border',
            getRuleIdColor(finding.rule_id),
          )}
        >
          {finding.rule_id}
        </Badge>

        {/* Pattern name + one-line explanation */}
        <div className="flex-1 min-w-0">
          <span className="font-medium text-foreground">{finding.pattern_name}</span>
          <span className="text-muted-foreground ml-2 truncate text-[11px]">{finding.message}</span>
        </div>

        {/* File + line in monospace */}
        <span className="text-[10px] text-muted-foreground/60 font-mono shrink-0 hidden sm:inline-flex items-center gap-1">
          <FileCode className="h-3 w-3 inline" />
          {finding.file.split('/').pop()}:{finding.start_line}
        </span>

        {/* Confidence mini bar */}
        <div className="shrink-0 w-12 flex items-center gap-1">
          <div className="flex-1 h-1 bg-muted/30 rounded-full overflow-hidden">
            <div
              className={cn(
                'h-full rounded-full',
                SEVERITY_BAR_COLORS[finding.severity] ?? 'bg-sky-400',
              )}
              style={{ width: `${confidencePct}%` }}
            />
          </div>
          <span className="text-[9px] text-muted-foreground/60 font-mono w-6 text-right">
            {confidencePct}%
          </span>
        </div>

        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground/50 shrink-0" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/50 shrink-0" />
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-border/30 pt-3">
          {/* File + line */}
          <div className="text-xs flex items-center gap-2">
            <FolderOpen className="h-3.5 w-3.5 text-muted-foreground/50" />
            <code className="font-mono text-[11px] text-foreground bg-muted/20 px-2 py-0.5 rounded">
              {finding.file}
            </code>
            <span className="text-muted-foreground">line</span>
            <span className="font-mono text-foreground font-medium">{finding.start_line}</span>
          </div>

          {/* Matched text snippet */}
          {finding.matched_text && (
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 font-medium">
                Matched Text
              </p>
              <pre className="text-[11px] font-mono bg-muted/20 rounded-lg p-3 overflow-x-auto text-foreground whitespace-pre-wrap break-all border border-border/30">
                {finding.matched_text}
              </pre>
            </div>
          )}

          {/* Why this is dangerous */}
          <div className="p-3 bg-muted/20 rounded-lg text-xs border border-border/20">
            <p className="font-medium text-foreground mb-1 flex items-center gap-1.5">
              <CircleAlert className="h-3.5 w-3.5 text-amber-500" />
              Why this is dangerous
            </p>
            <p className="text-muted-foreground leading-relaxed">{finding.explanation}</p>
          </div>

          {/* Remediation */}
          <div className="p-3 bg-emerald-500/5 border border-emerald-500/20 rounded-lg text-xs">
            <p className="font-medium text-emerald-600 mb-1 flex items-center gap-1.5">
              <ShieldCheck className="h-3.5 w-3.5" />
              Remediation
            </p>
            <p className="text-muted-foreground leading-relaxed">{finding.remediation}</p>
          </div>

          {/* Confidence bar */}
          <div>
            <div className="flex items-center justify-between text-[10px] text-muted-foreground mb-1">
              <span>Confidence</span>
              <span className="font-mono font-medium">{confidencePct}%</span>
            </div>
            <div className="h-1.5 bg-muted/30 rounded-full overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-full transition-all',
                  SEVERITY_BAR_COLORS[finding.severity] ?? 'bg-sky-400',
                )}
                style={{ width: `${confidencePct}%` }}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Severity Group (expandable section) ───────────────────────────────────────

function SeverityGroup({ severity, findings }: { severity: Severity; findings: PatternFinding[] }) {
  const config = SEVERITY_CONFIG[severity];
  const [expanded, setExpanded] = useState(config.defaultExpanded);
  const Icon = config.icon;

  if (findings.length === 0) return null;

  return (
    <div className={cn('rounded-lg border overflow-hidden', config.border)}>
      <button
        onClick={() => setExpanded(!expanded)}
        className={cn(
          'w-full flex items-center gap-2.5 px-4 py-2.5 text-xs font-medium transition-colors',
          config.bg,
          config.color,
          'hover:opacity-90',
        )}
      >
        <Icon className="h-4 w-4 shrink-0" />
        <span className="uppercase tracking-wider font-semibold text-[11px]">{config.label}</span>
        <Badge
          variant="outline"
          className={cn('text-[10px] font-mono font-semibold ml-1', config.color, config.border)}
        >
          {findings.length}
        </Badge>
        <div className="flex-1" />
        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5 shrink-0 opacity-60" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 shrink-0 opacity-60" />
        )}
      </button>

      {expanded && (
        <div className="p-3 space-y-2 bg-card">
          {findings.map((f, i) => (
            <FindingCard key={`${f.rule_id}-${i}`} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Per-Skill Security Report Card ────────────────────────────────────────────

function SkillReportCard({ r }: { r: SkillRootResult }) {
  const [open, setOpen] = useState(true);
  const patFindings = r.pattern_findings ?? [];
  const injCount = r.injection_reports?.length ?? 0;
  const supCount = r.supply_findings?.length ?? 0;
  const totalFindings = patFindings.length + injCount + supCount;

  const riskScore = useMemo(() => computeRiskScore(patFindings), [patFindings]);
  const scoreLevel = riskScoreLevel(riskScore);
  // This panel scans a surface that is already installed and running, so it
  // gets review wording rather than install-time advice.
  const rec = recommendationBadge(computeRiskLevel(patFindings), 'installed');

  // Group findings by severity
  const bySeverity = useMemo(() => {
    const map: Record<Severity, PatternFinding[]> = { critical: [], high: [], medium: [], low: [] };
    for (const f of patFindings) {
      const sev = (f.severity as Severity) || 'low';
      if (map[sev]) map[sev].push(f);
      else map.low.push(f);
    }
    return map;
  }, [patFindings]);

  // Category counts with highest severity per category
  const categoryInfo = useMemo(() => {
    const map = new Map<string, { count: number; highestSev: Severity }>();
    for (const f of patFindings) {
      const existing = map.get(f.category);
      if (!existing) {
        map.set(f.category, { count: 1, highestSev: (f.severity as Severity) || 'low' });
      } else {
        existing.count++;
        const currentIdx = SEVERITY_ORDER.indexOf(existing.highestSev);
        const newIdx = SEVERITY_ORDER.indexOf((f.severity as Severity) || 'low');
        if (newIdx < currentIdx) existing.highestSev = (f.severity as Severity) || 'low';
      }
    }
    return map;
  }, [patFindings]);

  // Distinct category count for the summary line
  const categoryCount = categoryInfo.size;

  return (
    <div className="rounded-lg border bg-card overflow-hidden">
      {/* Header row */}
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-muted/5 transition-colors"
      >
        {/* Risk gauge */}
        <div className="shrink-0">
          <RiskGauge score={riskScore} size={72} />
        </div>

        {/* Skill info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm font-semibold text-foreground capitalize">{r.agent}</span>
            <span className="text-muted-foreground/40">/</span>
            <span className="text-xs text-muted-foreground">{r.kind}</span>
            {/* Recommendation badge */}
            <span
              className={cn(
                'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide',
                rec.bg,
                rec.color,
              )}
            >
              {(rec.label === 'DO NOT INSTALL' || rec.label === 'REVIEW') && (
                <Ban className="h-3 w-3" />
              )}
              {(rec.label === 'SAFE' || rec.label === 'CLEAN') && <ShieldCheck className="h-3 w-3" />}
              {(rec.label === 'CAUTION' || rec.label === 'ATTENTION') && (
                <AlertTriangle className="h-3 w-3" />
              )}
              {rec.label}
            </span>
          </div>
          <p className="text-[11px] text-muted-foreground/60 font-mono truncate">{r.path}</p>
          {/* Finding count summary */}
          {totalFindings > 0 ? (
            <p className="text-[11px] text-muted-foreground mt-1">
              <span className="font-medium text-foreground">{totalFindings}</span> issue
              {totalFindings !== 1 ? 's' : ''} across{' '}
              <span className="font-medium text-foreground">{categoryCount}</span> categor
              {categoryCount !== 1 ? 'ies' : 'y'}
            </p>
          ) : (
            <p className="text-[11px] text-emerald-600 mt-1 flex items-center gap-1">
              <CheckCircle className="h-3 w-3" />
              No issues found &mdash; {r.files_scanned} files scanned
            </p>
          )}
        </div>

        {/* Files scanned + chevron */}
        <div className="shrink-0 flex items-center gap-3">
          <span className="text-[10px] text-muted-foreground/50">{r.files_scanned} files</span>
          <span className="text-[10px] text-muted-foreground/40">owner: {r.owner}</span>
          {open ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground/40" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground/40" />
          )}
        </div>
      </button>

      {/* Expanded report body */}
      {open && totalFindings > 0 && (
        <div className="border-t border-border/30 px-5 py-4 space-y-4">
          {/* Category summary chips */}
          {categoryInfo.size > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {[...categoryInfo.entries()]
                .sort(
                  (a, b) =>
                    SEVERITY_ORDER.indexOf(a[1].highestSev) -
                    SEVERITY_ORDER.indexOf(b[1].highestSev),
                )
                .map(([cat, info]) => (
                  <span
                    key={cat}
                    className={cn(
                      'inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-semibold border',
                      CATEGORY_SEVERITY_COLORS[info.highestSev] ??
                        CATEGORY_COLORS[cat] ??
                        'bg-gray-100 text-gray-700 border-gray-200',
                    )}
                  >
                    {CATEGORY_LABELS[cat] ?? cat.replace(/_/g, ' ')}: {info.count}
                  </span>
                ))}
            </div>
          )}

          {/* Findings grouped by severity */}
          <div className="space-y-3">
            {SEVERITY_ORDER.map((sev) => (
              <SeverityGroup key={sev} severity={sev} findings={bySeverity[sev]} />
            ))}
          </div>

          {/* Legacy injection reports */}
          {injCount > 0 && (
            <div className="space-y-2">
              <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <FileWarning className="h-3.5 w-3.5 text-red-400" />
                Injection Reports
              </h4>
              {r.injection_reports?.map((ir, i) => (
                <div
                  key={`inj-${i}`}
                  className="flex items-start gap-2 text-xs rounded-lg border bg-red-50/30 px-3 py-2"
                >
                  <FileWarning className="h-3.5 w-3.5 mt-0.5 shrink-0 text-red-400" />
                  <div className="min-w-0">
                    <span className="font-mono text-[11px] text-foreground">
                      {ir.path.split('/').pop()}
                    </span>
                    <span className="text-red-500 ml-2 font-medium">prompt injection</span>
                    <p className="text-[10px] text-muted-foreground mt-0.5">
                      {ir.findings?.flatMap((f) => f.signals).join('; ') || 'flagged'}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Legacy supply findings */}
          {supCount > 0 && (
            <div className="space-y-2">
              <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <Package className="h-3.5 w-3.5 text-amber-400" />
                Supply Chain Findings
              </h4>
              {r.supply_findings?.map((sr, i) => (
                <div
                  key={`sup-${i}`}
                  className="flex items-start gap-2 text-xs rounded-lg border bg-amber-50/30 px-3 py-2"
                >
                  <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0 text-amber-400" />
                  <div className="min-w-0">
                    <span className="font-mono text-[11px] text-foreground">
                      {sr.path.split('/').pop()}
                    </span>
                    <span className="text-amber-500 ml-2 font-medium">
                      supply-chain [{sr.risk_level}]
                    </span>
                    <p className="text-[10px] text-muted-foreground mt-0.5">
                      {sr.findings?.map((f) => `${f.kind}: ${f.detail}`).join('; ') || 'flagged'}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main Skills Component ───────────────────────────────────────────────────

export default function Skills() {
  const { scanSkillsAuto } = useStore();
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<SkillScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runScan = async () => {
    setScanning(true);
    setError(null);
    try {
      setResult(await scanSkillsAuto());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  // Aggregate all pattern findings
  const allPatternFindings = useMemo(() => {
    if (!result) return [];
    return result.results.flatMap((r) => r.pattern_findings ?? []);
  }, [result]);

  const totalRiskScore = useMemo(() => computeRiskScore(allPatternFindings), [allPatternFindings]);
  const totalScoreLevel = riskScoreLevel(totalRiskScore);
  const totalRiskLevel = useMemo(() => computeRiskLevel(allPatternFindings), [allPatternFindings]);

  // Severity breakdown for overall summary
  const severityBreakdown = useMemo(() => {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of allPatternFindings) {
      const sev = (f.severity as Severity) || 'low';
      if (counts[sev] !== undefined) counts[sev]++;
      else counts.low++;
    }
    return counts;
  }, [allPatternFindings]);

  // Category summary across all surfaces
  const totalCategoryInfo = useMemo(() => {
    const map = new Map<string, { count: number; highestSev: Severity }>();
    for (const f of allPatternFindings) {
      const existing = map.get(f.category);
      if (!existing) {
        map.set(f.category, { count: 1, highestSev: (f.severity as Severity) || 'low' });
      } else {
        existing.count++;
        const currentIdx = SEVERITY_ORDER.indexOf(existing.highestSev);
        const newIdx = SEVERITY_ORDER.indexOf((f.severity as Severity) || 'low');
        if (newIdx < currentIdx) existing.highestSev = (f.severity as Severity) || 'low';
      }
    }
    return map;
  }, [allPatternFindings]);

  const agents = result ? [...new Set(result.results.map((r) => r.agent))] : [];

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header + Scan Button */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Shield className="h-5 w-5 text-primary" />
            <h2 className="text-lg font-semibold tracking-tight">Agent Skills Audit</h2>
          </div>
          <p className="text-xs text-muted-foreground">
            Discover every installed AI agent's skills, plugins, rules and MCP configs, and scan
            them for prompt injection &amp; supply-chain risk.
          </p>
        </div>
        <Button
          size="sm"
          className="h-10 gap-2 px-5 font-medium"
          onClick={runScan}
          disabled={scanning}
        >
          {scanning ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <ScanLine className="h-4 w-4" />
          )}
          {scanning ? 'Scanning...' : 'Scan All Agent Skills'}
        </Button>
      </div>

      {/* Error state */}
      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-400 flex items-center gap-2">
          <ShieldX className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {/* Empty state — no scan run yet */}
      {!result && !scanning && (
        <div className="rounded-lg border border-dashed bg-card/50 p-16 text-center">
          <Gauge className="h-10 w-10 mx-auto mb-4 text-muted-foreground/20" />
          <p className="text-sm text-muted-foreground font-medium mb-1">
            Scan agent skills to detect security vulnerabilities before they run
          </p>
          <p className="text-xs text-muted-foreground/50">
            Covers Claude, Cursor, Windsurf, Gemini, Continue, Codex, Aider — across all users.
          </p>
        </div>
      )}

      {/* Scanning state */}
      {scanning && !result && (
        <div className="rounded-lg border bg-card/50 p-16 text-center">
          <Loader2 className="h-10 w-10 mx-auto mb-4 text-primary animate-spin" />
          <p className="text-sm text-muted-foreground font-medium">
            Scanning agent skill surfaces...
          </p>
          <p className="text-xs text-muted-foreground/50 mt-1">
            Enumerating skills, plugins, MCP configs and running SkillSpector patterns
          </p>
        </div>
      )}

      {/* Results */}
      {result && (
        <>
          {/* Overall summary banner */}
          {allPatternFindings.length > 0 && (
            <div
              className={cn(
                'rounded-lg border p-5 flex items-center gap-5',
                totalScoreLevel === 'critical' && 'bg-red-500/5 border-red-500/30',
                totalScoreLevel === 'high' && 'bg-orange-500/5 border-orange-500/30',
                totalScoreLevel === 'medium' && 'bg-amber-500/5 border-amber-500/30',
                totalScoreLevel === 'low' && 'bg-sky-500/5 border-sky-500/30',
                totalScoreLevel === 'clean' && 'bg-emerald-500/5 border-emerald-500/30',
              )}
            >
              {/* Overall gauge */}
              <div className="shrink-0">
                <RiskGauge score={totalRiskScore} size={90} />
              </div>

              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-foreground mb-1.5">
                  {allPatternFindings.length} finding{allPatternFindings.length !== 1 ? 's' : ''}{' '}
                  across {totalCategoryInfo.size} categor
                  {totalCategoryInfo.size !== 1 ? 'ies' : 'y'}
                </p>

                {/* Severity breakdown */}
                <div className="flex items-center gap-3 mb-2">
                  {SEVERITY_ORDER.map((sev) => {
                    const count = severityBreakdown[sev];
                    if (count === 0) return null;
                    const config = SEVERITY_CONFIG[sev];
                    return (
                      <span key={sev} className={cn('text-[11px] font-semibold', config.color)}>
                        {count} {config.label}
                      </span>
                    );
                  })}
                </div>

                {/* Category chips */}
                <div className="flex flex-wrap gap-1.5">
                  {[...totalCategoryInfo.entries()]
                    .sort(
                      (a, b) =>
                        SEVERITY_ORDER.indexOf(a[1].highestSev) -
                        SEVERITY_ORDER.indexOf(b[1].highestSev),
                    )
                    .map(([cat, info]) => (
                      <span
                        key={cat}
                        className={cn(
                          'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border',
                          CATEGORY_SEVERITY_COLORS[info.highestSev] ??
                            CATEGORY_COLORS[cat] ??
                            'bg-gray-100 text-gray-700 border-gray-200',
                        )}
                      >
                        {CATEGORY_LABELS[cat] ?? cat.replace(/_/g, ' ')}: {info.count}
                      </span>
                    ))}
                </div>
              </div>

              {/* Recommendation badge */}
              <div className="shrink-0 text-right">
                {(() => {
                  const rec = recommendationBadge(totalRiskLevel, 'installed');
                  return (
                    <span
                      className={cn(
                        'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold uppercase tracking-wide',
                        rec.bg,
                        rec.color,
                      )}
                    >
                      {(rec.label === 'DO NOT INSTALL' || rec.label === 'REVIEW') && (
                        <Ban className="h-3.5 w-3.5" />
                      )}
                      {(rec.label === 'SAFE' || rec.label === 'CLEAN') && (
                        <ShieldCheck className="h-3.5 w-3.5" />
                      )}
                      {(rec.label === 'CAUTION' || rec.label === 'ATTENTION') && (
                        <AlertTriangle className="h-3.5 w-3.5" />
                      )}
                      {rec.label}
                    </span>
                  );
                })()}
              </div>
            </div>
          )}

          {/* Summary stat cards */}
          <div className="grid grid-cols-4 gap-3">
            <div className="rounded-lg border bg-card px-4 py-3.5">
              <p className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                Surfaces
              </p>
              <p className="text-xl font-semibold font-mono tabular-nums">{result.roots_found}</p>
              <p className="text-[10px] text-muted-foreground/60 mt-0.5 truncate">
                {agents.length ? agents.join(', ') : '--'}
              </p>
            </div>
            <div className="rounded-lg border bg-card px-4 py-3.5">
              <p className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                Files Scanned
              </p>
              <p className="text-xl font-semibold font-mono tabular-nums">{result.files_scanned}</p>
            </div>
            <div className="rounded-lg border bg-card px-4 py-3.5">
              <p className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                Total Findings
              </p>
              <p
                className={cn(
                  'text-xl font-semibold font-mono tabular-nums',
                  allPatternFindings.length > 0
                    ? RISK_META[totalScoreLevel].color
                    : 'text-emerald-400',
                )}
              >
                {allPatternFindings.length}
              </p>
            </div>
            <div className="rounded-lg border bg-card px-4 py-3.5">
              <p className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                Risk Score
              </p>
              <p
                className={cn(
                  'text-xl font-semibold font-mono tabular-nums',
                  RISK_META[totalScoreLevel].color,
                )}
              >
                {totalRiskScore}
                <span className="text-sm text-muted-foreground/50">/100</span>
              </p>
            </div>
          </div>

          {/* Per-skill report cards */}
          {result.results.length === 0 ? (
            <div className="rounded-lg border border-dashed bg-card/50 p-12 text-center text-sm text-muted-foreground">
              <Package className="h-8 w-8 mx-auto mb-3 text-muted-foreground/30" />
              No AI agent skill surfaces found on this host.
            </div>
          ) : (
            <div className="space-y-4">
              <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <Eye className="h-3.5 w-3.5" />
                Security Report by Skill
              </h3>
              {result.results.map((r, i) => (
                <SkillReportCard key={i} r={r} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
