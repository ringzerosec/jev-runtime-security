// SPDX-License-Identifier: Apache-2.0
import { useState } from 'react';
import { useStore } from '../store';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { cn } from '../lib/utils';
import { threatCategoryLabel } from '../lib/threatCategories';
import { describeRefusal, type RefusalEvent } from '../lib/refusals';
import {
  ShieldCheck,
  Lock,
  FileKey,
  Globe,
  Terminal,
  Check,
  Ban,
  ChevronDown,
  ChevronRight,
  ArrowLeft,
  Shield,
  X,
} from 'lucide-react';

type Event = {
  id: string;
  type: string;
  skill_name: string;
  target: string;
  allowed: boolean;
  reason?: string;
  timestamp: string;
  category?: string;
  classified_by?: string;
};

// Benign file patterns that should not appear as threats — these are normal
// runtime file reads from Node.js, Python, etc.
const BENIGN_PATTERNS = [
  /\.js$/, // JS modules (walk.js, acorn.js, lexer.js, etc.)
  /\.mjs$/,
  /\.cjs$/,
  /\.ts$/,
  /\.json$/,
  /\.node$/, // native addons
  /node_modules\//,
  /\.npm\//,
  /\.nvm\//,
  /\/usr\/lib\//,
  /\/usr\/bin\/node/,
  /\/usr\/bin\/python/,
  /\/usr\/bin\/deno/,
  /\/proc\/meminfo/,
  /\/proc\/version/,
  /\/proc\/cpuinfo/,
  /\/proc\/self\//,
  /\/proc\/\d+\//,
  /\/sys\/fs\/cgroup/,
  /\.so(\.\d+)*$/, // shared libraries
  /\.pyc$/,
  /version_signature/,
  /index\.bundle/,
  /package\.json$/,
  /\.cache\//,
  /\.local\//,
  /\/tmp\//,
  /\.cargo\//,
];

function isBenign(target: string): boolean {
  if (!target) return false;
  return BENIGN_PATTERNS.some((p) => p.test(target));
}

const AGENT_LABELS: Record<string, string> = {
  claude: 'Claude Code',
  codex: 'Codex CLI',
  gemini: 'Gemini CLI',
  cursor: 'Cursor',
  copilot: 'GitHub Copilot',
  opencode: 'opencode',
  windsurf: 'Windsurf',
};
function agentLabel(process?: string): string {
  if (!process) return '';
  const p = process.toLowerCase();
  const hit = Object.keys(AGENT_LABELS).find((k) => p === k || p.startsWith(k));
  return hit ? AGENT_LABELS[hit] : process;
}

export default function Threats({ onNavigate }: { onNavigate?: (page: 'policy') => void } = {}) {
  const { refusals } = useStore();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  // Reviewed is a per-viewer note ("I've looked at this"), kept in this
  // browser. Every item here was already refused; reviewing changes nothing.
  const [resolvedIds, setResolvedIds] = useState<Set<string>>(() => {
    try {
      return new Set<string>(JSON.parse(localStorage.getItem('rz_reviewed_refusals') ?? '[]'));
    } catch {
      return new Set<string>();
    }
  });
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);

  const getSeverity = (event: Event) => {
    const kind = event.type?.toLowerCase() || '';
    // Critical: attack chain, offensive prompt, mprotect W→X
    if (kind === 'attack_chain') return 'critical';
    if (kind === 'offensive_prompt') return 'critical';
    if (kind === 'mprotect_wx') return 'high';
    const t = event.target?.toLowerCase() || '';
    // Critical: sensitive credential files
    if (t.match(/id_rsa|id_ed25519|credentials|shadow/)) return 'critical';
    // High: secrets/env files or network activity
    if (t.match(/\.env|passwd|secret|token/)) return 'high';
    if (kind.includes('network')) return 'high';
    // Check if this is benign child process noise before marking medium
    if (isBenign(event.target)) return 'low';
    const proc = event.skill_name?.toLowerCase() || '';
    if (['node', 'npm', 'npx', 'python', 'python3', 'pip', 'deno', 'bun'].includes(proc)) {
      // Known runtime child processes — not threats unless touching sensitive files
      return 'low';
    }
    if (kind.includes('process')) return 'medium';
    return 'low';
  };

  // Every refusal is listed. Severity orders and labels them; it never hides
  // one: if the kernel refused it, the notice that pointed here must find it.
  const displayThreats = refusals;
  const active = displayThreats.filter((e) => !resolvedIds.has(e.id));
  const resolved = displayThreats.filter((e) => resolvedIds.has(e.id));

  const getSeverityStyle = (sev: string) => {
    switch (sev) {
      case 'critical':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'high':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'medium':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      default:
        return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
    }
  };

  const getIcon = (event: Event) => {
    const kind = event.type?.toLowerCase() || '';
    if (kind.includes('network')) return Globe;
    if (kind.includes('process')) return Terminal;
    return FileKey;
  };

  const getDescription = (event: Event) => {
    const t = event.target?.toLowerCase() || '';
    if (t.startsWith('pkg_install:')) return 'Package install refused';
    if (t.startsWith('mcp_held:')) return 'New MCP server held';
    if (t.startsWith('mcp_tool:')) return 'MCP tool refused';
    if (t.endsWith(':prompt-secret')) return 'Secret blocked in a prompt';
    if (t.startsWith('tamper:') || t.includes('tamper:')) return 'Tamper attempt refused';
    if (/(^|\/)(api-token|daemon\.toml|profiles\.json|file-access-rules\.json|ringzero-daemon\.service)$/.test(t))
      return "Agent refused Ring Zero's own files";
    if (t.includes('id_rsa') || t.includes('id_ed25519')) return 'SSH private key access attempt';
    if (t.includes('credentials')) return 'Cloud credentials access attempt';
    if (t.includes('.env')) return 'Environment secrets access attempt';
    if (t.includes('passwd')) return 'System password file access attempt';
    if (t.includes('shadow')) return 'Shadow password file access attempt';
    if (t.includes('token') || t.includes('secret')) return 'Secret/token access attempt';
    const kind = event.type?.toLowerCase() || '';
    if (kind.includes('process') && !event.allowed) {
      if (event.category === 'privilege_escalation') return 'Agent refused an admin tool';
      if (event.category === 'rogue_agent') return 'Agent refused work outside its own process';
    }
    if (kind.includes('file') && !event.allowed && event.category === 'memory_poisoning')
      return "Agent refused a change to an agent's instructions";
    // Everything listed here was refused; say so rather than "suspicious".
    if (kind.includes('network')) return event.allowed ? 'Outbound network connection flagged' : 'Connection refused';
    if (kind.includes('process')) return event.allowed ? 'Suspicious process spawn detected' : 'Program refused';
    return event.allowed ? 'Suspicious file access detected' : 'File access refused';
  };

  // The line under a threat's title: who did it, and what it touched, in
  // words rather than the raw event target.
  const getSubject = (event: Event) => {
    const who = agentLabel((event as { process?: string }).process ?? event.skill_name);
    const t = event.target || '';
    if (t.startsWith('PKG_INSTALL:')) return `${who} · ${t.slice('PKG_INSTALL:'.length)}`;
    if (t.startsWith('MCP_HELD:')) return `${who} · ${t.slice('MCP_HELD:'.length)} · waiting for approval`;
    if (t.startsWith('MCP_TOOL:')) return `${who} · ${t.slice('MCP_TOOL:'.length).replace('/', ' · ')}`;
    if (t.endsWith(':prompt-secret')) return `${who} · the secret was masked and the prompt not sent`;
    if (t.startsWith('TAMPER:') || t.includes('TAMPER:')) return `${who} · ${t.replace(/^.*TAMPER:/, '').replace(/_/g, ' ')}`;
    return who ? `${who} · ${t}` : t;
  };

  const markResolved = (id: string) => {
    const next = new Set([...resolvedIds, id]);
    setResolvedIds(next);
    try {
      localStorage.setItem('rz_reviewed_refusals', JSON.stringify([...next].slice(-1000)));
    } catch {
      /* per-viewer convenience only */
    }
    if (selectedEvent?.id === id) setSelectedEvent(null);
  };

  // --- Detail view ---
  if (selectedEvent) {
    const e = selectedEvent;
    const severity = getSeverity(e);
    const Icon = getIcon(e);

    return (
      <div className="space-y-4 max-w-3xl">
        <button
          onClick={() => setSelectedEvent(null)}
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft className="h-3 w-3" /> Back to Security history
        </button>

        <div className="rounded-lg border bg-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Lock className="h-4 w-4 text-red-400" />
            <h3 className="text-sm font-semibold text-foreground">{getDescription(e)}</h3>
            <Badge className={cn('text-[10px] px-1.5 border', getSeverityStyle(severity))}>
              {severity.toUpperCase()}
            </Badge>
          </div>

          <div className="grid grid-cols-2 gap-4 text-xs mb-4">
            {e.category && (
              <div className="col-span-2">
                <p className="text-muted-foreground mb-0.5">Category</p>
                <p className="text-foreground">
                  {threatCategoryLabel(e.category)}
                  <span className="text-muted-foreground">
                    {' '}· labelled by {e.classified_by === 'rules' || !e.classified_by ? 'built-in rules' : e.classified_by}
                  </span>
                </p>
              </div>
            )}
            <div>
              <p className="text-muted-foreground mb-0.5">Target</p>
              <code className="text-foreground font-mono text-[11px] break-all">{e.target?.replace(/^PKG_INSTALL:/, '')}</code>
            </div>
            <div>
              <p className="text-muted-foreground mb-0.5">Process</p>
              <p className="text-foreground font-mono">{e.skill_name || 'node'}</p>
            </div>
            <div>
              <p className="text-muted-foreground mb-0.5">Type</p>
              <p className="text-foreground">{e.type || 'File Access'}</p>
            </div>
            <div>
              <p className="text-muted-foreground mb-0.5">Timestamp</p>
              <p className="text-foreground">{new Date(e.timestamp).toLocaleString()}</p>
            </div>
            <div>
              <p className="text-muted-foreground mb-0.5">Severity</p>
              <Badge className={cn('text-[10px] px-1.5 border', getSeverityStyle(severity))}>
                {severity.toUpperCase()}
              </Badge>
            </div>
            <div>
              <p className="text-muted-foreground mb-0.5">Action Taken</p>
              <p className={cn('font-medium', e.allowed ? 'text-amber-500' : 'text-red-400')}>
                {e.allowed ? 'Flagged — allowed by policy' : 'Refused before it happened'}
              </p>
            </div>
          </div>

          {e.reason && (
            <div className="p-3 bg-muted/30 rounded-lg text-xs text-muted-foreground mb-4">
              <p className="font-medium text-foreground mb-1">Reason</p>
              <p className="font-mono text-[11px]">{e.reason}</p>
            </div>
          )}

          <div className="p-3 bg-muted/30 rounded-lg text-xs text-muted-foreground mb-4">
            <p className="font-medium text-foreground mb-1">Analysis</p>
            <p>
              Process <code className="text-foreground">{e.skill_name || 'node'}</code>{' '}
              {e.allowed ? 'accessed' : 'attempted to access'}{' '}
              <code className="text-foreground">{e.target?.replace(/^PKG_INSTALL:/, '')}</code>.
              {severity === 'critical' && ' This is a highly sensitive credential file.'}
              {severity === 'high' && ' This file may contain secrets or credentials.'}
              {severity === 'medium' && ' This operation was flagged by policy rules.'}
              {severity === 'low' &&
                ' This is a low-severity event that may be routine process behavior.'}
            </p>
          </div>

          <div className="flex flex-wrap gap-2 pt-3 border-t border-border/50">
            {describeRefusal(e as unknown as RefusalEvent).changeable && onNavigate && (
              <Button size="sm" variant="secondary" className="h-7 text-xs" onClick={() => onNavigate('policy')}>
                <Shield className="h-3 w-3 mr-1" />
                Change rule
              </Button>
            )}
            {!resolvedIds.has(e.id) && (
              <Button size="sm" variant="secondary" className="h-7 text-xs" onClick={() => markResolved(e.id)}>
                <Check className="h-3 w-3 mr-1" />
                Mark reviewed
              </Button>
            )}
          </div>
        </div>

      </div>
    );
  }

  // --- List view ---
  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h2 className="text-lg font-semibold tracking-tight">Security history</h2>
        <div className="flex items-center gap-3">
          <p className="text-xs text-muted-foreground">
            {displayThreats.length === 0
              ? 'Nothing refused in the last 24 hours'
              : `${displayThreats.length} refused in the last 24 hours, before they happened · ${active.length} to review`}
          </p>
        </div>
      </div>

      {active.length === 0 && resolved.length === 0 ? (
        <div className="text-center py-16">
          <ShieldCheck className="h-8 w-8 mx-auto mb-3 text-emerald-400 opacity-60" />
          <p className="text-sm text-muted-foreground">Nothing refused in the last 24 hours</p>
          <p className="text-xs text-muted-foreground/60 mt-1">Whatever Ring Zero Security refuses appears here</p>
        </div>
      ) : null}

      {/* Active threats */}
      {active.length > 0 && (
        <div className="space-y-2">
          {active.map((event) => {
            const severity = getSeverity(event);
            const Icon = getIcon(event);

            return (
              <div
                key={event.id}
                className={cn(
                  'rounded-lg border bg-card transition-all',
                  severity === 'critical' && 'border-red-500/20',
                  severity === 'high' && 'border-orange-500/20',
                )}
              >
                <button
                  onClick={() => setSelectedEvent(event)}
                  className="w-full flex items-center gap-3 px-4 py-3 text-left"
                >
                  <Lock className="h-3.5 w-3.5 text-red-400 shrink-0" />
                  <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-foreground truncate">
                        {getDescription(event)}
                      </span>
                      <Badge
                        className={cn('text-[10px] px-1.5 border', getSeverityStyle(severity))}
                      >
                        {severity.toUpperCase()}
                      </Badge>
                      {event.category && (
                        <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] text-muted-foreground shrink-0">
                          {threatCategoryLabel(event.category)}
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] text-muted-foreground truncate">
                      {getSubject(event)}
                    </div>
                  </div>
                  <span className="text-[10px] text-muted-foreground/60 shrink-0">
                    {new Date(event.timestamp).toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                    })}
                  </span>
                  <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/40 shrink-0" />
                </button>
              </div>
            );
          })}
        </div>
      )}

      {/* Resolved */}
      {resolved.length > 0 && (
        <div>
          <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">
            Reviewed
          </h3>
          <div className="space-y-1">
            {resolved.map((event) => (
              <div
                key={event.id}
                className="flex items-center gap-3 px-4 py-2 rounded-lg bg-muted/20 text-xs"
              >
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <span className="text-muted-foreground flex-1 truncate">
                  {getDescription(event)}
                </span>
                <code className="text-[10px] text-muted-foreground/60 truncate max-w-48">
                  {event.target?.replace(/^PKG_INSTALL:/, '')}
                </code>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
