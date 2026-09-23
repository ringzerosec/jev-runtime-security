// SPDX-License-Identifier: Apache-2.0
import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useStore } from '../store';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { cn } from '../lib/utils';
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
  Eye,
} from 'lucide-react';
import { useTokenScope } from '@/hooks/use-token-scope';
import { toast } from './ui/toast';

type Event = {
  id: string;
  type: string;
  skill_name: string;
  target: string;
  allowed: boolean;
  reason?: string;
  timestamp: string;
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

export default function Threats() {
  const { readOnly: threatsReadOnly } = useTokenScope();
  const { events } = useStore();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [resolvedIds, setResolvedIds] = useState<Set<string>>(new Set());
  const [whitelistedPaths, setWhitelistedPaths] = useState<Set<string>>(new Set());
  const [trustedProcesses, setTrustedProcesses] = useState<Set<string>>(new Set());
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [showBenign, setShowBenign] = useState(false);

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

  const blocked = events.filter((e) => !e.allowed);
  // Filter out LOW severity threats (benign runtime noise) unless user opts in
  const realThreats = blocked.filter((e) => getSeverity(e) !== 'low');
  const lowCount = blocked.length - realThreats.length;
  const displayThreats = showBenign ? blocked : realThreats;
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
    if (t.includes('id_rsa') || t.includes('id_ed25519')) return 'SSH private key access attempt';
    if (t.includes('credentials')) return 'Cloud credentials access attempt';
    if (t.includes('.env')) return 'Environment secrets access attempt';
    if (t.includes('passwd')) return 'System password file access attempt';
    if (t.includes('shadow')) return 'Shadow password file access attempt';
    if (t.includes('token') || t.includes('secret')) return 'Secret/token access attempt';
    const kind = event.type?.toLowerCase() || '';
    if (kind.includes('network')) return 'Outbound network connection flagged';
    if (kind.includes('process')) return 'Suspicious process spawn detected';
    return 'Suspicious file access detected';
  };

  const markResolved = (id: string) => {
    setResolvedIds(new Set([...resolvedIds, id]));
    if (selectedEvent?.id === id) setSelectedEvent(null);
  };

  const whitelistPath = (event: Event) => {
    const filename = event.target?.split('/').pop() || '';
    // Unblocking a path is a policy change. With the read-only token the
    // daemon would return 403, so say what to run instead of failing silently.
    if (threatsReadOnly) {
      toast({
        variant: 'warning',
        title: 'Needs root',
        description: `Run: sudo rz file-access remove <id>  (path: ${filename})`,
      });
      return;
    }
    setWhitelistedPaths(new Set([...whitelistedPaths, filename]));
    try {
      invoke('update_policy', { policy: { action: 'unblock_file', name: filename } });
    } catch {}
    markResolved(event.id);
  };

  const trustProcess = (event: Event) => {
    const proc = event.skill_name || 'node';
    setTrustedProcesses(new Set([...trustedProcesses, proc]));
    markResolved(event.id);
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
          <ArrowLeft className="h-3 w-3" /> Back to Threats
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
            <div>
              <p className="text-muted-foreground mb-0.5">Target</p>
              <code className="text-foreground font-mono text-[11px] break-all">{e.target}</code>
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
                {e.allowed ? 'Flagged — allowed by policy' : 'Blocked by security policy'}
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
              <code className="text-foreground">{e.target}</code>.
              {severity === 'critical' && ' This is a highly sensitive credential file.'}
              {severity === 'high' && ' This file may contain secrets or credentials.'}
              {severity === 'medium' && ' This operation was flagged by policy rules.'}
              {severity === 'low' &&
                ' This is a low-severity event that may be routine process behavior.'}
            </p>
          </div>

          <div className="flex flex-wrap gap-2 pt-3 border-t border-border/50">
            <Button
              size="sm"
              variant="secondary"
              className="h-7 text-xs"
              onClick={() => whitelistPath(e)}
            >
              <ShieldCheck className="h-3 w-3 mr-1" />
              Whitelist Path
            </Button>
            <Button
              size="sm"
              variant="secondary"
              className="h-7 text-xs"
              onClick={() => trustProcess(e)}
            >
              <Shield className="h-3 w-3 mr-1" />
              Trust Process
            </Button>
            <Button
              size="sm"
              variant="secondary"
              className="h-7 text-xs"
              onClick={() => markResolved(e.id)}
            >
              <Check className="h-3 w-3 mr-1" />
              Dismiss
            </Button>
          </div>
        </div>

        {/* Whitelisted / Trusted summary */}
        {(whitelistedPaths.size > 0 || trustedProcesses.size > 0) && (
          <div className="rounded-lg border bg-card p-4 text-xs">
            {whitelistedPaths.size > 0 && (
              <div className="mb-2">
                <p className="text-muted-foreground mb-1">Whitelisted paths:</p>
                <div className="flex flex-wrap gap-1">
                  {[...whitelistedPaths].map((p) => (
                    <Badge
                      key={p}
                      variant="outline"
                      className="text-[10px] border-emerald-500/30 text-emerald-400"
                    >
                      {p}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            {trustedProcesses.size > 0 && (
              <div>
                <p className="text-muted-foreground mb-1">Trusted processes:</p>
                <div className="flex flex-wrap gap-1">
                  {[...trustedProcesses].map((p) => (
                    <Badge
                      key={p}
                      variant="outline"
                      className="text-[10px] border-emerald-500/30 text-emerald-400"
                    >
                      {p}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  // --- List view ---
  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-lg font-semibold tracking-tight">Threats</h2>
        <div className="flex items-center gap-3">
          <p className="text-xs text-muted-foreground">
            {active.length} active · {resolved.length} resolved
          </p>
          {lowCount > 0 && (
            <button
              onClick={() => setShowBenign(!showBenign)}
              className="text-[10px] text-muted-foreground/60 hover:text-muted-foreground transition-colors flex items-center gap-1"
            >
              <Eye className="h-3 w-3" />
              {showBenign ? 'Hide' : 'Show'} {lowCount} low severity
            </button>
          )}
        </div>
      </div>

      {active.length === 0 && resolved.length === 0 ? (
        <div className="text-center py-16">
          <ShieldCheck className="h-8 w-8 mx-auto mb-3 text-emerald-400 opacity-60" />
          <p className="text-sm text-muted-foreground">No threats detected</p>
          <p className="text-xs text-muted-foreground/60 mt-1">Security events will appear here</p>
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
                    </div>
                    <code className="text-[11px] text-muted-foreground truncate block">
                      {event.target}
                    </code>
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
            Resolved
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
                  {event.target}
                </code>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
