// SPDX-License-Identifier: Apache-2.0
import { useState, useEffect, useCallback, useRef } from 'react';
import { daemonFetch } from '../lib/daemonApi';
import type { Page } from '../App';
import { useStore, type EnforcementCategories } from '../store';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { cn } from '../lib/utils';
import AgentIcon, { guessAgent } from './AgentIcon';
import {
  Shield,
  ShieldOff,
  ShieldCheck,
  ShieldAlert,
  Users,
  KeyRound,
  Upload,
  MessageSquareWarning,
  Package,
  Maximize2,
  FileOutput,
  BrainCircuit,
  Wrench,
  Bot,
  Eye,
  Plug,
  AlertTriangle,
  ChevronRight,
  Activity,
  Scan,
  Lock,
  FileWarning,
} from 'lucide-react';

// ── Types ─────────────────────────────────────────────────────────────────────

type SessionState = 'PENDING' | 'ACTIVE' | 'WAITING_APPROVAL' | 'EXPIRED' | 'TERMINATED';

function normalizeAgentType(type: string | Record<string, string>): string {
  if (typeof type === 'string') return type.toLowerCase();
  if (typeof type === 'object' && type !== null) {
    const val = (type as Record<string, string>).custom;
    return typeof val === 'string' ? val.toLowerCase() : 'custom';
  }
  return 'custom';
}

interface Session {
  id: string;
  agent_type: string | Record<string, string>;
  actor: string;
  declared_scope: string[];
  state: SessionState;
  privileged: boolean;
  start_time: string;
  end_time: string | null;
  event_count: number;
}

type Event = {
  id: string;
  type: string;
  skill_name: string;
  target: string;
  allowed: boolean;
  timestamp: string;
};

// Category icon mapping (matches Enforcement.tsx)
const CATEGORY_ICONS: Record<keyof EnforcementCategories, typeof KeyRound> = {
  credential_access: KeyRound,
  data_exfiltration: Upload,
  privilege_escalation: ShieldAlert,
  prompt_injection: MessageSquareWarning,
  supply_chain: Package,
  excessive_agency: Maximize2,
  output_handling: FileOutput,
  memory_poisoning: BrainCircuit,
  tool_misuse: Wrench,
  rogue_agent: Bot,
  system_prompt_leakage: Eye,
  mcp_tool_poisoning: Plug,
  harmful_content: AlertTriangle,
};

const CATEGORY_LABELS: Record<keyof EnforcementCategories, string> = {
  credential_access: 'Credential Access',
  data_exfiltration: 'Data Exfiltration',
  privilege_escalation: 'Privilege Escalation',
  prompt_injection: 'Prompt Injection',
  supply_chain: 'Supply Chain',
  excessive_agency: 'Excessive Agency',
  output_handling: 'Output Handling',
  memory_poisoning: 'Memory Poisoning',
  tool_misuse: 'Tool Misuse',
  rogue_agent: 'Rogue Agent',
  system_prompt_leakage: 'Prompt Leakage',
  mcp_tool_poisoning: 'MCP Poisoning',
  harmful_content: 'Harmful Content',
};

// Noise filters for recent events
const NOISE_TARGETS = [
  /etilqs_/,
  /sqlx-sqlite-wor/,
  /\/proc\/stat$/,
  /\/proc\/\d+\/fd\//,
  /\/dev\/null/,
  /pipe:\[/,
];
const NOISE_PROCESSES = ['systemd', 'journald', 'snapd', 'systemd-journal', 'systemd-resolved'];

function isNoiseEvent(e: Event): boolean {
  const target = e.target || '';
  const proc = e.skill_name || '';
  if (NOISE_PROCESSES.includes(proc.toLowerCase())) return true;
  if (NOISE_TARGETS.some((p) => p.test(target))) return true;
  return false;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const DAEMON_API = 'http://127.0.0.1:7700/api/v1';

function elapsed(start: string, end: string | null) {
  const from = new Date(start).getTime();
  const to = end ? new Date(end).getTime() : Date.now();
  const secs = Math.floor((to - from) / 1000);
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export default function Dashboard({ onNavigate }: { onNavigate?: (page: Page) => void }) {
  const { events, daemonConnected, status, fetchStatus, skills, enforcement, fetchEnforcement } =
    useStore();
  const [sessions, setSessions] = useState<Session[]>([]);
  const [daemonHint, setDaemonHint] = useState<string | null>(null);
  const retryRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Auto-retry: poll every 5s when daemon is disconnected
  useEffect(() => {
    if (!daemonConnected) {
      retryRef.current = setInterval(() => {
        fetchStatus();
      }, 5000);
    } else {
      setDaemonHint(null);
    }
    return () => {
      if (retryRef.current) clearInterval(retryRef.current);
    };
  }, [daemonConnected, fetchStatus]);

  // Fetch enforcement on mount
  useEffect(() => {
    fetchEnforcement();
  }, [fetchEnforcement]);

  const handleStartDaemon = async () => {
    setDaemonHint(null);
    try {
      const resp = await daemonFetch(`${DAEMON_API}/status`);
      if (resp.ok) {
        await fetchStatus();
        return;
      }
    } catch {
      /* not reachable */
    }
    setDaemonHint('Run: sudo systemctl start ringzero-daemon');
  };

  // Fetch sessions
  const fetchSessions = useCallback(async () => {
    try {
      const resp = await daemonFetch(`${DAEMON_API}/sessions`);
      if (resp.ok) {
        const data = await resp.json();
        setSessions(data.sessions ?? data ?? []);
      }
    } catch {
      /* daemon not reachable */
    }
  }, []);

  useEffect(() => {
    fetchSessions();
    const interval = setInterval(fetchSessions, 5000);
    return () => clearInterval(interval);
  }, [fetchSessions]);

  // Derived values
  const activeSessions = sessions.filter(
    (s) => s.state === 'ACTIVE' || s.state === 'PENDING' || s.state === 'WAITING_APPROVAL',
  );
  const threatsDetected = events.filter((e) => !e.allowed).length;

  // Enforcement-derived
  const cats = enforcement?.categories;
  // Categories set to alert/block are ADVISORY labels applied to the trace.
  // They are counted here as what they are, and deliberately not used to
  // decide the protection status below.
  const protectionRulesCount = cats
    ? (Object.values(cats) as string[]).filter((v) => v === 'alert' || v === 'block').length
    : 0;

  // PROTECTION STATUS MUST REFLECT THE KERNEL, NOT A CONFIG FILE.
  //
  // This used to read "Protected — kernel-level enforcement is active" whenever
  // any threat category was set to "block". That was false twice over: the
  // function that would act on those categories is never called at runtime, and
  // even by its own design it only relabels a trace record in userspace. An
  // operator could be shown a green shield while nothing was being refused.
  //
  // The only field in /status that describes the kernel honestly is whether the
  // eBPF programs are loaded. Note `enforce_mode` is NOT usable here: it is a
  // boolean about the userspace ACL engine's default-deny setting, and that
  // engine is observe-only, so it would be a second false signal. The real
  // kernel posture (enforce_blocks, derived from daemon.mode) is not currently
  // exposed by the status endpoint; until it is, this deliberately claims less
  // than it could rather than more.
  const ebpfActive = status?.ebpf_active === true || status?.kernel_monitoring === 'active';
  const protectionStatus: 'protected' | 'monitoring' | 'unprotected' = ebpfActive
    ? 'protected'
    : daemonConnected
      ? 'monitoring'
      : 'unprotected';

  // Categories not set to observe (active protection)
  const activeCategories = cats
    ? (Object.entries(cats) as [keyof EnforcementCategories, string][]).filter(
        ([, v]) => v !== 'observe',
      )
    : [];

  // Recent security events (filtered, last 10)
  const recentEvents = events.filter((e) => !isNoiseEvent(e)).slice(0, 10);

  // Event kind badge config
  function kindBadge(kind: string): { label: string; color: string; bg: string } {
    const k = kind.toLowerCase();
    if (k.includes('file_create') || k === 'file_create')
      return { label: 'file_create', color: 'text-blue-700', bg: 'bg-blue-50' };
    if (k.includes('file_open') || k === 'file_open')
      return { label: 'file_open', color: 'text-amber-700', bg: 'bg-amber-50' };
    if (k.includes('network') || k === 'network_connect')
      return { label: 'network', color: 'text-purple-700', bg: 'bg-purple-50' };
    if (k.includes('process'))
      return { label: 'process', color: 'text-green-700', bg: 'bg-green-50' };
    return { label: kind || 'event', color: 'text-gray-700', bg: 'bg-gray-50' };
  }

  return (
    <div className="space-y-5 max-w-5xl">
      {/* Daemon connection error */}
      {!daemonConnected && (
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-3 px-4 py-3 rounded-lg border bg-event-block-bg border-red-200">
            <ShieldOff className="h-5 w-5 text-event-block" />
            <span className="text-sm font-medium text-event-block-text">Daemon not running</span>
            <span className="text-xs text-muted-foreground ml-1">Auto-retrying...</span>
            <Button
              size="sm"
              variant="destructive"
              className="ml-auto rounded-full text-xs h-7 px-3"
              onClick={handleStartDaemon}
            >
              Start daemon
            </Button>
          </div>
          {daemonHint && (
            <pre className="text-xs bg-muted rounded-lg px-4 py-2 font-mono text-foreground">
              {daemonHint}
            </pre>
          )}
        </div>
      )}

      {/* Row 1 — Stat cards */}
      <div className="grid grid-cols-4 gap-3">
        <StatCard
          label="Agents Monitored"
          value={activeSessions.length}
          accent="text-primary"
          icon={Users}
        />
        <StatCard
          label="Skills Scanned"
          value={skills.length}
          accent="text-amber-600"
          icon={Scan}
        />
        <StatCard
          label="Categories Flagged"
          value={protectionRulesCount}
          accent="text-blue-600"
          icon={Lock}
        />
        <StatCard
          label="Threats Detected"
          value={threatsDetected}
          accent="text-event-block"
          icon={FileWarning}
        />
      </div>

      {/* Row 2 — Protection Status */}
      <div className="rounded-lg border bg-card">
        <div className="flex items-center justify-between px-4 py-3 border-b">
          <div className="flex items-center gap-2">
            <Shield className="h-3.5 w-3.5 text-muted-foreground" />
            <h3 className="text-sm font-medium">Protection Status</h3>
          </div>
          <Button
            size="sm"
            variant="outline"
            className="text-xs h-7 px-3 rounded-full"
            onClick={() => onNavigate?.('enforcement')}
          >
            Configure
          </Button>
        </div>

        <div className="px-4 py-4">
          {/* Shield + status */}
          <div className="flex items-center gap-4 mb-4">
            <div
              className={cn(
                'h-14 w-14 rounded-xl flex items-center justify-center',
                protectionStatus === 'protected'
                  ? 'bg-green-50'
                  : protectionStatus === 'monitoring'
                    ? 'bg-amber-50'
                    : 'bg-gray-100',
              )}
            >
              {protectionStatus === 'protected' ? (
                <ShieldCheck className="h-7 w-7 text-green-600" />
              ) : protectionStatus === 'monitoring' ? (
                <ShieldAlert className="h-7 w-7 text-amber-600" />
              ) : (
                <ShieldOff className="h-7 w-7 text-gray-400" />
              )}
            </div>
            <div>
              <p
                className={cn(
                  'text-lg font-semibold',
                  protectionStatus === 'protected'
                    ? 'text-green-700'
                    : protectionStatus === 'monitoring'
                      ? 'text-amber-700'
                      : 'text-gray-500',
                )}
              >
                {protectionStatus === 'protected'
                  ? 'Protected'
                  : protectionStatus === 'monitoring'
                    ? 'Monitoring'
                    : 'Unprotected'}
              </p>
              <p className="text-xs text-muted-foreground">
                {protectionStatus === 'protected'
                  ? 'Kernel file rules are being enforced. Exec, network and process activity is recorded, not refused.'
                  : protectionStatus === 'monitoring'
                    ? 'Daemon is running and observing agent activity'
                    : 'Start the daemon to begin monitoring'}
              </p>
            </div>
          </div>

          {/* Active enforcement summary */}
          {activeCategories.length > 0 ? (
            <div className="space-y-2">
              {(() => {
                const blockCount = activeCategories.filter(([, a]) => a === 'block').length;
                const alertCount = activeCategories.filter(([, a]) => a === 'alert').length;
                const totalCategories = cats ? Object.keys(cats).length : 0;
                const allBlock = blockCount === totalCategories;
                const allAlert = alertCount === totalCategories;
                return (
                  <div className="flex items-center gap-3 flex-wrap">
                    {allBlock ? (
                      <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-red-50 text-red-700 text-xs font-semibold">
                        All {totalCategories} categories: BLOCK
                      </span>
                    ) : allAlert ? (
                      <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-amber-50 text-amber-700 text-xs font-semibold">
                        All {totalCategories} categories: ALERT
                      </span>
                    ) : (
                      <>
                        {blockCount > 0 && (
                          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-red-50 text-red-700 text-xs font-semibold">
                            {blockCount} blocked
                          </span>
                        )}
                        {alertCount > 0 && (
                          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-amber-50 text-amber-700 text-xs font-semibold">
                            {alertCount} alerting
                          </span>
                        )}
                        <span className="text-[11px] text-muted-foreground">
                          {totalCategories - blockCount - alertCount} observing
                        </span>
                      </>
                    )}
                  </div>
                );
              })()}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              All categories set to observe. Configure enforcement to enable alerts or blocking.
            </p>
          )}
        </div>
      </div>

      {/* Row 3 — Recent Security Events */}
      <div className="rounded-lg border bg-card">
        <div className="flex items-center justify-between px-4 py-3 border-b">
          <div className="flex items-center gap-2">
            <Activity className="h-3.5 w-3.5 text-muted-foreground" />
            <h3 className="text-sm font-medium">Recent Security Events</h3>
          </div>
          <button
            onClick={() => onNavigate?.('sessions')}
            className="text-[11px] font-medium text-primary hover:text-primary/80 transition-colors"
          >
            View All
          </button>
        </div>

        {recentEvents.length === 0 ? (
          <EmptyState daemonConnected={daemonConnected} />
        ) : (
          <div className="divide-y divide-border">
            {recentEvents.map((event) => {
              const kb = kindBadge(event.type);
              return (
                <div
                  key={event.id}
                  className={cn(
                    'flex items-center gap-2 px-4 py-2.5 text-xs',
                    !event.allowed && 'bg-red-50/30',
                  )}
                >
                  {/* Kind badge */}
                  <span
                    className={cn(
                      'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium w-24 justify-center',
                      kb.bg,
                      kb.color,
                    )}
                  >
                    {kb.label}
                  </span>

                  {/* Target */}
                  <code className="font-mono text-[11px] text-foreground truncate flex-1 min-w-0">
                    {event.target}
                  </code>

                  {/* Process */}
                  <span className="font-mono text-[11px] text-muted-foreground truncate w-24 text-right">
                    {event.skill_name}
                  </span>

                  {/* Timestamp */}
                  <span className="font-mono text-[11px] text-muted-foreground w-16 text-right shrink-0">
                    {new Date(event.timestamp).toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                    })}
                  </span>

                  {/* Allowed/blocked indicator */}
                  {!event.allowed && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-event-block-bg text-event-block-text">
                      <span className="w-1.5 h-1.5 rounded-full bg-event-block" />
                      BLOCK
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  accent,
  icon: Icon,
}: {
  label: string;
  value: number;
  accent?: string;
  icon?: typeof Users;
}) {
  return (
    <div className="rounded-lg border bg-card px-4 py-3.5">
      <div className="flex items-center justify-between mb-1">
        <p className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
          {label}
        </p>
        {Icon && <Icon className="h-3.5 w-3.5 text-muted-foreground/50" />}
      </div>
      <p
        className={cn('text-xl font-semibold tabular-nums font-mono', accent || 'text-foreground')}
      >
        {value}
      </p>
    </div>
  );
}

function EmptyState({ daemonConnected }: { daemonConnected: boolean }) {
  if (!daemonConnected) {
    return (
      <div className="text-center py-16">
        <ShieldOff className="h-8 w-8 mx-auto mb-3 text-event-block opacity-40" />
        <p className="text-sm font-medium text-foreground mb-1">Daemon not running</p>
        <p className="text-xs text-muted-foreground">
          Start the daemon to begin monitoring AI agents.
        </p>
      </div>
    );
  }

  return (
    <div className="text-center py-16">
      <Shield className="h-8 w-8 mx-auto mb-3 text-primary opacity-30" />
      <p className="text-sm font-medium text-foreground mb-1">No recent events</p>
      <p className="text-xs text-muted-foreground">
        Start an AI agent to see security events here.
      </p>
    </div>
  );
}
