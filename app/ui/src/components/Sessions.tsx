// SPDX-License-Identifier: Apache-2.0
import { useState, useEffect, useCallback, useMemo } from 'react';
import { daemonFetch } from '../lib/daemonApi';
import {
  Users,
  Shield,
  Clock,
  CheckCircle,
  XCircle,
  RefreshCw,
  Plus,
  ChevronRight,
  ChevronDown,
  ArrowLeft,
  FileKey,
  Globe,
  Terminal,
  Brain,
  Wrench,
  Lock,
  Unlock,
  Sparkles,
  FileText,
  Eye,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  ShieldBan,
  Cpu,
  GitBranch,
  AlertTriangle,
} from 'lucide-react';
import { cn } from '../lib/utils';
import AgentIcon, { guessAgent } from './AgentIcon';
import { useTokenScope } from '@/hooks/use-token-scope';

// ── Types ─────────────────────────────────────────────────────────────────────

type SessionState = 'PENDING' | 'ACTIVE' | 'WAITING_APPROVAL' | 'EXPIRED' | 'TERMINATED';

interface Session {
  id: string;
  agent_type: string | Record<string, string>;
  actor: string;
  declared_scope: string[];
  state: SessionState;
  privileged: boolean;
  policies: string[];
  granted_access: string[];
  jit_identities: string[];
  start_time: string;
  end_time: string | null;
  ttl_secs: number | null;
  event_count: number;
}

// ── Containment & Agent Identity types ────────────────────────────────────────

interface ContainmentStatus {
  session_id: string;
  contained: boolean;
  cgroup_path?: string;
  nftables_active?: boolean;
  reason?: string;
}

interface AgentIdentity {
  session_id: string;
  agent: {
    type: string;
    provider: string;
    model?: string;
    binary_path?: string;
    version?: string;
  };
  context: {
    current_prompt?: string;
    task_description?: string;
    tools_available: string[];
    last_tool_call?: string;
  };
  lineage: {
    pid?: number;
    ppid?: number;
    parent_process?: string;
    process_tree: string[];
    cwd?: string;
    started_at: string;
  };
  policy: {
    profile: string;
    active_rules: number;
    violations: number;
    declared_scope: string[];
    containment: string;
  };
  risk_score: number;
  data_exfiltration: {
    pii_detected: number;
    secrets_detected: number;
    action_mode: string;
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const DAEMON_API = 'http://127.0.0.1:7700/api/v1';

const AGENT_ICONS: Record<string, string> = {
  claude: '🤖',
  chatgpt: '🟢',
  gemini: '💎',
  deepseek: '🔵',
  cursor: '⚡',
  copilot: '🪁',
  devin: '🛠️',
};

function normalizeAgentType(type: string | Record<string, string>): string {
  if (typeof type === 'string') return type.toLowerCase();
  // serde serializes Custom("foo") as {"custom": "foo"}
  if (typeof type === 'object' && type !== null) {
    const val = (type as Record<string, string>).custom;
    return typeof val === 'string' ? val.toLowerCase() : 'custom';
  }
  return 'custom';
}

function agentIcon(type: string | Record<string, string>) {
  return AGENT_ICONS[normalizeAgentType(type)] ?? '🤖';
}

function stateConfig(state: SessionState) {
  switch (state) {
    case 'ACTIVE':
      return {
        label: 'Active',
        color: 'text-green-400',
        bg: 'bg-green-400/10',
        dot: 'bg-green-400',
      };
    case 'PENDING':
      return {
        label: 'Pending',
        color: 'text-yellow-400',
        bg: 'bg-yellow-400/10',
        dot: 'bg-yellow-400',
      };
    case 'WAITING_APPROVAL':
      return {
        label: 'Active',
        color: 'text-green-400',
        bg: 'bg-green-400/10',
        dot: 'bg-green-400',
      };
    case 'EXPIRED':
      return {
        label: 'Expired',
        color: 'text-muted-foreground',
        bg: 'bg-muted/30',
        dot: 'bg-muted-foreground',
      };
    case 'TERMINATED':
      return { label: 'Terminated', color: 'text-red-400', bg: 'bg-red-400/10', dot: 'bg-red-400' };
  }
}

function elapsed(start: string, end: string | null) {
  const from = new Date(start).getTime();
  const to = end ? new Date(end).getTime() : Date.now();
  const secs = Math.floor((to - from) / 1000);
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

// ── Create session dialog ─────────────────────────────────────────────────────

function CreateDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  // Creating a session changes daemon state, so a read-only token cannot do it.
  const { readOnly: sessionsReadOnly } = useTokenScope();
  const [actor, setActor] = useState('');
  const [agent, setAgent] = useState('claude');
  const [scope, setScope] = useState('');
  const [ttl, setTtl] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  async function submit() {
    if (!actor.trim()) {
      setErr('Actor is required');
      return;
    }
    setBusy(true);
    setErr('');
    try {
      const body = {
        actor: actor.trim(),
        agent_type: agent,
        declared_scope: scope.trim()
          ? scope
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
          : [],
        ttl_secs: ttl ? parseInt(ttl) : null,
      };
      const res = await daemonFetch(`${DAEMON_API}/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(await res.text());
      onCreated();
      onClose();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        className="bg-card border border-border rounded-xl w-full max-w-md p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-base font-semibold mb-4">New Session</h2>

        <div className="space-y-3">
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Agent type</label>
            <select
              value={agent}
              onChange={(e) => setAgent(e.target.value)}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm"
            >
              {Object.keys(AGENT_ICONS).map((k) => (
                <option key={k} value={k}>
                  {agentIcon(k)} {k.charAt(0).toUpperCase() + k.slice(1)}
                </option>
              ))}
              <option value="custom">Custom</option>
            </select>
          </div>

          <div>
            <label className="text-xs text-muted-foreground mb-1 block">
              Actor (user / identity)
            </label>
            <input
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              placeholder="alice@example.com"
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm placeholder:text-muted-foreground/50"
            />
          </div>

          <div>
            <label className="text-xs text-muted-foreground mb-1 block">
              Declared scope (comma-separated)
            </label>
            <input
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              placeholder="read_files, query_db, send_slack"
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm placeholder:text-muted-foreground/50"
            />
          </div>

          <div>
            <label className="text-xs text-muted-foreground mb-1 block">
              TTL (seconds, leave blank for no expiry)
            </label>
            <input
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              type="number"
              min="60"
              placeholder="3600"
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm placeholder:text-muted-foreground/50"
            />
          </div>
        </div>

        {err && <p className="text-xs text-red-400 mt-2">{err}</p>}

        {sessionsReadOnly && (
          <p className="mt-4 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
            This app is a viewer. Creating a session needs an operator with root
            — run <code className="font-mono text-amber-100">sudo rz sessions create</code>.
          </p>
        )}

        <div className="flex gap-2 mt-5">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 rounded-md border border-border text-sm hover:bg-muted/50 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={busy || sessionsReadOnly}
            className="flex-1 px-4 py-2 rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
          >
            {busy ? 'Creating…' : 'Create Session'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Session row ───────────────────────────────────────────────────────────────

function SessionRow({
  session,
  onSelect,
  onTerminate,
  isContained,
}: {
  session: Session;
  onSelect: () => void;
  onTerminate: () => void;
  isContained?: boolean;
}) {
  const cfg = stateConfig(session.state);

  return (
    <tr
      className="border-b border-border/50 hover:bg-muted/20 cursor-pointer transition-colors"
      onClick={onSelect}
    >
      <td className="px-4 py-3">
        <div className="flex items-center gap-2.5">
          <span className="text-lg leading-none">{agentIcon(session.agent_type)}</span>
          <div>
            <p className="text-sm font-medium capitalize">
              {normalizeAgentType(session.agent_type)}
            </p>
            <p className="text-xs text-muted-foreground truncate max-w-[120px]">{session.actor}</p>
          </div>
        </div>
      </td>

      <td className="px-4 py-3">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span
            className={cn(
              'inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full font-medium',
              cfg.bg,
              cfg.color,
            )}
          >
            <span className={cn('w-1.5 h-1.5 rounded-full', cfg.dot)} />
            {cfg.label}
          </span>
          {isContained && (
            <span className="inline-flex items-center gap-1 text-[10px] bg-[#01696F]/10 text-[#01696F] px-1.5 py-0.5 rounded-full font-semibold">
              <ShieldBan className="h-2.5 w-2.5" />
              CONTAINED
            </span>
          )}
          {session.privileged && (
            <span className="text-[10px] bg-orange-500/15 text-orange-400 px-1.5 py-0.5 rounded-full font-medium">
              PRIVILEGED
            </span>
          )}
        </div>
      </td>

      <td className="px-4 py-3 text-xs text-muted-foreground">
        {session.declared_scope.length > 0 ? (
          session.declared_scope.slice(0, 2).join(', ') +
          (session.declared_scope.length > 2 ? ` +${session.declared_scope.length - 2}` : '')
        ) : (
          <span className="italic">—</span>
        )}
      </td>

      <td className="px-4 py-3 text-xs text-muted-foreground">
        {elapsed(session.start_time, session.end_time)}
      </td>

      <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-end gap-1">
          {(session.state === 'ACTIVE' ||
            session.state === 'PENDING' ||
            session.state === 'WAITING_APPROVAL') && (
            <button
              onClick={onTerminate}
              className="text-[10px] bg-red-500/10 text-red-400 hover:bg-red-500/20 px-2 py-1 rounded font-medium transition-colors"
            >
              Terminate
            </button>
          )}
          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/40" />
        </div>
      </td>
    </tr>
  );
}

// ── Detail view (full page overlay with graph) ────────────────────────────────

interface SessionEvent {
  id: string;
  kind: string;
  process: string;
  pid: number;
  target: string;
  allowed: boolean;
  reason?: string;
  timestamp: string;
  llm_context?: {
    provider: string;
    model?: string;
    response_text?: string;
    tool_call?: string;
    usage?: { input_tokens?: number; output_tokens?: number };
  };
}

// ── Baseline policy types ──────────────────────────────────────────────────

interface ActivityRule {
  class: string;
  action: string | { allow_scoped: { patterns: string[] } };
  description: string;
}

interface SessionPolicy {
  session_id: string;
  agent_type: string;
  profile_label: string;
  profile_description: string;
  rules: ActivityRule[];
  declared_scope: string[];
  created_at: string;
  updated_at: string;
}

interface BaselineViolation {
  session_id: string;
  event_id: string;
  activity_class: string;
  action_taken: string;
  rule_description: string;
  process: string;
  target: string;
  pid: number;
  timestamp: string;
}

function actionLabel(action: string | { allow_scoped: { patterns: string[] } }): {
  text: string;
  color: string;
  bg: string;
} {
  if (typeof action === 'string') {
    switch (action) {
      case 'allow':
        return { text: 'Allow', color: 'text-green-700', bg: 'bg-green-100' };
      case 'warn':
        return { text: 'Warn', color: 'text-amber-700', bg: 'bg-amber-100' };
      case 'block':
        return { text: 'Block', color: 'text-red-700', bg: 'bg-red-100' };
      default:
        return { text: action, color: 'text-gray-700', bg: 'bg-gray-100' };
    }
  }
  if ('allow_scoped' in action) {
    return { text: 'Scoped', color: 'text-blue-700', bg: 'bg-blue-100' };
  }
  return { text: 'Unknown', color: 'text-gray-700', bg: 'bg-gray-100' };
}

function classLabel(cls: string): string {
  return cls.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());
}

function classIcon(cls: string) {
  switch (cls) {
    case 'file_read':
      return FileText;
    case 'file_write':
      return FileText;
    case 'file_delete':
      return XCircle;
    case 'process_exec':
      return Terminal;
    case 'process_fork':
      return Terminal;
    case 'network_connect':
      return Globe;
    case 'network_send':
      return Globe;
    case 'dns_query':
      return Globe;
    case 'credential_access':
      return Lock;
    case 'privilege_escalation':
      return ShieldAlert;
    default:
      return Eye;
  }
}

// ── Baseline policy card ──────────────────────────────────────────────────

function PolicyCard({
  policy,
  violations,
}: {
  policy: SessionPolicy | null;
  violations: BaselineViolation[];
}) {
  const [expanded, setExpanded] = useState(false);

  if (!policy) {
    return (
      <div className="bg-card border border-border rounded-xl px-5 py-4">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <ShieldOff className="h-4 w-4" />
          <span>No baseline policy assigned</span>
        </div>
      </div>
    );
  }

  const blockedCount = violations.filter((v) => v.action_taken === 'blocked').length;
  const warnedCount = violations.filter((v) => v.action_taken === 'warned').length;

  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-muted/20 transition-colors"
      >
        <div className="h-8 w-8 rounded-lg bg-[#01696F]/10 flex items-center justify-center shrink-0">
          <ShieldCheck className="h-4 w-4 text-[#01696F]" />
        </div>
        <div className="flex-1 text-left">
          <p className="text-sm font-semibold">{policy.profile_label}</p>
          <p className="text-xs text-muted-foreground">{policy.profile_description}</p>
        </div>
        {blockedCount > 0 && (
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-100 text-red-700 font-semibold">
            {blockedCount} blocked
          </span>
        )}
        {warnedCount > 0 && (
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 font-semibold">
            {warnedCount} warned
          </span>
        )}
        <span className="text-[10px] px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 font-mono">
          {policy.rules.length} rules
        </span>
        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        )}
      </button>

      {expanded && (
        <div className="border-t border-border">
          {/* Rules grid */}
          <div className="divide-y divide-border/50">
            {policy.rules.map((rule, i) => {
              const al = actionLabel(rule.action);
              const Icon = classIcon(rule.class);
              const ruleViolations = violations.filter((v) => v.activity_class === rule.class);

              return (
                <div key={i} className="flex items-center gap-3 px-5 py-2.5 text-[13px]">
                  <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="font-medium w-[140px] shrink-0">{classLabel(rule.class)}</span>
                  <span
                    className={cn(
                      'text-[10px] px-2 py-0.5 rounded-full font-semibold shrink-0',
                      al.bg,
                      al.color,
                    )}
                  >
                    {al.text}
                  </span>
                  <span className="text-xs text-muted-foreground truncate flex-1">
                    {rule.description}
                  </span>
                  {typeof rule.action === 'object' && 'allow_scoped' in rule.action && (
                    <span
                      className="text-[10px] text-blue-600 font-mono truncate max-w-[200px]"
                      title={rule.action.allow_scoped.patterns.join(', ')}
                    >
                      {rule.action.allow_scoped.patterns.length} patterns
                    </span>
                  )}
                  {ruleViolations.length > 0 && (
                    <span
                      className={cn(
                        'text-[10px] px-1.5 py-0.5 rounded-full font-semibold',
                        ruleViolations.some((v) => v.action_taken === 'blocked')
                          ? 'bg-red-100 text-red-700'
                          : 'bg-amber-100 text-amber-700',
                      )}
                    >
                      {ruleViolations.length}
                    </span>
                  )}
                </div>
              );
            })}
          </div>

          {/* Recent violations */}
          {violations.length > 0 && (
            <div className="border-t border-border px-5 py-3">
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold mb-2">
                Recent Violations
              </p>
              <div className="space-y-1.5 max-h-[200px] overflow-y-auto">
                {violations.slice(0, 20).map((v, i) => (
                  <div
                    key={i}
                    className={cn(
                      'flex items-center gap-2 text-[12px] px-3 py-1.5 rounded-md',
                      v.action_taken === 'blocked' ? 'bg-red-50' : 'bg-amber-50',
                    )}
                  >
                    <span
                      className={cn(
                        'text-[10px] px-1.5 py-0.5 rounded font-semibold shrink-0',
                        v.action_taken === 'blocked'
                          ? 'bg-red-100 text-red-700'
                          : 'bg-amber-100 text-amber-700',
                      )}
                    >
                      {v.action_taken.toUpperCase()}
                    </span>
                    <span className="font-medium text-foreground/80 shrink-0">
                      {classLabel(v.activity_class)}
                    </span>
                    <span className="text-muted-foreground font-mono truncate flex-1">
                      {v.target}
                    </span>
                    <span className="text-muted-foreground/50 text-[11px] font-mono shrink-0">
                      {new Date(v.timestamp).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                      })}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function eventIcon(kind: string) {
  if (kind?.includes('llm_tool_call')) return Wrench;
  if (kind?.includes('llm_')) return Brain;
  if (kind?.includes('network')) return Globe;
  if (kind?.includes('process')) return Terminal;
  return FileKey;
}

function eventLabel(kind: string) {
  return (kind || 'unknown').replace(/_/g, ' ');
}

// ── Noise filter (shared with ProcessTree) ────────────────────────────────────

const NOISE_TARGETS = [
  'memory.high',
  'memory.max',
  'memory.low',
  'memory.current',
  'memory.stat',
  'memory.swap.current',
  'memory.swap.max',
  'cpu.max',
  'cpu.stat',
  'cpu.weight',
  'cgroup.procs',
  'cgroup.controllers',
  'cgroup.subtree_control',
  'cgroup.events',
  'pids.max',
  'pids.current',
  'io.max',
  'io.stat',
  'maps',
  'filesystems',
  'mountinfo',
  'mounts',
  'status',
];

function isNoiseEvent(ev: { kind?: string; target: string }): boolean {
  const t = ev.target || '';
  const basename = t.split('/').pop() || '';
  if (NOISE_TARGETS.includes(basename)) return true;
  if (t.includes('/sys/fs/cgroup/') || (t.includes('/proc/') && t.includes('/cgroup'))) return true;
  // Filter shared library opens (libc.so, libm.so, etc.)
  if (basename.match(/^lib[a-z].*\.so/)) return true;
  return false;
}

// ── Extract last user message from raw API JSON ───────────────────────────────

function stripSystemReminders(text: string): string {
  return text.replace(/<system-reminder>[\s\S]*?<\/system-reminder>/g, '').trim();
}

function extractFromRoleFormat(text: string): string {
  // Rust ssl_sniff formats as: [role] content\n[role] content
  const lines = text.split('\n');
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    if (line.startsWith('[user] ')) {
      const content = stripSystemReminders(line.slice(7));
      if (content && content.length > 1) return content;
    }
  }
  return '';
}

function extractUserMessage(raw: string): { userMsg: string; model: string; fullText: string } {
  let model = '';
  let userMsg = '';

  // First: try the [role] format from Rust ssl_sniff
  if (raw.includes('[user] ')) {
    userMsg = extractFromRoleFormat(raw);
    const modelMatch = raw.match(/"model"\s*:\s*"([^"]+)"/);
    if (modelMatch) model = modelMatch[1];
    if (userMsg) return { userMsg, model, fullText: raw };
  }

  // Second: try JSON parse
  try {
    const parsed = JSON.parse(raw);
    model = parsed.model || '';
    if (Array.isArray(parsed.messages)) {
      for (let i = parsed.messages.length - 1; i >= 0; i--) {
        const m = parsed.messages[i];
        if (m.role === 'user') {
          if (typeof m.content === 'string') {
            userMsg = stripSystemReminders(m.content);
          } else if (Array.isArray(m.content)) {
            for (let j = m.content.length - 1; j >= 0; j--) {
              const block = m.content[j];
              if (block.type === 'text' && block.text) {
                const cleaned = stripSystemReminders(block.text);
                if (cleaned) {
                  userMsg = cleaned;
                  break;
                }
              }
            }
          }
          if (userMsg) break;
        }
      }
    }
  } catch {
    // Truncated JSON — try regex
    const matches = [...raw.matchAll(/"role"\s*:\s*"user"[^}]*"content"\s*:\s*"([^"]{1,200})"/g)];
    if (matches.length > 0) {
      userMsg = stripSystemReminders(matches[matches.length - 1][1]);
    }
    if (!userMsg) {
      const mm = raw.match(/"model"\s*:\s*"([^"]+)"/);
      if (mm) model = mm[1];
      userMsg = stripSystemReminders(raw.slice(0, 300));
    }
  }

  userMsg = userMsg.replace(/^\[user\]\s*/, '').trim();
  if (!userMsg) userMsg = '(empty prompt)';

  return { userMsg, model, fullText: raw };
}

// ── Session event row (unified: files + AI in one list) ───────────────────────

function SessionEventRow({
  event,
  violation,
}: {
  event: SessionEvent;
  violation?: BaselineViolation;
}) {
  const [expanded, setExpanded] = useState(false);

  const isPrompt = event.kind === 'llm_request';
  const isResponse = event.kind === 'llm_response';
  const isToolCall = event.kind === 'llm_tool_call';
  const isAi = isPrompt || isResponse || isToolCall;
  const isFile = event.kind?.startsWith('file_');
  const hasExpandable = isAi && event.llm_context?.response_text;

  // Parse AI prompt to get just the user message
  const parsed = useMemo(() => {
    if (!isPrompt || !event.llm_context?.response_text) return null;
    return extractUserMessage(event.llm_context.response_text);
  }, [isPrompt, event.llm_context?.response_text]);

  // Badge styling
  let badgeBg = 'bg-green-100';
  let badgeText = 'text-green-700';
  let badgeLabel = 'File Open';
  let rowBg = '';
  let IconEl = FileText;

  if (isPrompt) {
    badgeBg = 'bg-purple-100';
    badgeText = 'text-purple-700';
    badgeLabel = 'AI PROMPT';
    rowBg = 'bg-purple-50/40';
    IconEl = Sparkles;
  } else if (isResponse) {
    badgeBg = 'bg-green-100';
    badgeText = 'text-green-700';
    badgeLabel = 'AI RESPONSE';
    rowBg = 'bg-green-50/40';
    IconEl = Brain;
  } else if (isToolCall) {
    badgeBg = 'bg-amber-100';
    badgeText = 'text-amber-700';
    badgeLabel = 'TOOL CALL';
    rowBg = 'bg-amber-50/30';
    IconEl = Wrench;
  } else if (isFile) {
    badgeLabel = event.kind === 'file_open' ? 'File Open' : event.kind.replace(/_/g, ' ');
    badgeBg = 'bg-green-100';
    badgeText = 'text-green-700';
    IconEl = FileText;
  } else if (event.kind?.startsWith('network_') || event.kind === 'dns_query') {
    badgeBg = 'bg-amber-50';
    badgeText = 'text-amber-600';
    badgeLabel = 'Network';
    IconEl = Globe;
  }

  // For AI prompts: show the user message
  // For AI responses: show a preview of the response text, not the provider:model target
  const displayTarget =
    isPrompt && parsed
      ? parsed.userMsg
      : (isResponse || isToolCall) && event.llm_context?.response_text
        ? event.llm_context.response_text.slice(0, 120).replace(/\n/g, ' ')
        : isResponse || isToolCall
          ? '' // No response text yet — model name shown separately
          : event.target;

  // Model: extract from parsed prompt or llm_context, falling back to target field
  const rawModel =
    isPrompt && parsed?.model
      ? parsed.model
      : event.llm_context?.model || (isAi ? event.target.split(':').pop() || '' : '');
  const displayModel = !rawModel || rawModel === 'unknown' ? '' : rawModel;

  return (
    <div>
      <button
        onClick={() => hasExpandable && setExpanded(!expanded)}
        className={cn(
          'w-full flex items-center gap-2.5 px-5 py-2.5 text-[13px] transition-colors',
          'hover:bg-muted/30',
          rowBg,
          hasExpandable ? 'cursor-pointer' : 'cursor-default',
        )}
      >
        {/* Type icon */}
        <IconEl
          className={cn(
            'h-3.5 w-3.5 shrink-0',
            isPrompt
              ? 'text-purple-500'
              : isResponse
                ? 'text-green-600'
                : isToolCall
                  ? 'text-amber-600'
                  : 'text-muted-foreground',
          )}
        />

        {/* Badge */}
        <span
          className={cn(
            'text-[10px] px-2 py-0.5 rounded-full font-semibold shrink-0 font-mono',
            badgeBg,
            badgeText,
          )}
        >
          {badgeLabel}
        </span>

        {/* Model name for AI events */}
        {isAi && displayModel && (
          <span className="text-[11px] text-muted-foreground font-mono shrink-0">
            {displayModel}
          </span>
        )}

        {/* Tool name */}
        {isToolCall && event.llm_context?.tool_call && (
          <span className="text-[11px] px-1.5 py-0.5 rounded bg-amber-50 text-amber-700 font-mono shrink-0">
            {event.llm_context.tool_call}
          </span>
        )}

        {/* Target / user message */}
        <span
          className={cn(
            'truncate flex-1 text-left',
            isPrompt
              ? 'text-[13px] text-foreground/80'
              : 'text-[12px] text-foreground/70 font-mono',
          )}
        >
          {displayTarget}
        </span>

        {/* Process name */}
        <span className="text-muted-foreground/60 shrink-0 text-[11px] font-mono">
          {event.process}
        </span>

        {/* Timestamp */}
        <span className="text-muted-foreground/40 shrink-0 w-[75px] text-right text-[11px] font-mono">
          {new Date(event.timestamp).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          })}
        </span>

        {/* Violation badge */}
        {violation && (
          <span
            className={cn(
              'text-[9px] px-1.5 py-0.5 rounded font-bold shrink-0 uppercase',
              violation.action_taken === 'blocked'
                ? 'bg-red-100 text-red-700'
                : 'bg-amber-100 text-amber-700',
            )}
            title={violation.rule_description}
          >
            {violation.action_taken}
          </span>
        )}

        {/* Expand chevron for AI events */}
        {hasExpandable ? (
          expanded ? (
            <ChevronDown className="h-3 w-3 text-muted-foreground shrink-0" />
          ) : (
            <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
          )
        ) : (
          <div className="w-3 shrink-0" />
        )}
      </button>

      {/* Expanded AI content — show user message prominently, full JSON in details */}
      {expanded && event.llm_context?.response_text && (
        <div className="mx-5 mb-2 space-y-2">
          {isPrompt && parsed ? (
            <>
              <div className="p-3 rounded-md bg-purple-50/50 border border-purple-200/50">
                <p className="text-[10px] text-purple-600 font-semibold mb-1.5 uppercase tracking-wider">
                  User message
                </p>
                <p className="text-[13px] text-purple-900/90 whitespace-pre-wrap break-words leading-relaxed">
                  {parsed.userMsg}
                </p>
              </div>
              <details className="group">
                <summary className="text-[10px] text-muted-foreground cursor-pointer hover:text-foreground transition-colors">
                  Show full API request
                </summary>
                <div className="mt-1 p-3 rounded-md font-mono text-[11px] whitespace-pre-wrap break-all max-h-[300px] overflow-y-auto leading-relaxed border bg-gray-50 border-gray-200 text-gray-700">
                  {event.llm_context.response_text}
                </div>
              </details>
            </>
          ) : (
            <div
              className={cn(
                'p-3 rounded-md font-mono text-[11px] whitespace-pre-wrap break-all max-h-[400px] overflow-y-auto leading-relaxed border',
                'bg-green-50/50 border-green-200/50 text-green-900/80',
              )}
            >
              {event.llm_context.response_text}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Session detail (unified process tree view) ────────────────────────────────

type SessionFilter = 'all' | 'ai' | 'files';

function SessionDetail({
  session,
  onClose,
  onTerminate,
}: {
  session: Session;
  onClose: () => void;
  onTerminate: () => void;
}) {
  const cfg = stateConfig(session.state);
  const [events, setEvents] = useState<SessionEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(true);
  const [llmEvents, setLlmEvents] = useState<SessionEvent[]>([]);
  const [llmLoading, setLlmLoading] = useState(true);
  const [filter, setFilter] = useState<SessionFilter>('all');
  const [policy, setPolicy] = useState<SessionPolicy | null>(null);
  const [violations, setViolations] = useState<BaselineViolation[]>([]);
  const [containment, setContainment] = useState<ContainmentStatus | null>(null);
  const [agentIdentity, setAgentIdentity] = useState<AgentIdentity | null>(null);
  const [identityExpanded, setIdentityExpanded] = useState(false);

  // Fetch containment status for this session
  useEffect(() => {
    async function fetchContainment() {
      try {
        const res = await daemonFetch(`${DAEMON_API}/containment/status`);
        if (res.ok) {
          const data = await res.json();
          const statuses: ContainmentStatus[] = Array.isArray(data) ? data : (data.statuses ?? []);
          const match = statuses.find((s) => s.session_id === session.id);
          setContainment(match ?? null);
        }
      } catch {
        /* ignore */
      }
    }
    fetchContainment();
    const id = setInterval(fetchContainment, 10000);
    return () => clearInterval(id);
  }, [session.id]);

  // Fetch agent identity for this session
  useEffect(() => {
    async function fetchIdentity() {
      try {
        const res = await daemonFetch(`${DAEMON_API}/agent-identity/${session.id}`);
        if (res.ok) setAgentIdentity(await res.json());
      } catch {
        /* ignore */
      }
    }
    fetchIdentity();
    const id = setInterval(fetchIdentity, 15000);
    return () => clearInterval(id);
  }, [session.id]);

  // Fetch baseline policy for this session
  useEffect(() => {
    async function fetchPolicy() {
      try {
        const res = await daemonFetch(`${DAEMON_API}/sessions/${session.id}/policy`);
        if (res.ok) setPolicy(await res.json());
      } catch {
        /* ignore */
      }
    }
    fetchPolicy();
    const id = setInterval(fetchPolicy, 10000);
    return () => clearInterval(id);
  }, [session.id]);

  // Fetch violations for this session
  useEffect(() => {
    async function fetchViolations() {
      try {
        const res = await daemonFetch(`${DAEMON_API}/observer/violations?limit=100`);
        if (res.ok) {
          const all: BaselineViolation[] = await res.json();
          setViolations(all.filter((v) => v.session_id === session.id));
        }
      } catch {
        /* ignore */
      }
    }
    fetchViolations();
    const id = setInterval(fetchViolations, 5000);
    return () => clearInterval(id);
  }, [session.id]);

  // Fetch session-specific events
  useEffect(() => {
    async function fetchSessionEvents() {
      try {
        const res = await daemonFetch(`${DAEMON_API}/sessions/${session.id}/events`);
        if (res.ok) {
          const data = await res.json();
          setEvents(data.events ?? []);
        }
      } catch {
        /* ignore */
      }
      setEventsLoading(false);
    }
    fetchSessionEvents();
    const id = setInterval(fetchSessionEvents, 3000);
    return () => clearInterval(id);
  }, [session.id]);

  // Fetch LLM events separately (kind filter avoids kernel noise)
  useEffect(() => {
    async function fetchLlm() {
      try {
        const res = await daemonFetch(
          `${DAEMON_API}/events?limit=200&kind=llm_request,llm_response,llm_tool_call`,
        );
        if (res.ok) {
          const data = await res.json();
          setLlmEvents(Array.isArray(data) ? data : (data.events ?? []));
        }
      } catch {
        /* ignore */
      }
      setLlmLoading(false);
    }
    fetchLlm();
    const id = setInterval(fetchLlm, 3000);
    return () => clearInterval(id);
  }, []);

  // Merge, dedup, filter noise, consolidate network, sort newest-first
  const mergedEvents = useMemo(() => {
    const seen = new Set<string>();
    const merged: SessionEvent[] = [];
    // Track network targets to consolidate duplicates
    const networkSeen = new Set<string>();
    for (const e of [...events, ...llmEvents]) {
      if (seen.has(e.id) || isNoiseEvent(e)) continue;
      seen.add(e.id);
      // Hide network & DNS noise entirely — only AI + file events matter
      if (e.kind?.startsWith('network_') || e.kind === 'dns_query') continue;
      // Also hide mprotect / process noise
      if (e.kind === 'process_exec' || e.kind === 'process_fork' || e.kind === 'process_exit')
        continue;
      merged.push(e);
    }
    // Newest first — user shouldn't have to scroll to bottom
    merged.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return merged;
  }, [events, llmEvents]);

  // Filtered events
  const filtered = useMemo(() => {
    return mergedEvents.filter((ev) => {
      if (filter === 'ai') return ev.kind?.startsWith('llm_');
      if (filter === 'files') return ev.kind?.startsWith('file_');
      return true;
    });
  }, [mergedEvents, filter]);

  // Summary counts
  // Build violation lookup by event ID for inline badges
  const violationMap = useMemo(() => {
    const map = new Map<string, BaselineViolation>();
    for (const v of violations) {
      map.set(v.event_id, v);
    }
    return map;
  }, [violations]);

  const promptCount = 0; // removed
  const responseCount = 0; // removed
  const fileCount = mergedEvents.filter((e) => e.kind?.startsWith('file_')).length;
  // Filter out LLM events from display — security product, not prompt logger
  const displayEvents = mergedEvents.filter(
    (e) => !e.target?.startsWith('etilqs_') && !e.kind?.startsWith('llm_'),
  );

  return (
    <div className="space-y-4">
      {/* Back button */}
      <button
        onClick={onClose}
        className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
      >
        <ArrowLeft className="h-3 w-3" /> Back to Sessions
      </button>

      {/* Compact header */}
      <div className="bg-card border border-border rounded-xl px-5 py-4 flex items-center gap-3">
        <AgentIcon agent={guessAgent(normalizeAgentType(session.agent_type))} className="w-8 h-8" />
        <div className="flex-1">
          <p className="font-semibold capitalize">{normalizeAgentType(session.agent_type)} Agent</p>
          <p className="text-xs text-muted-foreground">
            {session.actor} · {elapsed(session.start_time, session.end_time)}
          </p>
        </div>
        <span
          className={cn(
            'inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full font-medium',
            cfg.bg,
            cfg.color,
          )}
        >
          <span className={cn('w-1.5 h-1.5 rounded-full', cfg.dot)} />
          {cfg.label}
        </span>
        {containment?.contained && (
          <span className="inline-flex items-center gap-1 text-[10px] bg-[#01696F]/10 text-[#01696F] px-2 py-1 rounded-full font-semibold">
            <ShieldBan className="h-3 w-3" />
            CONTAINED
          </span>
        )}
        {(session.state === 'ACTIVE' ||
          session.state === 'PENDING' ||
          session.state === 'WAITING_APPROVAL') && (
          <button
            onClick={onTerminate}
            className="text-xs px-3 py-1.5 rounded-md bg-red-500/10 text-red-500 font-medium hover:bg-red-500/20 transition-colors"
          >
            Terminate
          </button>
        )}
      </div>
      {/* Baseline policy card */}
      <PolicyCard policy={policy} violations={violations} />

      {/* Summary badges */}
      <div className="flex items-center gap-3 flex-wrap">
        {fileCount > 0 && (
          <span className="text-[12px] px-3 py-1 rounded-full bg-blue-50 text-blue-600 font-semibold font-mono">
            {fileCount} {fileCount === 1 ? 'file' : 'files'}
          </span>
        )}
        <span className="text-xs text-muted-foreground ml-auto font-mono">
          {mergedEvents.length} total
        </span>
      </div>

      {/* Unified event list (like AgentSight) */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        {/* Filter tabs */}
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border">
          {[
            { id: 'all' as SessionFilter, label: 'All' },

            { id: 'files' as SessionFilter, label: 'Files Only' },
          ].map((f) => (
            <button
              key={f.id}
              onClick={() => setFilter(f.id)}
              className={cn(
                'text-[12px] px-3 py-1.5 rounded-full font-medium transition-colors',
                filter === f.id
                  ? 'bg-[#01696F]/10 text-[#01696F]'
                  : 'text-muted-foreground hover:bg-muted/50',
              )}
            >
              {f.label}
            </button>
          ))}
          <span className="text-[11px] text-muted-foreground ml-auto font-mono">
            {filtered.length} events
          </span>
        </div>

        {/* Events */}
        {eventsLoading && llmLoading ? (
          <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">
            <RefreshCw className="h-4 w-4 mr-2 animate-spin" /> Loading…
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12">
            <Clock className="h-6 w-6 mx-auto mb-2 opacity-30 text-muted-foreground" />
            <p className="text-xs text-muted-foreground">No events recorded yet</p>
          </div>
        ) : (
          <div className="max-h-[700px] overflow-y-auto divide-y divide-border/30">
            {filtered.map((event) => (
              <SessionEventRow
                key={event.id}
                event={event}
                violation={violationMap.get(event.id)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Grouped agent list ───────────────────────────────────────────────────────

interface AgentGroup {
  agentType: string;
  sessions: Session[];
  liveCount: number;
  totalEvents: number;
}

function AgentGroupedList({
  sessions,
  containmentMap,
  onSelect,
  onTerminate,
}: {
  sessions: Session[];
  containmentMap: Map<string, boolean>;
  onSelect: (s: Session) => void;
  onTerminate: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // Group sessions by agent type
  const groups = useMemo(() => {
    const map = new Map<string, Session[]>();
    for (const s of sessions) {
      const key = normalizeAgentType(s.agent_type);
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(s);
    }
    const result: AgentGroup[] = [];
    for (const [agentType, group] of map) {
      // Sort sessions newest first
      group.sort((a, b) => new Date(b.start_time).getTime() - new Date(a.start_time).getTime());
      result.push({
        agentType,
        sessions: group,
        liveCount: group.filter((s) => ['ACTIVE', 'PENDING', 'WAITING_APPROVAL'].includes(s.state))
          .length,
        totalEvents: group.reduce((sum, s) => sum + s.event_count, 0),
      });
    }
    // Sort groups: agents with live sessions first, then by session count
    result.sort((a, b) => b.liveCount - a.liveCount || b.sessions.length - a.sessions.length);
    return result;
  }, [sessions]);

  const toggle = (agentType: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(agentType)) next.delete(agentType);
      else next.add(agentType);
      return next;
    });
  };

  return (
    <div className="divide-y divide-border/50">
      {groups.map((group) => {
        const isExpanded = expanded.has(group.agentType);
        const latest = group.sessions[0];
        const latestCfg = stateConfig(latest.state);
        const anyContained = group.sessions.some((s) => containmentMap.get(s.id));

        return (
          <div key={group.agentType}>
            {/* Agent group header row */}
            <button
              onClick={() => toggle(group.agentType)}
              className="w-full flex items-center gap-3 px-4 py-3.5 hover:bg-muted/20 transition-colors text-left"
            >
              <AgentIcon agent={guessAgent(group.agentType)} className="w-8 h-8 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold capitalize">{group.agentType}</span>
                  {group.liveCount > 0 && (
                    <span className="inline-flex items-center gap-1 text-[10px] bg-green-500/10 text-green-600 px-1.5 py-0.5 rounded-full font-semibold">
                      <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                      {group.liveCount} live
                    </span>
                  )}
                  {anyContained && (
                    <span className="inline-flex items-center gap-1 text-[10px] bg-[#01696F]/10 text-[#01696F] px-1.5 py-0.5 rounded-full font-semibold">
                      <ShieldBan className="h-2.5 w-2.5" />
                      CONTAINED
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-muted-foreground">
                  {group.sessions.length} session{group.sessions.length !== 1 ? 's' : ''}
                  {' · '}
                  {group.totalEvents.toLocaleString()} events
                  {group.liveCount === 0 && latest.end_time && (
                    <> · last active {new Date(latest.end_time).toLocaleDateString()}</>
                  )}
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span
                  className={cn(
                    'inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full font-medium',
                    latestCfg.bg,
                    latestCfg.color,
                  )}
                >
                  <span className={cn('w-1.5 h-1.5 rounded-full', latestCfg.dot)} />
                  {latestCfg.label}
                </span>
                {isExpanded ? (
                  <ChevronDown className="h-3.5 w-3.5 text-muted-foreground/50" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/50" />
                )}
              </div>
            </button>

            {/* Expanded session list */}
            {isExpanded && (
              <div className="bg-muted/10 border-t border-border/30">
                <table className="w-full">
                  <thead>
                    <tr className="text-[10px] uppercase tracking-wide text-muted-foreground/60">
                      <th className="px-4 pl-14 py-1.5 text-left font-medium">Session</th>
                      <th className="px-4 py-1.5 text-left font-medium">State</th>
                      <th className="px-4 py-1.5 text-left font-medium">Events</th>
                      <th className="px-4 py-1.5 text-left font-medium">Started</th>
                      <th className="px-4 py-1.5 text-left font-medium">Duration</th>
                      <th className="px-4 py-1.5 text-right font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {group.sessions.map((s, i) => {
                      const cfg = stateConfig(s.state);
                      const isContained = containmentMap.get(s.id);
                      return (
                        <tr
                          key={s.id}
                          onClick={() => onSelect(s)}
                          className="border-t border-border/20 hover:bg-muted/30 cursor-pointer transition-colors text-xs"
                        >
                          <td className="px-4 pl-14 py-2.5">
                            <div className="flex items-center gap-2">
                              <span className="text-muted-foreground/50 font-mono text-[10px] w-4">
                                #{group.sessions.length - i}
                              </span>
                              <span className="font-mono text-[11px] text-foreground/70 truncate max-w-[180px]">
                                {s.id}
                              </span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-1.5">
                              <span
                                className={cn(
                                  'inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded-full font-medium',
                                  cfg.bg,
                                  cfg.color,
                                )}
                              >
                                <span className={cn('w-1 h-1 rounded-full', cfg.dot)} />
                                {cfg.label}
                              </span>
                              {isContained && <ShieldBan className="h-3 w-3 text-[#01696F]" />}
                              {s.privileged && (
                                <span className="text-[9px] text-orange-500 font-semibold">
                                  PRIV
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-2.5 font-mono text-muted-foreground">
                            {s.event_count.toLocaleString()}
                          </td>
                          <td className="px-4 py-2.5 text-muted-foreground">
                            {new Date(s.start_time).toLocaleString([], {
                              month: 'short',
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </td>
                          <td className="px-4 py-2.5 text-muted-foreground font-mono">
                            {elapsed(s.start_time, s.end_time)}
                          </td>
                          <td
                            className="px-4 py-2.5 text-right"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {['ACTIVE', 'PENDING', 'WAITING_APPROVAL'].includes(s.state) && (
                              <button
                                onClick={() => onTerminate(s.id)}
                                className="text-[10px] bg-red-500/10 text-red-400 hover:bg-red-500/20 px-2 py-1 rounded font-medium transition-colors"
                              >
                                Terminate
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Sessions() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<Session | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [filter, setFilter] = useState<'all' | 'live' | 'terminal'>('all');
  const [containmentMap, setContainmentMap] = useState<Map<string, boolean>>(new Map());

  // Fetch containment statuses for all sessions
  useEffect(() => {
    async function fetchContainment() {
      try {
        const res = await daemonFetch(`${DAEMON_API}/containment/status`);
        if (res.ok) {
          const data = await res.json();
          const statuses: ContainmentStatus[] = Array.isArray(data) ? data : (data.statuses ?? []);
          const map = new Map<string, boolean>();
          for (const s of statuses) {
            if (s.contained) map.set(s.session_id, true);
          }
          setContainmentMap(map);
        }
      } catch {
        /* ignore */
      }
    }
    fetchContainment();
    const id = setInterval(fetchContainment, 10000);
    return () => clearInterval(id);
  }, []);

  const fetchSessions = useCallback(async () => {
    try {
      const res = await daemonFetch(`${DAEMON_API}/sessions`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setSessions(data);
      setError('');
    } catch (e) {
      setError('Cannot reach daemon — is ringzero-daemon running?');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSessions();
    const id = setInterval(fetchSessions, 5000);
    return () => clearInterval(id);
  }, [fetchSessions]);

  async function handleTerminate(id: string) {
    await daemonFetch(`${DAEMON_API}/sessions/${id}`, { method: 'DELETE' });
    fetchSessions();
    setSelected(null);
  }

  const displayed = sessions.filter((s) => {
    if (filter === 'live') return ['PENDING', 'ACTIVE', 'WAITING_APPROVAL'].includes(s.state);
    if (filter === 'terminal') return ['EXPIRED', 'TERMINATED'].includes(s.state);
    return true;
  });

  const liveCnt = sessions.filter((s) => s.state === 'ACTIVE').length;
  const totalCnt = sessions.length;
  const privilegedCnt = sessions.filter((s) => s.privileged).length;

  // --- Session Detail (inline, replaces the list) ---
  if (selected) {
    return (
      <div className="space-y-5">
        <SessionDetail
          session={selected}
          onClose={() => setSelected(null)}
          onTerminate={() => handleTerminate(selected.id)}
        />

        {/* Create dialog is modal — it's an alert/action, not navigation */}
        {showCreate && (
          <CreateDialog onClose={() => setShowCreate(false)} onCreated={fetchSessions} />
        )}
      </div>
    );
  }

  // --- Session List ---
  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Sessions</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Every AI agent session — real-time, across your org
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchSessions}
            className="p-2 rounded-md border border-border text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
          >
            <Plus className="h-4 w-4" /> New Session
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-card border border-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <div className="h-7 w-7 rounded-lg bg-green-500/10 flex items-center justify-center">
              <Shield className="h-3.5 w-3.5 text-green-400" />
            </div>
            <span className="text-xs text-muted-foreground">Active Now</span>
          </div>
          <p className="text-2xl font-bold">{liveCnt}</p>
        </div>

        <div className="bg-card border border-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <div className="h-7 w-7 rounded-lg bg-muted/30 flex items-center justify-center">
              <Users className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
            <span className="text-xs text-muted-foreground">Total Sessions</span>
          </div>
          <p className="text-2xl font-bold">{totalCnt}</p>
        </div>

        <div className="bg-card border border-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <div
              className={cn(
                'h-7 w-7 rounded-lg flex items-center justify-center',
                privilegedCnt > 0 ? 'bg-orange-500/10' : 'bg-muted/30',
              )}
            >
              <Users
                className={cn(
                  'h-3.5 w-3.5',
                  privilegedCnt > 0 ? 'text-orange-400' : 'text-muted-foreground',
                )}
              />
            </div>
            <span className="text-xs text-muted-foreground">Privileged</span>
          </div>
          <p className={cn('text-2xl font-bold', privilegedCnt > 0 && 'text-orange-400')}>
            {privilegedCnt}
          </p>
        </div>
      </div>

      {/* Table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        {/* Filter tabs */}
        <div className="flex items-center gap-1 px-4 py-3 border-b border-border">
          {(['all', 'live', 'terminal'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-medium transition-colors capitalize',
                filter === f
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:text-foreground hover:bg-muted/50',
              )}
            >
              {f === 'live' ? 'Live' : f === 'terminal' ? 'Ended' : 'All'}
              {f === 'all' && sessions.length > 0 && (
                <span className="ml-1.5 text-[10px] bg-muted/60 px-1.5 py-0.5 rounded-full">
                  {sessions.length}
                </span>
              )}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-16 text-sm text-muted-foreground">
            <RefreshCw className="h-4 w-4 mr-2 animate-spin" /> Loading sessions…
          </div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center py-16 gap-2">
            <XCircle className="h-8 w-8 text-red-400/50" />
            <p className="text-sm text-muted-foreground">{error}</p>
          </div>
        ) : displayed.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-2">
            <Clock className="h-8 w-8 text-muted-foreground/30" />
            <p className="text-sm text-muted-foreground">No sessions yet</p>
            <button
              onClick={() => setShowCreate(true)}
              className="text-xs text-primary hover:underline"
            >
              Create a session
            </button>
          </div>
        ) : (
          <AgentGroupedList
            sessions={displayed}
            containmentMap={containmentMap}
            onSelect={(s) => setSelected(s)}
            onTerminate={(id) => handleTerminate(id)}
          />
        )}
      </div>

      {/* Create dialog — modal is fine here, it's an action prompt */}
      {showCreate && (
        <CreateDialog onClose={() => setShowCreate(false)} onCreated={fetchSessions} />
      )}
    </div>
  );
}
