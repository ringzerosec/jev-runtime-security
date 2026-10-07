// SPDX-License-Identifier: Apache-2.0
// Policy.tsx — one place for what AI on this machine is allowed to do.
//
// Four questions, top to bottom:
//   1. How strict is this machine?            (mode)
//   2. What data is off-limits to every agent? (protected files — kernel-enforced)
//   3. What may each agent and MCP server do?  (capability profiles — watching)
//   4. What happens to secrets in prompts?     (prompt guard)
// The older per-category alert settings sit at the bottom, collapsed, because
// they record violations rather than refuse anything.

import { useEffect, useState } from 'react';
import { daemonApi } from '../lib/daemonApi';
import { Badge } from './ui/badge';
import { cn } from '../lib/utils';
import FileAccess from './FileAccess';
import Enforcement from './Enforcement';
import {
  Lock,
  Eye,
  Bot,
  Plug,
  Globe,
  Terminal,
  MessageSquareLock,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react';

interface Violation {
  profile: string;
  rule: string;
  detail: string;
  pid: number;
  process: string;
  at: string;
}
interface Profile {
  name: string;
  kind: 'agent' | 'mcp';
  agent?: string;
  mcp_match: string[];
  allow_hosts: string[];
  allow_spawn: boolean;
  allow_programs: string[];
  stats: { allowed: number; would_block: number };
  recent: Violation[];
}
interface PolicyState {
  stage: string;
  mode: string;
  prompt_guard: 'off' | 'warn' | 'block';
  profiles: Profile[];
}

function SectionTitle({
  n,
  title,
  question,
  right,
}: {
  n: number;
  title: string;
  question: string;
  right?: React.ReactNode;
}) {
  return (
    <div className="flex items-end justify-between gap-4 mb-3">
      <div>
        <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          {n} · {title}
        </div>
        <h2 className="text-base font-semibold">{question}</h2>
      </div>
      {right}
    </div>
  );
}

function networkLine(p: Profile): string {
  if (p.allow_hosts.length === 0) return 'No network access';
  if (p.allow_hosts.includes('*')) return 'Any host';
  return `Only ${p.allow_hosts.join(', ')}`;
}
function programsLine(p: Profile): string {
  if (!p.allow_spawn) return 'May not start other programs';
  if (p.allow_programs.length === 0) return 'May start any program';
  return `Only ${p.allow_programs.join(', ')}`;
}

function ProfileCard({ p }: { p: Profile }) {
  const [open, setOpen] = useState(false);
  const Icon = p.kind === 'agent' ? Bot : Plug;
  const blocked = p.stats.would_block;
  return (
    <div className="rounded-lg border bg-card">
      <div className="px-4 py-3 flex items-start justify-between gap-4">
        <div className="flex items-start gap-3 min-w-0">
          <div className="p-2 rounded-md bg-muted">
            <Icon className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-medium">
              {p.name}{' '}
              <span className="text-xs font-normal text-muted-foreground">
                {p.kind === 'agent' ? 'Agent' : 'MCP server'}
              </span>
            </div>
            <div className="mt-1.5 space-y-1 text-xs">
              <div className="flex items-center gap-1.5">
                <Globe className="h-3.5 w-3.5 text-muted-foreground" />
                {networkLine(p)}
              </div>
              <div className="flex items-center gap-1.5">
                <Terminal className="h-3.5 w-3.5 text-muted-foreground" />
                {programsLine(p)}
              </div>
            </div>
          </div>
        </div>
        <div className="text-right shrink-0">
          <div className="text-xs text-muted-foreground tabular-nums">{p.stats.allowed} allowed</div>
          <div
            className={cn(
              'text-sm font-semibold tabular-nums',
              blocked ? 'text-amber-500' : 'text-muted-foreground',
            )}
          >
            {blocked} would block
          </div>
        </div>
      </div>
      {p.recent.length > 0 && (
        <div className="border-t">
          <button
            onClick={() => setOpen((o) => !o)}
            className="w-full px-4 py-2 flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            Latest {p.recent.length} outside this profile
          </button>
          {open && (
            <div className="px-4 pb-3 space-y-1.5">
              {p.recent.map((v, i) => (
                <div key={i} className="text-xs flex gap-2">
                  <span className="text-muted-foreground tabular-nums shrink-0">
                    {new Date(v.at).toLocaleTimeString()}
                  </span>
                  <span className="font-mono">{v.process}</span>
                  <span className="text-muted-foreground">{v.detail}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const PROMPT_GUARD_TEXT: Record<string, { label: string; text: string; cls: string }> = {
  block: {
    label: 'Blocked',
    text: 'A prompt that contains a secret is not sent. The person sees why; the trace keeps the secret masked.',
    cls: 'border-emerald-500/30 text-emerald-500',
  },
  warn: {
    label: 'Recorded',
    text: 'A prompt that contains a secret is sent, and recorded with the secret masked.',
    cls: 'border-amber-500/30 text-amber-500',
  },
  off: {
    label: 'Off',
    text: 'Prompts are not checked for secrets.',
    cls: 'border-border text-muted-foreground',
  },
};

export default function Policy() {
  const [state, setState] = useState<PolicyState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showCategories, setShowCategories] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const s = await daemonApi<PolicyState>('GET', '/api/v1/policy/profiles');
        if (alive) {
          setState(s);
          setError(null);
        }
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : 'Could not reach the daemon');
      }
    };
    void load();
    const t = setInterval(load, 5000); // live "would block" counts
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const enforcing = state?.mode === 'enforce';
  const pg = PROMPT_GUARD_TEXT[state?.prompt_guard ?? 'warn'];
  const agents = state?.profiles.filter((p) => p.kind === 'agent') ?? [];
  const mcps = state?.profiles.filter((p) => p.kind === 'mcp') ?? [];

  return (
    <div className="space-y-10 max-w-5xl">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Policy</h1>
        <p className="text-sm text-muted-foreground mt-1">
          What AI on this machine is allowed to do. Enforced in the operating system, below every
          agent; changing it needs an administrator password.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-500">
          {error}
        </div>
      )}

      {/* 1 — Mode */}
      <section>
        <SectionTitle n={1} title="Mode" question="How strict is this machine?" />
        <div
          className={cn(
            'rounded-lg border px-5 py-4 flex items-center gap-4',
            enforcing ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-amber-500/30 bg-amber-500/5',
          )}
        >
          {enforcing ? (
            <ShieldCheck className="h-6 w-6 text-emerald-500" />
          ) : (
            <Eye className="h-6 w-6 text-amber-500" />
          )}
          <div>
            <div className="text-sm font-semibold">{enforcing ? 'Enforcing' : 'Watching only'}</div>
            <div className="text-xs text-muted-foreground">
              {enforcing
                ? 'Protected data below is refused by the kernel, for every agent and everything it starts.'
                : 'Everything is recorded; nothing is refused yet.'}
            </div>
          </div>
        </div>
      </section>

      {/* 2 — Protected data */}
      <section>
        <SectionTitle
          n={2}
          title="Protected data"
          question="What may no agent ever touch?"
          right={
            <Badge variant="outline" className="gap-1 border-emerald-500/30 text-emerald-500">
              <Lock className="h-3 w-3" /> Enforced by the kernel
            </Badge>
          }
        />
        <FileAccess embedded />
      </section>

      {/* 3 — Capability profiles */}
      <section>
        <SectionTitle
          n={3}
          title="Agent & tool permissions"
          question="What may each agent and MCP server do?"
          right={
            <Badge variant="outline" className="gap-1 border-amber-500/30 text-amber-500">
              <Eye className="h-3 w-3" /> Watching — would-block is recorded
            </Badge>
          }
        />
        {state && state.profiles.length === 0 ? (
          <div className="rounded-lg border border-dashed p-6 text-sm text-muted-foreground">
            No permissions are set yet. Add a <span className="font-mono">[[profiles]]</span> entry
            per agent or MCP server in <span className="font-mono">/etc/ringzero/daemon.toml</span>.
          </div>
        ) : (
          <div className="space-y-6">
            {agents.length > 0 && (
              <div className="space-y-2">
                <div className="text-xs text-muted-foreground">Agents</div>
                {agents.map((p) => (
                  <ProfileCard key={p.name} p={p} />
                ))}
              </div>
            )}
            {mcps.length > 0 && (
              <div className="space-y-2">
                <div className="text-xs text-muted-foreground">MCP servers</div>
                {mcps.map((p) => (
                  <ProfileCard key={p.name} p={p} />
                ))}
              </div>
            )}
          </div>
        )}
      </section>

      {/* 4 — Prompts */}
      <section>
        <SectionTitle n={4} title="Prompts" question="What happens to a secret pasted into a prompt?" />
        <div className="rounded-lg border bg-card px-5 py-4 flex items-start gap-4">
          <MessageSquareLock className="h-5 w-5 mt-0.5 text-muted-foreground" />
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold">Secrets in prompts</span>
              <Badge variant="outline" className={pg.cls}>
                {pg.label}
              </Badge>
            </div>
            <div className="text-xs text-muted-foreground mt-1">
              {pg.text} Checked on this machine; nothing is sent anywhere to check it.
            </div>
          </div>
        </div>
      </section>

      {/* 5 — Alert categories (collapsed) */}
      <section>
        <button
          onClick={() => setShowCategories((v) => !v)}
          className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
        >
          {showCategories ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          Alert categories
          <span className="text-xs">(record and flag for review; they do not refuse anything)</span>
        </button>
        {showCategories && (
          <div className="mt-4">
            <div className="mb-3 flex items-center gap-2 text-xs text-muted-foreground">
              <AlertTriangle className="h-3.5 w-3.5" />
              Refusals come from Protected data and, once enforced, Agent &amp; tool permissions above.
            </div>
            <Enforcement embedded />
          </div>
        )}
      </section>
    </div>
  );
}
