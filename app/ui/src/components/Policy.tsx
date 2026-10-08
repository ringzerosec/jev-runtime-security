// SPDX-License-Identifier: Apache-2.0
// Policy.tsx — one place for what AI on this machine is allowed to do.
//
// Every section is a control: something the kernel or the agent hook refuses.
//   1. Can anything switch Ring Zero off?        (tamper protection)
//   2. What data is off-limits to every agent?   (protected files, kernel)
//   3. What may no agent run or change?          (agent controls, kernel)
//   4. What may each agent and MCP server do?    (capability profiles, watching)
//   5. What happens to secrets in prompts?       (prompt guard, agent hook)
// Threat categories are not settings. They are labels a classifier puts on
// what happened, shown on Threats.

import { useCallback, useEffect, useState } from 'react';
import { daemonApi } from '../lib/daemonApi';
import { Badge } from './ui/badge';
import { cn } from '../lib/utils';
import ProtectedData from './ProtectedData';
import { runPrivilegedSequence, describeFailure } from '@/lib/privileged';
import { toast } from './ui/toast';
import PermissionsPanel from './PermissionsPanel';
import { Lock, Eye, MessageSquareLock, ShieldBan, LogOut, FileLock2, FileX2 } from 'lucide-react';

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
  tamper_protection?: boolean;
  prompt_guard: 'off' | 'warn' | 'block';
  controls?: Controls;
  profiles: Profile[];
}
interface Controls {
  admin_tools: boolean;
  escape_tools: boolean;
  instruction_files: boolean;
  quarantine: boolean;
  write_scan: boolean;
  lists: { admin_tools: string[]; escape_tools: string[]; instruction_files: string[] };
}
type SettingKey = 'tamper_protection' | 'prompt_guard' | 'admin_tools' | 'escape_tools' | 'instruction_files' | 'quarantine';

function ToggleSwitch({ on, busy, label, onChange }: { on: boolean; busy?: boolean; label: string; onChange: (v: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={busy}
      onClick={() => onChange(!on)}
      className={cn(
        'relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
        on ? 'bg-primary' : 'bg-muted-foreground/30',
      )}
    >
      <span className={cn('inline-block h-5 w-5 rounded-full bg-white shadow transition-transform', on ? 'translate-x-5' : 'translate-x-0.5')} />
    </button>
  );
}

/** One posture tile: green when on, amber when off, neutral when informational. */
function Posture({ ok, label, value }: { ok: boolean | null; label: string; value: string }) {
  return (
    <div
      className={cn(
        'rounded-xl border px-4 py-3',
        ok === true && 'border-emerald-500/25 bg-emerald-500/5',
        ok === false && 'border-amber-500/30 bg-amber-500/5',
        ok === null && 'bg-card',
      )}
    >
      <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={cn('text-sm font-semibold mt-0.5', ok === true && 'text-emerald-600', ok === false && 'text-amber-600')}>
        {value}
      </div>
    </div>
  );
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

/** One kernel control: what it refuses, the exact list, and its switch. */
function ControlRow({
  icon: Icon,
  title,
  text,
  items,
  on,
  enforcing,
  busy,
  onChange,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  text: string;
  items?: string[];
  on: boolean;
  enforcing: boolean;
  busy: boolean;
  onChange: (v: boolean) => void;
}) {
  const status = !on ? 'Off' : enforcing ? 'Blocks' : 'Watching only';
  return (
    <div className="flex items-start gap-4 px-5 py-4">
      <Icon className="h-5 w-5 text-muted-foreground shrink-0 mt-0.5" />
      <div className="flex-1 min-w-0">
        <div className="text-sm font-semibold flex items-center gap-2">
          {title}
          <span
            className={cn(
              'rounded-full px-2 py-0.5 text-[10px] font-medium',
              status === 'Blocks' && 'bg-emerald-500/10 text-emerald-600',
              status === 'Watching only' && 'bg-amber-500/10 text-amber-600',
              status === 'Off' && 'bg-muted text-muted-foreground',
            )}
          >
            {status}
          </span>
        </div>
        <div className="text-xs text-muted-foreground mt-0.5">{text}</div>
        {items && items.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {items.map((it) => (
              <span key={it} className="rounded-md border bg-muted/40 px-1.5 py-0.5 font-mono text-[11px]">
                {it}
              </span>
            ))}
          </div>
        )}
      </div>
      <ToggleSwitch on={on} busy={busy} label={title} onChange={onChange} />
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

  const load = useCallback(async () => {
    try {
      setState(await daemonApi<PolicyState>('GET', '/api/v1/policy/profiles'));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not reach the daemon');
    }
  }, []);
  useEffect(() => {
    void load();
    const t = setInterval(load, 5000); // live "would block" counts
    return () => clearInterval(t);
  }, [load]);

  // One privileged change, asked for and applied immediately — the same
  // password prompt every time, never cached.
  const [applying, setApplying] = useState<string | null>(null);
  const applySetting = async (key: SettingKey, value: string) => {
    setApplying(key);
    try {
      const r = await runPrivilegedSequence([['settings', 'set', key, value]]);
      if (r.ok) {
        toast({ variant: 'success', title: 'Saved', description: 'The change is in effect.' });
        await load();
      } else {
        const { title, description } = describeFailure(r);
        toast({ variant: 'error', title, description });
      }
    } finally {
      setApplying(null);
    }
  };
  const offProtections = state
    ? [
        state.tamper_protection === false && 'Tamper protection is off',
        state.prompt_guard === 'off' && 'Secrets in prompts are not checked',
        state.controls?.admin_tools === false && 'Agents may run admin tools',
        state.controls?.escape_tools === false && 'Agents may start work outside their own process',
        state.mode !== 'enforce' && 'This machine is only watching; nothing is refused',
      ].filter(Boolean)
    : [];

  const enforcing = state?.mode === 'enforce';
  const c = state?.controls;
  const controlsTotal = 4;
  const controlsOn = c ? [c.admin_tools, c.escape_tools, c.instruction_files, c.quarantine].filter(Boolean).length : 0;
  const pg = PROMPT_GUARD_TEXT[state?.prompt_guard ?? 'warn'];

  return (
    <div className="space-y-10 max-w-5xl">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Policy</h1>
        <p className="text-sm text-muted-foreground mt-1">
          What AI on this machine is allowed to do. Each section says whether it is enforced or
          only watched.
        </p>
      </div>

      {/* Posture at a glance */}
      {state && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Posture
            ok={state.mode === 'enforce'}
            label="Mode"
            value={state.mode === 'enforce' ? 'Enforcing' : 'Watching only'}
          />
          <Posture
            ok={state.tamper_protection !== false}
            label="Tamper protection"
            value={state.tamper_protection !== false ? 'On' : 'Off'}
          />
          <Posture
            ok={state.prompt_guard === 'block'}
            label="Secrets in prompts"
            value={state.prompt_guard === 'block' ? 'Blocked' : state.prompt_guard === 'warn' ? 'Recorded' : 'Not checked'}
          />
          <Posture
            ok={controlsOn === controlsTotal}
            label="Agent controls"
            value={`${controlsOn} of ${controlsTotal} on`}
          />
        </div>
      )}

      {offProtections.length > 0 && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-800 dark:text-amber-200">
          <span className="font-semibold">Protection is reduced.</span> {offProtections.join(' · ')}.
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-500">
          {error}
        </div>
      )}

      {/* 2 — Protected data */}
      {/* Product security */}
      <section>
        <SectionTitle n={1} title="Product security" question="Can anything switch Ring Zero off?" />
        <div className="rounded-xl border bg-card divide-y">
          <div className="flex items-center gap-4 px-5 py-4">
            <div className="flex-1">
              <div className="text-sm font-semibold flex items-center gap-1.5">
                Tamper protection <Lock className="h-3 w-3 text-muted-foreground" aria-label="Needs an administrator" />
              </div>
              <div className="text-xs text-muted-foreground mt-0.5">
                No agent can stop, debug or unload Ring Zero, or touch its settings. Turning this off asks for the administrator password.
              </div>
            </div>
            <ToggleSwitch
              on={state?.tamper_protection !== false}
              busy={applying === 'tamper_protection'}
              label="Tamper protection"
              onChange={(v) => applySetting('tamper_protection', v ? 'on' : 'off')}
            />
          </div>
          <div className="flex items-center gap-4 px-5 py-3 text-xs text-muted-foreground">
            <Lock className="h-3.5 w-3.5" /> Every change on this page asks for the administrator password. Agents can never make these changes.
          </div>
        </div>
      </section>

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
        <ProtectedData />
      </section>

      {/* 3 — Agent controls */}
      <section>
        <SectionTitle
          n={3}
          title="Agent controls"
          question="What may no agent run or change?"
          right={
            <Badge variant="outline" className="gap-1 border-emerald-500/30 text-emerald-500">
              <Lock className="h-3 w-3" /> Enforced by the kernel
            </Badge>
          }
        />
        <div className="rounded-xl border bg-card divide-y">
          <ControlRow
            icon={ShieldBan}
            title="Agents can't run admin tools"
            text="Refused to every agent and anything it starts. This includes terminals inside AI editors such as Cursor and Windsurf."
            items={c?.lists.admin_tools}
            on={!!c?.admin_tools}
            enforcing={enforcing}
            busy={applying === 'admin_tools'}
            onChange={(v) => applySetting('admin_tools', v ? 'on' : 'off')}
          />
          <ControlRow
            icon={LogOut}
            title="Agents can't start work outside their own process"
            text="These start a program that no longer traces back to the agent, so nothing could follow what it does."
            items={c?.lists.escape_tools}
            on={!!c?.escape_tools}
            enforcing={enforcing}
            busy={applying === 'escape_tools'}
            onChange={(v) => applySetting('escape_tools', v ? 'on' : 'off')}
          />
          <ControlRow
            icon={FileLock2}
            title="Agents can't change their own instructions"
            text="Agents may read these files but not change, create, rename or delete them. Turn this off while you ask an agent to edit one."
            items={c?.lists.instruction_files}
            on={!!c?.instruction_files}
            enforcing={enforcing}
            busy={applying === 'instruction_files'}
            onChange={(v) => applySetting('instruction_files', v ? 'on' : 'off')}
          />
          <ControlRow
            icon={FileX2}
            title="Agents can't run flagged files they wrote"
            text={
              c && !c.write_scan
                ? 'Files agents write are not being scanned on this machine, so nothing is flagged.'
                : 'Every file an agent writes is scanned when it is saved. If the scan finds something serious, no agent may run or open that file.'
            }
            on={!!c?.quarantine}
            enforcing={enforcing}
            busy={applying === 'quarantine'}
            onChange={(v) => applySetting('quarantine', v ? 'on' : 'off')}
          />
        </div>
      </section>

      {/* 3 — Capability profiles */}
      <section>
        <SectionTitle
          n={4}
          title="Agent & tool permissions"
          question="What may each agent and MCP server do?"
          right={
            <Badge variant="outline" className="gap-1 border-amber-500/30 text-amber-500">
              <Eye className="h-3 w-3" /> Watching only
            </Badge>
          }
        />
        {state && state.profiles.length === 0 ? (
          <div className="rounded-lg border border-dashed p-6 text-sm text-muted-foreground">
            No agent permissions are set yet.
          </div>
        ) : (
          state && <PermissionsPanel profiles={state.profiles} onSaved={load} />
        )}
      </section>

      {/* 4 — Prompts */}
      <section>
        <SectionTitle n={5} title="Prompts" question="What happens to a secret pasted into a prompt?" />
        <div className="rounded-xl border bg-card px-5 py-4 flex items-center gap-4">
          <MessageSquareLock className="h-5 w-5 text-muted-foreground shrink-0" />
          <div className="flex-1">
            <div className="text-sm font-semibold flex items-center gap-1.5">
              Secrets in prompts <Lock className="h-3 w-3 text-muted-foreground" aria-label="Needs an administrator" />
            </div>
            <div className="text-xs text-muted-foreground mt-0.5">{pg.text} Checked on this machine; nothing is sent anywhere to check it.</div>
          </div>
          <div className="inline-flex rounded-lg border p-0.5 text-xs shrink-0" role="radiogroup" aria-label="Secrets in prompts">
            {([['off', 'Off'], ['warn', 'Detect'], ['block', 'Block']] as const).map(([val, lab]) => (
              <button
                key={val}
                role="radio"
                aria-checked={state?.prompt_guard === val}
                disabled={applying === 'prompt_guard'}
                onClick={() => state?.prompt_guard !== val && applySetting('prompt_guard', val)}
                className={cn(
                  'px-3 py-1.5 rounded-md transition-colors',
                  state?.prompt_guard === val ? 'bg-primary text-primary-foreground font-medium' : 'text-muted-foreground hover:bg-muted',
                )}
              >
                {lab}
              </button>
            ))}
          </div>
        </div>
      </section>

    </div>
  );
}
