// SPDX-License-Identifier: Apache-2.0
// PermissionsPanel.tsx — what each agent and MCP server may reach and run.
//
// Every agent Discovery found is listed, whether or not it has limits yet.
// Pick one, and set Network and Programs to one of three things:
//   No limit — anything goes, nothing is recorded against it
//   Watch    — anything outside the approved list is recorded, not refused
//   Block    — the kernel refuses anything outside the list
// Things the agent actually reached outside its list are offered for
// approval, so a list is built from real work. One Save sends every changed
// profile as `rz profile set --json …` through polkit: the administrator
// password is asked once per save.

import { useEffect, useMemo, useState } from 'react';
import { runPrivilegedSequence, describeFailure } from '@/lib/privileged';
import { toast } from './ui/toast';
import { cn } from '../lib/utils';
import { Bot, Plug, Globe, Terminal, Lock, Undo2, Loader2, X, Plus, Check } from 'lucide-react';

export interface Profile {
  name: string;
  kind: 'agent' | 'mcp';
  agent?: string;
  mcp_match: string[];
  allow_hosts: string[];
  allow_spawn: boolean;
  allow_programs: string[];
  network_mode?: 'watch' | 'enforce';
  programs_mode?: 'watch' | 'enforce';
  stats: { allowed: number; would_block: number };
  recent: { at: string; process: string; detail: string; rule?: string }[];
  /** Found by Discovery, no profile saved yet. */
  unsaved?: boolean;
}

export interface DiscoveredAgent {
  id: string;
  name: string;
}

type Level = 'none' | 'watch' | 'block';

const toConfig = (p: Profile) => ({
  name: p.name,
  ...(p.agent ? { agent: p.agent } : { mcp_match: p.mcp_match }),
  allow_hosts: p.allow_hosts,
  allow_spawn: p.allow_spawn,
  allow_programs: p.allow_programs,
  network_mode: p.network_mode ?? 'watch',
  programs_mode: p.programs_mode ?? 'watch',
});
const sameConfig = (a: Profile, b: Profile) => JSON.stringify(toConfig(a)) === JSON.stringify(toConfig(b));

const netLevel = (p: Profile): Level =>
  p.allow_hosts.includes('*') ? 'none' : p.network_mode === 'enforce' ? 'block' : 'watch';
const progLevel = (p: Profile): Level =>
  p.allow_spawn && p.allow_programs.length === 0 ? 'none' : p.programs_mode === 'enforce' ? 'block' : 'watch';

const LEVEL_TEXT: Record<Level, string> = { none: 'No limit', watch: 'Watching', block: 'Blocking' };

function blankProfile(a: DiscoveredAgent): Profile {
  return {
    name: a.name,
    kind: 'agent',
    agent: a.id,
    mcp_match: [],
    allow_hosts: ['*'],
    allow_spawn: true,
    allow_programs: [],
    network_mode: 'watch',
    programs_mode: 'watch',
    stats: { allowed: 0, would_block: 0 },
    recent: [],
    unsaved: true,
  };
}

/** What the agent reached outside its list, from recorded violations. */
function seenOutside(p: Profile, which: 'network' | 'programs'): string[] {
  const out = new Set<string>();
  for (const v of p.recent) {
    if (which === 'network') {
      const m = v.detail.match(/connected to ([^\s:,]+)(?::\d+)?/);
      if (m) out.add(m[1]);
    } else {
      const m = v.detail.match(/started ([^\s;,]+)/);
      if (m) out.add(m[1]);
    }
  }
  const have = which === 'network' ? p.allow_hosts : p.allow_programs;
  return [...out].filter((x) => !have.includes(x));
}

function Choice({ value, onChange, label }: { value: Level; onChange: (l: Level) => void; label: string }) {
  return (
    <div className="inline-flex rounded-lg border p-0.5 text-xs" role="radiogroup" aria-label={label}>
      {(['none', 'watch', 'block'] as const).map((l) => (
        <button
          key={l}
          role="radio"
          aria-checked={value === l}
          onClick={() => value !== l && onChange(l)}
          className={cn(
            'px-3 py-1.5 rounded-md transition-colors',
            value === l
              ? l === 'block'
                ? 'bg-primary text-primary-foreground font-medium'
                : l === 'watch'
                  ? 'bg-amber-500/15 text-amber-700 font-medium'
                  : 'bg-muted font-medium'
              : 'text-muted-foreground hover:bg-muted/60',
          )}
        >
          {l === 'none' ? 'No limit' : l === 'watch' ? 'Watch' : 'Block'}
        </button>
      ))}
    </div>
  );
}

function ListEditor({ items, onChange, placeholder }: { items: string[]; onChange: (v: string[]) => void; placeholder: string }) {
  const [draft, setDraft] = useState('');
  const add = () => {
    const v = draft.trim();
    if (v && !items.includes(v)) onChange([...items, v]);
    setDraft('');
  };
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {items.map((it) => (
          <span key={it} className="inline-flex items-center gap-1 rounded-md border bg-muted/40 pl-2 pr-1 py-0.5 font-mono text-[11px]">
            {it}
            <button onClick={() => onChange(items.filter((x) => x !== it))} aria-label={`Remove ${it}`} className="rounded p-0.5 hover:bg-muted">
              <X className="h-3 w-3" />
            </button>
          </span>
        ))}
      </div>
      <div className="flex gap-2">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && add()}
          placeholder={placeholder}
          className="flex-1 min-w-0 rounded-md border bg-background px-2.5 py-1.5 text-xs font-mono outline-none focus:ring-2 focus:ring-primary/30"
        />
        <button onClick={add} disabled={!draft.trim()} className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs hover:bg-muted disabled:opacity-40">
          <Plus className="h-3.5 w-3.5" /> Add
        </button>
      </div>
    </div>
  );
}

function Suggestions({ items, onApprove }: { items: string[]; onApprove: (x: string) => void }) {
  if (items.length === 0) return null;
  return (
    <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2.5">
      <div className="text-[11px] font-medium text-amber-700 mb-1.5">Seen outside the list. Approve to add it.</div>
      <div className="flex flex-wrap gap-1.5">
        {items.map((x) => (
          <button
            key={x}
            onClick={() => onApprove(x)}
            className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-0.5 font-mono text-[11px] hover:border-primary hover:text-primary"
          >
            <Check className="h-3 w-3" /> {x}
          </button>
        ))}
      </div>
    </div>
  );
}

function Section({
  icon: Icon,
  title,
  level,
  onLevel,
  explain,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  level: Level;
  onLevel: (l: Level) => void;
  explain: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border bg-card p-4 space-y-3">
      <div className="flex items-center gap-3 flex-wrap">
        <Icon className="h-4 w-4 text-muted-foreground" />
        <h4 className="text-sm font-semibold flex-1">{title}</h4>
        <Choice value={level} onChange={onLevel} label={title} />
      </div>
      <p className="text-xs text-muted-foreground">{explain}</p>
      {level !== 'none' && children}
    </div>
  );
}

function Detail({ p, onChange }: { p: Profile; onChange: (p: Profile) => void }) {
  const net = netLevel(p);
  const prog = progLevel(p);
  const hosts = p.allow_hosts.filter((h) => h !== '*');

  const setNet = (l: Level) => {
    if (l === 'none') onChange({ ...p, allow_hosts: ['*'] });
    else onChange({ ...p, allow_hosts: hosts, network_mode: l === 'block' ? 'enforce' : 'watch' });
  };
  const setProg = (l: Level) => {
    if (l === 'none') onChange({ ...p, allow_spawn: true, allow_programs: [] });
    else
      onChange({
        ...p,
        allow_spawn: p.allow_programs.length > 0,
        programs_mode: l === 'block' ? 'enforce' : 'watch',
      });
  };

  const netExplain =
    net === 'none'
      ? `${p.name} may connect anywhere.`
      : `${p.name} may connect only to the hosts below. ${net === 'block' ? 'Anything else is refused by the kernel.' : 'Anything else is recorded, not refused.'} Its own model service is always reachable.`;
  const progExplain =
    prog === 'none'
      ? `${p.name} may run any program.`
      : p.allow_programs.length === 0
        ? `${p.name} may not start any program. ${prog === 'block' ? 'The kernel refuses them.' : 'Recorded, not refused.'}`
        : `${p.name} and everything it starts may run only the programs below. ${prog === 'block' ? 'Anything else is refused by the kernel.' : 'Anything else is recorded, not refused.'}`;

  return (
    <div className="space-y-3">
      <Section icon={Globe} title="Network" level={net} onLevel={setNet} explain={netExplain}>
        <ListEditor items={hosts} onChange={(v) => onChange({ ...p, allow_hosts: v })} placeholder="api.example.com, *.github.com, 10.0.0.0/24" />
        <Suggestions items={seenOutside(p, 'network')} onApprove={(x) => onChange({ ...p, allow_hosts: [...hosts, x] })} />
      </Section>
      <Section icon={Terminal} title="Programs" level={prog} onLevel={setProg} explain={progExplain}>
        <ListEditor
          items={p.allow_programs}
          onChange={(v) => onChange({ ...p, allow_programs: v, allow_spawn: v.length > 0 })}
          placeholder="git"
        />
        <Suggestions
          items={seenOutside(p, 'programs')}
          onApprove={(x) => onChange({ ...p, allow_programs: [...p.allow_programs, x], allow_spawn: true })}
        />
      </Section>
    </div>
  );
}

function statusLine(p: Profile): string {
  const n = netLevel(p);
  const g = progLevel(p);
  if (n === 'none' && g === 'none') return 'No limits';
  if (n === g) return `${LEVEL_TEXT[n]} network and programs`;
  return `Network ${LEVEL_TEXT[n].toLowerCase()} · programs ${LEVEL_TEXT[g].toLowerCase()}`;
}

export default function PermissionsPanel({
  profiles,
  discovered = [],
  onSaved,
}: {
  profiles: Profile[];
  discovered?: DiscoveredAgent[];
  onSaved: () => void;
}) {
  // Saved profiles, then every discovered agent that has none yet.
  const baseline = useMemo(() => {
    const out = [...profiles];
    const seen = new Set(profiles.map((p) => p.agent).filter(Boolean));
    for (const a of discovered) {
      if (!seen.has(a.id)) {
        seen.add(a.id);
        out.push(blankProfile(a));
      }
    }
    return out;
  }, [profiles, discovered]);

  const [local, setLocal] = useState<Profile[]>(baseline);
  const [selected, setSelected] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Fresh counts from the server, keeping unsaved edits.
  useEffect(() => {
    setLocal((cur) =>
      baseline.map((b) => {
        const edited = cur.find((c) => c.name === b.name);
        return edited && !sameConfig(edited, b) ? { ...edited, stats: b.stats, recent: b.recent } : b;
      }),
    );
  }, [baseline]);

  const changed = local.filter((l) => {
    const b = baseline.find((x) => x.name === l.name);
    return b && !sameConfig(b, l);
  });
  const current = local.find((p) => p.name === selected) ?? local[0];
  const update = (np: Profile) => setLocal((ls) => ls.map((x) => (x.name === np.name ? np : x)));

  const save = async () => {
    setSaving(true);
    try {
      const result = await runPrivilegedSequence(changed.map((p) => ['profile', 'set', '--json', JSON.stringify(toConfig(p))]));
      if (result.ok) {
        toast({ variant: 'success', title: 'Permissions saved', description: `${result.applied} agent${result.applied === 1 ? '' : 's'} updated.` });
        onSaved();
      } else {
        const { title, description } = describeFailure(result);
        toast({ variant: 'error', title, description });
        if (result.applied > 0) onSaved();
      }
    } finally {
      setSaving(false);
    }
  };

  if (local.length === 0) {
    return <div className="rounded-xl border border-dashed p-6 text-sm text-muted-foreground">No agents found on this machine yet.</div>;
  }

  const agents = local.filter((p) => p.kind === 'agent');
  const mcps = local.filter((p) => p.kind === 'mcp');
  const renderRow = (p: Profile) => {
    const n = netLevel(p);
    const g = progLevel(p);
    const level = n === 'block' || g === 'block' ? 'block' : n === 'watch' || g === 'watch' ? 'watch' : 'none';
    const Icon = p.kind === 'agent' ? Bot : Plug;
    const dirty = changed.some((c) => c.name === p.name);
    return (
      <button
        key={p.name}
        onClick={() => setSelected(p.name)}
        className={cn(
          'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors',
          current?.name === p.name ? 'bg-primary/10' : 'hover:bg-muted/60',
        )}
      >
        <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium truncate flex items-center gap-1.5">
            {p.name}
            {dirty && <span className="h-1.5 w-1.5 rounded-full bg-primary" aria-label="unsaved change" />}
          </div>
          <div className={cn('text-[11px] truncate', level === 'block' ? 'text-primary' : level === 'watch' ? 'text-amber-600' : 'text-muted-foreground')}>
            {statusLine(p)}
          </div>
        </div>
        {p.stats.would_block > 0 && (
          <span className="rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 tabular-nums" title="Times outside its limits since Ring Zero started">
            {p.stats.would_block}
          </span>
        )}
      </button>
    );
  };

  return (
    <div className="rounded-xl border bg-card overflow-hidden">
      <div className="grid md:grid-cols-[260px_minmax(0,1fr)]">
        <div className="border-b md:border-b-0 md:border-r p-2 space-y-0.5 bg-muted/20">
          <div className="px-3 pt-1 pb-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">Agents</div>
          {agents.map(renderRow)}
          {mcps.length > 0 && <div className="px-3 pt-3 pb-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">MCP servers</div>}
          {mcps.map(renderRow)}
        </div>
        <div className="p-4 space-y-3 min-w-0">
          {current && (
            <>
              <div>
                <h3 className="text-base font-semibold">{current.name}</h3>
                <p className="text-xs text-muted-foreground">
                  {current.unsaved && !changed.some((c) => c.name === current.name)
                    ? 'Found on this machine. No limits set yet.'
                    : current.stats.would_block > 0
                      ? `Outside its limits ${current.stats.would_block} time${current.stats.would_block === 1 ? '' : 's'} since Ring Zero started.`
                      : 'Nothing outside its limits since Ring Zero started.'}
                </p>
              </div>
              <Detail p={current} onChange={update} />
            </>
          )}
        </div>
      </div>

      {changed.length > 0 && (
        <div className="px-4 py-3 border-t bg-primary/5 flex items-center gap-3">
          <span className="text-sm">
            <span className="font-medium">
              {changed.length} agent{changed.length === 1 ? '' : 's'} changed
            </span>{' '}
            <span className="text-muted-foreground">· saving asks for the administrator password.</span>
          </span>
          <div className="ml-auto flex gap-2">
            <button onClick={() => setLocal(baseline)} disabled={saving} className="inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted">
              <Undo2 className="h-4 w-4" /> Undo
            </button>
            <button onClick={save} disabled={saving} className="inline-flex items-center gap-1.5 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-60">
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
              Save
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
