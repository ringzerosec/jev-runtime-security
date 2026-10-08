// SPDX-License-Identifier: Apache-2.0
// PermissionsPanel.tsx — what each agent and MCP server may do, as toggles.
//
// Every row is a few switches; the lists behind a switch (approved hosts,
// approved programs) open under "Edit". Changes are held on screen until
// "Save", which sends each changed profile as `rz profile set --json …`
// through polkit, so the administrator password is asked once per save.

import { useEffect, useMemo, useState } from 'react';
import { runPrivilegedSequence, describeFailure } from '@/lib/privileged';
import { toast } from './ui/toast';
import { cn } from '../lib/utils';
import { Bot, Plug, Globe, Terminal, Lock, Undo2, Loader2, ChevronDown, ChevronRight, X, Plus } from 'lucide-react';

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
  recent: { at: string; process: string; detail: string }[];
}

// The fields the daemon stores; everything else on a report is display-only.
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

function Switch({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      role="switch"
      aria-checked={on}
      aria-label={label}
      onClick={() => onChange(!on)}
      className={cn(
        'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
        on ? 'bg-amber-500' : 'bg-muted-foreground/30',
      )}
    >
      <span className={cn('inline-block h-4 w-4 rounded-full bg-white shadow transition-transform', on ? 'translate-x-4' : 'translate-x-0.5')} />
    </button>
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
        {items.length === 0 && <span className="text-xs text-muted-foreground">Nothing approved yet.</span>}
      </div>
      <div className="flex gap-2">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && add()}
          placeholder={placeholder}
          className="flex-1 rounded-md border bg-background px-2.5 py-1 text-xs font-mono outline-none focus:ring-2 focus:ring-primary/30"
        />
        <button onClick={add} disabled={!draft.trim()} className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs hover:bg-muted disabled:opacity-40">
          <Plus className="h-3.5 w-3.5" /> Add
        </button>
      </div>
    </div>
  );
}

// Every switch here means the same thing: ON limits it. A limit is either an
// approved list or "none at all" when the list is empty. OFF means anything.
// The lists are kept while a switch is off, so turning it back on restores them.
const kept = new Map<string, { hosts?: string[]; programs?: string[] }>();

function Row({ p, onChange }: { p: Profile; onChange: (p: Profile) => void }) {
  const [edit, setEdit] = useState(false);
  const [showRecent, setShowRecent] = useState(false);
  const isAgent = p.kind === 'agent';
  const Icon = isAgent ? Bot : Plug;
  const memo = kept.get(p.name) ?? {};

  // Network: limited unless "*" (any host) is in the list.
  const netLimited = !p.allow_hosts.includes('*');
  const hosts = p.allow_hosts.filter((h) => h !== '*');
  const setNet = (limit: boolean) => {
    if (limit) {
      onChange({ ...p, allow_hosts: memo.hosts ?? [] });
    } else {
      kept.set(p.name, { ...memo, hosts });
      onChange({ ...p, allow_hosts: ['*'] });
    }
  };

  // Programs: limited when it may not start any, or only approved ones.
  const progLimited = !p.allow_spawn || p.allow_programs.length > 0;
  const setProg = (limit: boolean) => {
    if (limit) {
      const list = memo.programs ?? [];
      onChange({ ...p, allow_spawn: list.length > 0, allow_programs: list });
    } else {
      kept.set(p.name, { ...memo, programs: p.allow_programs });
      onChange({ ...p, allow_spawn: true, allow_programs: [] });
    }
  };

  const netText = !netLimited ? 'Any host' : hosts.length ? 'Approved hosts only' : 'No network';
  const progText = !progLimited ? 'Any program' : p.allow_programs.length ? 'Approved programs only' : 'No programs';

  return (
    <div className="border-b last:border-b-0">
      <div className="grid grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)_96px] items-center gap-4 px-5 py-3.5">
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-2 rounded-lg bg-muted shrink-0"><Icon className="h-4 w-4" /></div>
          <div className="min-w-0">
            <div className="text-sm font-semibold truncate">{p.name}</div>
            <div className="text-[11px] text-muted-foreground">{isAgent ? 'Agent' : 'MCP server'}</div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <Switch on={netLimited} label={`${p.name}: limit network`} onChange={setNet} />
          <div className="text-xs leading-tight">
            <div className="font-medium">{netText}</div>
            {netLimited && hosts.length > 0 && <div className="text-muted-foreground">{hosts.length} approved</div>}
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <Switch on={progLimited} label={`${p.name}: limit programs`} onChange={setProg} />
          <div className="text-xs leading-tight">
            <div className="font-medium">{progText}</div>
            {progLimited && p.allow_programs.length > 0 && (
              <div className="text-muted-foreground">{p.allow_programs.length} approved</div>
            )}
          </div>
        </div>

        <button
          onClick={() => p.recent.length > 0 && setShowRecent((v) => !v)}
          disabled={p.recent.length === 0}
          className="text-right disabled:cursor-default"
          aria-label={`${p.stats.would_block} times outside the limits; show them`}
        >
          <div className={cn('text-xl font-semibold tabular-nums leading-none', p.stats.would_block ? 'text-amber-500' : 'text-muted-foreground/50')}>
            {p.stats.would_block}
          </div>
          <div className={cn('text-[10px] mt-1', p.recent.length ? 'text-primary hover:underline' : 'text-muted-foreground')}>
            {p.stats.would_block === 1 ? 'time' : 'times'}
          </div>
        </button>
      </div>

      {(netLimited || progLimited) && (
        <button onClick={() => setEdit((e) => !e)} className="flex items-center gap-1 px-5 pb-2.5 -mt-1 text-[11px] text-primary hover:underline">
          {edit ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          Edit approved {netLimited && progLimited ? 'hosts and programs' : netLimited ? 'hosts' : 'programs'}
        </button>
      )}
      {showRecent && (
        <div className="px-5 pb-3 space-y-1">
          <div className="text-[11px] font-medium text-muted-foreground mb-1">Latest outside the limits (recorded, not refused)</div>
          {p.recent.map((v, i) => (
            <div key={i} className="text-xs flex gap-2">
              <span className="text-muted-foreground tabular-nums shrink-0">{new Date(v.at).toLocaleTimeString()}</span>
              <span className="font-mono">{v.process}</span>
              <span className="text-muted-foreground">{v.detail}</span>
            </div>
          ))}
        </div>
      )}
      {edit && (
        <div className="grid md:grid-cols-2 gap-5 px-5 pb-4">
          {netLimited && (
            <div>
              <div className="flex items-center gap-1.5 text-xs font-medium mb-2"><Globe className="h-3.5 w-3.5" /> Approved hosts</div>
              <ListEditor items={hosts} onChange={(v) => onChange({ ...p, allow_hosts: v })} placeholder="10.0.0.0/24, 10.0.0.5, api.example.com" />
              <p className="text-[11px] text-muted-foreground mt-1.5">Empty means no network at all. IPs and ranges are exact; host names are looked up every 5 minutes.</p>
            </div>
          )}
          {progLimited && (
            <div>
              <div className="flex items-center gap-1.5 text-xs font-medium mb-2"><Terminal className="h-3.5 w-3.5" /> Approved programs</div>
              <ListEditor
                items={p.allow_programs}
                onChange={(v) => onChange({ ...p, allow_spawn: v.length > 0, allow_programs: v })}
                placeholder="git"
              />
              <p className="text-[11px] text-muted-foreground mt-1.5">Empty means it may not start any program.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function PermissionsPanel({ profiles, onSaved }: { profiles: Profile[]; onSaved: () => void }) {
  const [local, setLocal] = useState<Profile[]>(profiles);
  const [saving, setSaving] = useState(false);

  // Take fresh counts from the server without losing unsaved edits.
  useEffect(() => {
    setLocal((cur) =>
      profiles.map((sp) => {
        const edited = cur.find((c) => c.name === sp.name);
        return edited && !sameConfig(edited, sp) ? { ...edited, stats: sp.stats, recent: sp.recent } : sp;
      }),
    );
  }, [profiles]);

  const changed = useMemo(
    () => local.filter((l) => {
      const s = profiles.find((p) => p.name === l.name);
      return s && !sameConfig(s, l);
    }),
    [local, profiles],
  );

  const save = async () => {
    setSaving(true);
    try {
      const commands = changed.map((p) => ['profile', 'set', '--json', JSON.stringify(toConfig(p))]);
      const result = await runPrivilegedSequence(commands);
      if (result.ok) {
        toast({ variant: 'success', title: 'Permissions saved', description: `${result.applied} profile${result.applied === 1 ? '' : 's'} updated.` });
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

  const agents = local.filter((p) => p.kind === 'agent');
  const mcps = local.filter((p) => p.kind === 'mcp');
  const update = (np: Profile) => setLocal((ls) => ls.map((x) => (x.name === np.name ? np : x)));

  return (
    <div className="rounded-xl border bg-card overflow-hidden">
      <div className="px-5 py-2.5 border-b text-xs text-muted-foreground">
        A switch that is on limits that agent to its approved list. These limits are watched, not
        enforced yet: anything outside them is recorded and counted, never refused. Counts start
        when Ring Zero starts.
      </div>
      <div className="grid grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)_96px] gap-4 px-5 py-2 border-b bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
        <span>Agent / MCP server</span>
        <span className="flex items-center gap-1"><Globe className="h-3 w-3" /> Limit network</span>
        <span className="flex items-center gap-1"><Terminal className="h-3 w-3" /> Limit programs</span>
        <span className="text-right">Outside limits</span>
      </div>
      {agents.map((p) => <Row key={p.name} p={p} onChange={update} />)}
      {mcps.length > 0 && <div className="px-5 py-1.5 border-b bg-muted/20 text-[11px] text-muted-foreground">MCP servers</div>}
      {mcps.map((p) => <Row key={p.name} p={p} onChange={update} />)}

      {changed.length > 0 && (
        <div className="px-5 py-3 border-t bg-primary/5 flex items-center gap-3">
          <span className="text-sm">
            <span className="font-medium">{changed.length} profile{changed.length === 1 ? '' : 's'} changed</span>{' '}
            <span className="text-muted-foreground">— saving asks for the administrator password.</span>
          </span>
          <div className="ml-auto flex gap-2">
            <button onClick={() => setLocal(profiles)} disabled={saving} className="inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted">
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
