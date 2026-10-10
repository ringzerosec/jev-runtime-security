// SPDX-License-Identifier: Apache-2.0
// DiscoveryInventory.tsx — what AI is installed on this machine.
// Agents, IDE AI extensions, MCP servers and local model runtimes, across all
// users, with whether enforcement covers each agent. Read-only; driven by
// GET /api/v1/discovery/inventory. Secrets never reach this screen: the daemon
// reports MCP environment variables by name and redacts credential-like args.

import { useEffect, useState } from 'react';
import { daemonApi } from '../lib/daemonApi';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { cn } from '../lib/utils';
import { runPrivilegedSequence, describeFailure } from '@/lib/privileged';
import { toast } from './ui/toast';
import {
  Bot,
  Plug,
  Puzzle,
  Cpu,
  ShieldCheck,
  ShieldOff,
  Loader2,
  RefreshCw,
  Globe,
  KeyRound,
  PackageOpen,
  ShieldHalf,
} from 'lucide-react';

interface AgentInstall {
  id: string;
  name: string;
  owner: string;
  binary?: string;
  config_dir?: string;
  enforcement_covered: boolean;
}
interface IdeExtension {
  id: string;
  name: string;
  editor: string;
  version: string;
  owner: string;
  path: string;
}
interface McpServer {
  name: string;
  agent: string;
  owner: string;
  source: string;
  scope: string;
  transport: string;
  command?: string;
  url?: string;
  env_keys: string[];
  flags: string[];
  tools?: { name: string; description?: string }[];
  tools_note?: string;
}
interface ModelRuntime {
  id: string;
  name: string;
  owner: string;
  binary?: string;
  models_dir?: string;
  model_count?: number;
}
export interface Inventory {
  agents: AgentInstall[];
  ide_extensions: IdeExtension[];
  mcp_servers: McpServer[];
  model_runtimes: ModelRuntime[];
  enforcement_mode: string;
}

const FLAG_META: Record<string, { icon: React.ComponentType<{ className?: string }>; cls: string }> = {
  remote: { icon: Globe, cls: 'border-amber-500/30 text-amber-500' },
  'credentials in config': { icon: KeyRound, cls: 'border-red-500/30 text-red-500' },
  'unpinned package': { icon: PackageOpen, cls: 'border-amber-500/30 text-amber-500' },
};

function Tile({
  icon: Icon,
  label,
  value,
  note,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: number;
  note?: string;
}) {
  return (
    <div className="rounded-lg border bg-card p-3">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      {note && <div className="text-[11px] text-muted-foreground mt-0.5">{note}</div>}
    </div>
  );
}

function Section({
  title,
  count,
  children,
}: {
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border bg-card">
      <div className="flex items-center justify-between px-4 py-2.5 border-b">
        <h3 className="text-sm font-medium">{title}</h3>
        <span className="text-xs text-muted-foreground tabular-nums">{count}</span>
      </div>
      {count === 0 ? (
        <p className="px-4 py-3 text-xs text-muted-foreground">None found on this machine.</p>
      ) : (
        <div className="divide-y">{children}</div>
      )}
    </div>
  );
}

/** Variable NAMES passed to an MCP server (never values), collapsed to a count. */
function EnvKeys({ keys }: { keys: string[] }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="text-[11px] text-muted-foreground">
      <button onClick={() => setOpen((o) => !o)} className="hover:text-foreground underline-offset-2 hover:underline">
        {keys.length} environment variable{keys.length === 1 ? '' : 's'} {open ? '▴' : '▾'}
      </button>
      {open && <div className="mt-1 font-mono break-all">{keys.join(', ')}</div>}
    </div>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[11px] text-muted-foreground break-all">{children}</span>;
}

interface ManagedServer {
  id: string;
  name: string;
  agent: string;
  upstream: string;
  disabled_tools: string[];
  seen_tools: Record<string, string>;
}

/** The managed-server id when this server's address is Ring Zero's gateway. */
function managedId(url?: string): string | null {
  const m = url?.match(/^http:\/\/(?:127\.0\.0\.1|localhost):7700\/mcp\/([A-Za-z0-9_-]+)$/);
  return m ? m[1] : null;
}

/** One managed server's tools, each with an on/off switch (password-gated). */
function ManagedTools({ server, busy, onSwitch }: {
  server: ManagedServer;
  busy: string | null;
  onSwitch: (tool: string, on: boolean) => void;
}) {
  const names = [...new Set([...Object.keys(server.seen_tools ?? {}), ...(server.disabled_tools ?? [])])].sort();
  return (
    <div className="pt-1 space-y-1.5">
      <div className="text-[11px] text-muted-foreground">
        Goes through Ring Zero to <span className="font-mono">{server.upstream}</span>. The agent cannot reach it directly.
      </div>
      {names.length === 0 ? (
        <div className="text-[11px] text-muted-foreground">Its tools appear here once the server has listed them.</div>
      ) : (
        <div className="rounded-md border divide-y">
          {names.map((t) => {
            const on = !(server.disabled_tools ?? []).includes(t);
            const key = `${server.id}/${t}`;
            return (
              <div key={t} className="flex items-center justify-between gap-3 px-3 py-1.5">
                <div className="min-w-0">
                  <div className="font-mono text-[12px]">{t}</div>
                  {server.seen_tools?.[t] && (
                    <div className="text-[11px] text-muted-foreground truncate">{server.seen_tools[t]}</div>
                  )}
                </div>
                <button
                  role="switch"
                  aria-checked={on}
                  aria-label={`${t} ${on ? 'on' : 'off'}`}
                  disabled={busy === key}
                  onClick={() => onSwitch(t, !on)}
                  className={cn(
                    'shrink-0 rounded-full px-2.5 py-0.5 text-[11px] font-medium border transition-colors',
                    on ? 'bg-primary text-primary-foreground border-primary' : 'bg-muted text-muted-foreground',
                    busy === key && 'opacity-60',
                  )}
                >
                  {busy === key ? '…' : on ? 'On' : 'Off'}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function DiscoveryInventory() {
  const [gw, setGw] = useState<Record<string, ManagedServer>>({});
  const [held, setHeld] = useState<Record<string, { id: string; name: string; agent: string; upstream: string; first_seen: string }>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [inv, setInv] = useState<Inventory | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      setInv(await daemonApi<Inventory>('GET', '/api/v1/discovery/inventory'));
      try {
        const r = await daemonApi<{
          servers: Record<string, ManagedServer>;
          held?: Record<string, { id: string; name: string; agent: string; upstream: string; first_seen: string }>;
        }>('GET', '/api/v1/mcp/gateway');
        setGw(r?.servers ?? {});
        setHeld(r?.held ?? {});
      } catch {
        setGw({});
        setHeld({});
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not reach the daemon');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  // Each change asks for the administrator password, as every policy change does.
  const privileged = async (key: string, args: string[], done: string) => {
    setBusy(key);
    try {
      const r = await runPrivilegedSequence([args]);
      if (r.ok) {
        toast({ variant: 'success', title: 'Saved', description: done });
        await load();
      } else {
        const { title, description } = describeFailure(r);
        toast({ variant: 'error', title, description });
      }
    } finally {
      setBusy(null);
    }
  };
  const unmanagedRemote =
    inv?.mcp_servers.filter((m) => m.transport === 'http' && !managedId(m.url) && m.flags.includes('remote')).length ?? 0;

  const covered = inv?.agents.filter((a) => a.enforcement_covered).length ?? 0;
  const flaggedMcp = inv?.mcp_servers.filter((m) => m.flags.length > 0).length ?? 0;
  const modelCount = inv?.model_runtimes.reduce((n, r) => n + (r.model_count ?? 0), 0) ?? 0;

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">AI on this machine</h2>
          <p className="text-xs text-muted-foreground">
            Every AI agent, editor extension, MCP server and local model, for every user.
            {inv && (
              <>
                {' '}
                Enforcement mode:{' '}
                <span
                  className={cn(
                    'font-medium',
                    inv.enforcement_mode === 'enforce' ? 'text-emerald-500' : 'text-amber-500',
                  )}
                >
                  {inv.enforcement_mode}
                </span>
                .
              </>
            )}
          </p>
        </div>
        <Button size="sm" variant="outline" className="gap-2" onClick={load} disabled={loading}>
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          Refresh
        </Button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-500">
          {error}
        </div>
      )}

      {inv && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Tile
              icon={Bot}
              label="AI agents"
              value={inv.agents.length}
              note={`${covered} covered by enforcement`}
            />
            <Tile
              icon={Plug}
              label="MCP servers"
              value={inv.mcp_servers.length}
              note={flaggedMcp ? `${flaggedMcp} need review` : 'none flagged'}
            />
            <Tile icon={Puzzle} label="Editor AI extensions" value={inv.ide_extensions.length} />
            <Tile
              icon={Cpu}
              label="Local model runtimes"
              value={inv.model_runtimes.length}
              note={modelCount ? `${modelCount} models on disk` : undefined}
            />
          </div>

          <Section title="AI agents" count={inv.agents.length}>
            {inv.agents.map((a) => (
              <div key={`${a.id}-${a.owner}`} className="flex items-start justify-between gap-4 px-4 py-2.5">
                <div className="min-w-0">
                  <div className="text-sm font-medium">
                    {a.name} <span className="text-xs text-muted-foreground font-normal">· {a.owner}</span>
                  </div>
                  <Mono>{a.binary ?? a.config_dir}</Mono>
                </div>
                {a.enforcement_covered ? (
                  <Badge variant="outline" className="shrink-0 gap-1 border-emerald-500/30 text-emerald-500">
                    <ShieldCheck className="h-3 w-3" /> Protected
                  </Badge>
                ) : (
                  <Badge variant="outline" className="shrink-0 gap-1 border-amber-500/30 text-amber-500">
                    <ShieldOff className="h-3 w-3" /> Not covered
                  </Badge>
                )}
              </div>
            ))}
          </Section>

          {unmanagedRemote > 0 && (
            <div className="flex items-center justify-between gap-4 rounded-lg border bg-card px-4 py-3">
              <div className="text-xs text-muted-foreground">
                {unmanagedRemote} remote MCP server{unmanagedRemote === 1 ? '' : 's'} not managed. Route them through Ring
                Zero to switch individual tools on and off; agents then cannot reach them directly.
              </div>
              <Button
                size="sm"
                disabled={busy === 'adopt'}
                onClick={() =>
                  privileged('adopt', ['mcp', 'adopt'], 'Remote MCP servers now go through Ring Zero. Restart running agents.')
                }
              >
                <ShieldHalf className="h-3.5 w-3.5 mr-1" />
                {busy === 'adopt' ? 'Working…' : 'Manage through Ring Zero'}
              </Button>
            </div>
          )}
          <Section title="MCP servers" count={inv.mcp_servers.length}>
            {inv.mcp_servers.map((m) => (
              <div key={`${m.agent}-${m.owner}-${m.scope}-${m.name}`} className="px-4 py-2.5 space-y-1">
                <div className="flex items-start justify-between gap-4">
                  <div className="text-sm font-medium">
                    {m.name}{' '}
                    <span className="text-xs text-muted-foreground font-normal">
                      · {m.agent} · {m.scope === 'user' ? 'all projects' : m.scope.replace('project:', 'project ')} ·{' '}
                      {m.transport}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1 justify-end">
                    {m.flags.map((f) => {
                      const meta = FLAG_META[f];
                      const Icon = meta?.icon;
                      return (
                        <Badge key={f} variant="outline" className={cn('gap-1 text-[10px]', meta?.cls)}>
                          {Icon && <Icon className="h-3 w-3" />}
                          {f}
                        </Badge>
                      );
                    })}
                  </div>
                </div>
                <Mono>{m.url ?? m.command}</Mono>
                {m.env_keys.length > 0 && <EnvKeys keys={m.env_keys} />}
                {m.tools && (
                  <div className="pt-1">
                    <div className="text-[11px] text-muted-foreground mb-1">
                      {m.tools.length} tool{m.tools.length === 1 ? '' : 's'} offered, as the server lists them
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {m.tools.map((t) => (
                        <span
                          key={t.name}
                          title={t.description}
                          className="font-mono text-[11px] rounded border bg-muted/40 px-1.5 py-0.5"
                        >
                          {t.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {(() => {
                  const id = managedId(m.url);
                  const s = id ? gw[id] : undefined;
                  const h = Object.values(held).find((x) => x.name === m.name && x.agent === m.agent && x.upstream === m.url);
                  if (h) {
                    return (
                      <div className="flex items-center justify-between gap-3 rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2">
                        <div className="text-[11px]">
                          <span className="font-medium text-amber-700">Held, waiting for approval.</span>{' '}
                          <span className="text-muted-foreground">
                            Added to {m.agent}'s config after Ring Zero started managing MCP. No agent can reach it until
                            you approve it; approving routes it through Ring Zero with per-tool switches.
                          </span>
                        </div>
                        <Button
                          size="sm"
                          disabled={busy === 'adopt'}
                          onClick={() =>
                            privileged('adopt', ['mcp', 'adopt'], `${m.name} now goes through Ring Zero. Restart the agent.`)
                          }
                        >
                          {busy === 'adopt' ? 'Working…' : 'Approve'}
                        </Button>
                      </div>
                    );
                  }
                  if (s) {
                    return (
                      <>
                        <Badge variant="outline" className="gap-1 text-[10px] border-emerald-500/30 text-emerald-600">
                          <ShieldCheck className="h-3 w-3" /> Managed by Ring Zero
                        </Badge>
                        <ManagedTools
                          server={s}
                          busy={busy}
                          onSwitch={(tool, on) =>
                            privileged(
                              `${s.id}/${tool}`,
                              ['mcp', 'tool', s.id, tool, on ? 'on' : 'off'],
                              `${tool} is now ${on ? 'on' : 'off'} for ${s.name}.`,
                            )
                          }
                        />
                      </>
                    );
                  }
                  return !m.tools && m.tools_note ? (
                    <div className="text-[11px] text-muted-foreground">{m.tools_note}</div>
                  ) : null;
                })()}
              </div>
            ))}
          </Section>

          <div className="grid md:grid-cols-2 gap-4">
            <Section title="Editor AI extensions" count={inv.ide_extensions.length}>
              {inv.ide_extensions.map((e) => (
                <div key={e.path} className="px-4 py-2.5">
                  <div className="text-sm font-medium">
                    {e.name} <span className="text-xs text-muted-foreground font-normal">{e.version}</span>
                  </div>
                  <div className="text-[11px] text-muted-foreground">
                    {e.editor} · {e.owner}
                  </div>
                </div>
              ))}
            </Section>

            <Section title="Local model runtimes" count={inv.model_runtimes.length}>
              {inv.model_runtimes.map((r) => (
                <div key={`${r.id}-${r.owner}`} className="px-4 py-2.5">
                  <div className="text-sm font-medium">
                    {r.name}{' '}
                    {r.model_count !== undefined && (
                      <span className="text-xs text-muted-foreground font-normal">
                        {r.model_count} model{r.model_count === 1 ? '' : 's'}
                      </span>
                    )}
                  </div>
                  <Mono>{r.binary ?? r.models_dir}</Mono>
                </div>
              ))}
            </Section>
          </div>
        </>
      )}
    </div>
  );
}
