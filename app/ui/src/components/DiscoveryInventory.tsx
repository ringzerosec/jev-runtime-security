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

export default function DiscoveryInventory() {
  const [inv, setInv] = useState<Inventory | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      setInv(await daemonApi<Inventory>('GET', '/api/v1/discovery/inventory'));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not reach the daemon');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

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
