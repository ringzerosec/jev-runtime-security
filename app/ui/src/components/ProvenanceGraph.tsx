// SPDX-License-Identifier: Apache-2.0
// ProvenanceGraph.tsx — Force-directed provenance graph
// Shows kernel event flow as an interactive network graph

import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { cn } from '../lib/utils';
import { daemonFetch } from '../lib/daemonApi';
import {
  Activity,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Shield,
  Zap,
} from 'lucide-react';

// ── Types ─────────────────────────────────────────────────────────────────────

interface GNode {
  id: string;
  label: string;
  type: 'process' | 'file' | 'network';
  risk: 'safe' | 'warn' | 'danger';
  events: number;
  blocked: number;
}

interface GLink {
  source: string;
  target: string;
  allowed: boolean;
  count: number;
}

interface AttackChain {
  id: string;
  pattern_name: string;
  severity: string;
  mitre_id: string | null;
  session_id: string;
  matched_events: { process: string; target: string; activity: string }[];
}

// ── Colors ────────────────────────────────────────────────────────────────────

const COLORS = {
  safe: { fill: '#22c55e', ring: '#16a34a', bg: 'rgba(34,197,94,0.08)' },
  warn: { fill: '#f59e0b', ring: '#d97706', bg: 'rgba(245,158,11,0.08)' },
  danger: { fill: '#ef4444', ring: '#dc2626', bg: 'rgba(239,68,68,0.08)' },
  edge: { allowed: 'rgba(100,116,139,0.25)', blocked: 'rgba(239,68,68,0.6)' },
  process: '#6366f1',
  file: '#22c55e',
  network: '#f59e0b',
};

// ── Build graph from raw events ───────────────────────────────────────────────

function buildGraph(events: any[], chains: AttackChain[]): { nodes: GNode[]; links: GLink[] } {
  const nodeMap = new Map<string, GNode>();
  const linkMap = new Map<string, GLink>();

  const chainProcesses = new Set<string>();
  const chainTargets = new Set<string>();
  for (const c of chains) {
    for (const me of c.matched_events) {
      chainProcesses.add(me.process);
      chainTargets.add(me.target);
    }
  }

  for (const ev of events) {
    const process = ev.process || ev.skill_name || 'unknown';
    const target = ev.target || '';
    const kind = ev.kind || ev.type || '';
    const allowed = ev.allowed !== false;

    // Process node
    const procId = `p:${process}`;
    if (!nodeMap.has(procId)) {
      nodeMap.set(procId, {
        id: procId,
        label: process,
        type: 'process',
        risk: 'safe',
        events: 0,
        blocked: 0,
      });
    }
    const pn = nodeMap.get(procId)!;
    pn.events++;
    if (!allowed) pn.blocked++;
    if (chainProcesses.has(process) || pn.blocked > 0) pn.risk = 'danger';

    // Target node
    if (target) {
      const isNet =
        kind.toLowerCase().includes('network') ||
        kind.toLowerCase().includes('dns') ||
        target.match(/^\d+\.\d+\.\d+\.\d+/) ||
        target.includes(':');
      const tType = isNet ? ('network' as const) : ('file' as const);
      const tId = `${tType === 'network' ? 'n' : 'f'}:${target}`;

      if (!nodeMap.has(tId)) {
        const risk = chainTargets.has(target)
          ? ('danger' as const)
          : isNet
            ? ('warn' as const)
            : ('safe' as const);
        nodeMap.set(tId, { id: tId, label: target, type: tType, risk, events: 0, blocked: 0 });
      }
      const tn = nodeMap.get(tId)!;
      tn.events++;
      if (!allowed) {
        tn.blocked++;
        tn.risk = 'danger';
      }

      // Link
      const lk = `${procId}→${tId}`;
      if (!linkMap.has(lk)) {
        linkMap.set(lk, { source: procId, target: tId, allowed: true, count: 0 });
      }
      const link = linkMap.get(lk)!;
      link.count++;
      if (!allowed) link.allowed = false;
    }
  }

  return { nodes: Array.from(nodeMap.values()), links: Array.from(linkMap.values()) };
}

// ── Node renderer ─────────────────────────────────────────────────────────────

function drawNode(node: any, ctx: CanvasRenderingContext2D, globalScale: number) {
  const n = node as GNode & { x: number; y: number };
  const size = Math.max(6, Math.min(20, 4 + Math.sqrt(n.events) * 3));
  const fontSize = Math.max(8, 12 / globalScale);

  const palette =
    n.risk === 'danger' ? COLORS.danger : n.risk === 'warn' ? COLORS.warn : COLORS.safe;
  const typeColor =
    n.type === 'process' ? COLORS.process : n.type === 'network' ? COLORS.network : COLORS.file;

  // Glow for danger nodes
  if (n.risk === 'danger') {
    ctx.beginPath();
    ctx.arc(n.x, n.y, size + 6, 0, 2 * Math.PI);
    ctx.fillStyle = 'rgba(239,68,68,0.12)';
    ctx.fill();
  }

  // Outer ring
  ctx.beginPath();
  ctx.arc(n.x, n.y, size + 2, 0, 2 * Math.PI);
  ctx.strokeStyle = palette.ring;
  ctx.lineWidth = 1.5;
  ctx.stroke();

  // Fill
  ctx.beginPath();
  ctx.arc(n.x, n.y, size, 0, 2 * Math.PI);
  ctx.fillStyle = palette.bg;
  ctx.fill();

  // Inner dot (type color)
  ctx.beginPath();
  ctx.arc(n.x, n.y, size * 0.4, 0, 2 * Math.PI);
  ctx.fillStyle = typeColor;
  ctx.fill();

  // Event count badge
  if (n.events > 1) {
    const bx = n.x + size * 0.7;
    const by = n.y - size * 0.7;
    const br = Math.max(6, 4 + String(n.events).length * 2);
    ctx.beginPath();
    ctx.arc(bx, by, br, 0, 2 * Math.PI);
    ctx.fillStyle = palette.fill;
    ctx.fill();
    ctx.fillStyle = '#fff';
    ctx.font = `bold ${Math.max(6, 8 / Math.max(globalScale, 0.5))}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(String(n.events), bx, by);
  }

  // Label
  ctx.fillStyle = n.risk === 'danger' ? '#ef4444' : n.risk === 'warn' ? '#f59e0b' : '#94a3b8';
  ctx.font = `${fontSize}px monospace`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  const label = n.label.length > 24 ? '…' + n.label.slice(-22) : n.label;
  ctx.fillText(label, n.x, n.y + size + 4);
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ProvenanceGraph() {
  const [events, setEvents] = useState<any[]>([]);
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const graphRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 });

  const fetchData = useCallback(async () => {
    try {
      const [evResp, chResp] = await Promise.all([
        daemonFetch('http://127.0.0.1:7700/api/v1/events?limit=200'),
        daemonFetch('http://127.0.0.1:7700/api/v1/attack-chains'),
      ]);
      if (evResp.ok) {
        const raw = await evResp.json();
        const mapped = (Array.isArray(raw) ? raw : (raw.events ?? [])).map((e: any) => ({
          id: e.id,
          type: e.kind ?? e.type ?? 'unknown',
          process: e.process ?? e.skill_name ?? 'unknown',
          skill_name: e.process ?? e.skill_name ?? 'unknown',
          target: e.target,
          allowed: e.allowed,
          timestamp: e.timestamp,
          reason: e.reason,
        }));
        setEvents(mapped);
      }
      if (chResp.ok) setChains(await chResp.json());
    } catch {
      /* daemon offline */
    }
  }, []);

  useEffect(() => {
    fetchData();
    if (autoRefresh) {
      const iv = setInterval(fetchData, 5000);
      return () => clearInterval(iv);
    }
  }, [autoRefresh, fetchData]);

  // Track width only — height is fixed to prevent feedback loop
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) {
        setDimensions((prev) => ({ width: e.contentRect.width, height: prev.height }));
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Stabilize graph data — only create new object when content actually changes
  const prevKeyRef = useRef('');
  const stableGraphRef = useRef<{ nodes: GNode[]; links: GLink[] }>({ nodes: [], links: [] });
  const graphData = useMemo(() => {
    const built = buildGraph(events, chains);
    const key =
      built.nodes.map((n) => n.id + n.events + n.blocked).join(',') +
      '|' +
      built.links.map((l) => l.source + l.target + l.count).join(',');
    if (key !== prevKeyRef.current) {
      prevKeyRef.current = key;
      stableGraphRef.current = built;
    }
    return stableGraphRef.current;
  }, [events, chains]);

  const allowed = events.filter((e) => e.allowed !== false).length;
  const blocked = events.filter((e) => e.allowed === false).length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Activity className="h-5 w-5 text-primary" />
            Provenance Graph
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Live kernel event flow — processes, files, and network connections
          </p>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <CheckCircle className="h-3.5 w-3.5 text-green-400" />
            <span className="text-muted-foreground">Allowed</span>
            <span className="font-bold text-green-400">{allowed}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <XCircle className="h-3.5 w-3.5 text-red-400" />
            <span className="text-muted-foreground">Blocked</span>
            <span className="font-bold text-red-400">{blocked}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Activity className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="text-muted-foreground">Total</span>
            <span className="font-bold">{events.length}</span>
          </div>
          {chains.length > 0 && (
            <div className="flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
              <span className="text-muted-foreground">Chains</span>
              <span className="font-bold text-red-400">{chains.length}</span>
            </div>
          )}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={cn(
              'p-1.5 rounded-lg border transition-colors',
              autoRefresh
                ? 'bg-primary/10 border-primary/30 text-primary'
                : 'bg-muted/30 border-border text-muted-foreground',
            )}
            title={autoRefresh ? 'Auto-refresh on' : 'Auto-refresh off'}
          >
            <RefreshCw
              className={cn('h-3.5 w-3.5', autoRefresh && 'animate-spin')}
              style={autoRefresh ? { animationDuration: '3s' } : undefined}
            />
          </button>
        </div>
      </div>

      {/* Graph */}
      <div
        ref={containerRef}
        className="bg-card border border-border rounded-xl overflow-hidden"
        style={{ height: 500 }}
      >
        {graphData.nodes.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
            <Shield className="h-10 w-10 mb-3 opacity-30" />
            <p className="text-sm">No events yet</p>
            <p className="text-xs mt-1">
              Kernel events will appear here as they flow through the daemon
            </p>
          </div>
        ) : (
          <ForceGraph2D
            ref={graphRef}
            graphData={graphData}
            width={dimensions.width}
            height={dimensions.height}
            backgroundColor="transparent"
            nodeCanvasObject={drawNode}
            nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
              const size = Math.max(6, Math.min(20, 4 + Math.sqrt((node as GNode).events) * 3));
              ctx.beginPath();
              ctx.arc(node.x, node.y, size + 4, 0, 2 * Math.PI);
              ctx.fillStyle = color;
              ctx.fill();
            }}
            linkColor={(link: any) =>
              (link as GLink).allowed ? COLORS.edge.allowed : COLORS.edge.blocked
            }
            linkWidth={(link: any) => ((link as GLink).allowed ? 1 : 2.5)}
            linkCurvature={0.2}
            linkDirectionalParticles={(link: any) => ((link as GLink).allowed ? 0 : 2)}
            linkDirectionalParticleWidth={3}
            linkDirectionalParticleColor={() => '#ef4444'}
            linkLabel={(link: any) => {
              const l = link as GLink;
              return `${l.count} event${l.count > 1 ? 's' : ''} ${l.allowed ? '' : '(BLOCKED)'}`;
            }}
            nodeLabel={(node: any) => {
              const n = node as GNode;
              return `${n.label}\n${n.type} · ${n.events} events${n.blocked ? ` · ${n.blocked} blocked` : ''}`;
            }}
            d3AlphaDecay={0.05}
            d3VelocityDecay={0.4}
            cooldownTicks={50}
            warmupTicks={30}
            enableNodeDrag={true}
            enableZoomInteraction={true}
            enablePanInteraction={true}
          />
        )}

        {/* Legend */}
        <div className="border-t border-border px-4 py-2.5 flex items-center gap-5 text-[10px] text-muted-foreground">
          <span className="font-medium uppercase tracking-wider">Legend</span>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full" style={{ background: COLORS.process }} />
            Process
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full" style={{ background: COLORS.file }} />
            File
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full" style={{ background: COLORS.network }} />
            Network
          </div>
          <div className="w-px h-3 bg-border mx-1" />
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full border-2 border-green-500 bg-green-500/10" />
            Safe
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full border-2 border-amber-500 bg-amber-500/10" />
            Warning
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full border-2 border-red-500 bg-red-500/10" />
            Blocked
          </div>
        </div>
      </div>

      {/* Attack chains */}
      {chains.length > 0 && (
        <div className="space-y-2">
          <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
            Detected Attack Chains
          </p>
          {chains.map((chain) => {
            const isCritical = chain.severity === 'critical';
            return (
              <div
                key={chain.id}
                className={cn(
                  'flex items-start gap-3 px-3 py-2.5 rounded-lg border text-xs',
                  isCritical
                    ? 'bg-red-500/5 border-red-500/30'
                    : 'bg-amber-500/5 border-amber-500/30',
                )}
              >
                <Zap
                  className={cn(
                    'h-4 w-4 shrink-0 mt-0.5',
                    isCritical ? 'text-red-400' : 'text-amber-400',
                  )}
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold">{chain.pattern_name}</span>
                    <span
                      className={cn(
                        'px-1.5 py-0.5 rounded text-[9px] font-bold uppercase',
                        isCritical
                          ? 'bg-red-500/20 text-red-400'
                          : 'bg-amber-500/20 text-amber-400',
                      )}
                    >
                      {chain.severity}
                    </span>
                  </div>
                  {chain.mitre_id && (
                    <span className="text-muted-foreground font-mono">MITRE: {chain.mitre_id}</span>
                  )}
                  <div className="flex gap-1 mt-1 flex-wrap">
                    {chain.matched_events.map((me, i) => (
                      <span
                        key={i}
                        className="px-1.5 py-0.5 bg-muted/50 rounded text-[9px] font-mono"
                      >
                        {me.process} → {me.target}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
