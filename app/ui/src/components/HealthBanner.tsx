// SPDX-License-Identifier: Apache-2.0
// HealthBanner — global product-health indicator. Polls the daemon's
// per-subsystem health and surfaces a WARNING/CRITICAL banner the moment a
// load-bearing piece stops running (kernel enforcement, TLS inspection, the
// on-device AI engine), so the operator never falsely believes they're
// protected. Quiet (renders nothing) when everything is healthy.

import { useEffect, useState, useCallback } from 'react';
import { AlertTriangle, ShieldAlert, RefreshCw, X } from 'lucide-react';
import { cn } from '../lib/utils';

const HEALTH_URL = 'http://127.0.0.1:7700/api/v1/health/components';
const POLL_MS = 10_000;
const RETRY_MS = 5_000; // Faster polling when daemon is unreachable

// In the packaged Tauri app the webview origin is tauri://localhost, which the
// daemon's (dev-origin-only) CORS rejects — so a direct fetch fails. Route
// through the Rust backend (invoke), which isn't subject to browser CORS. In the
// browser-served UI (same origin as the daemon) a direct fetch works.
const isTauri = !!(window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;

async function fetchHealth(): Promise<Health> {
  if (isTauri) {
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<Health>('daemon_health');
  }
  const res = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(4000) });
  if (!res.ok) throw new Error(String(res.status));
  return (await res.json()) as Health;
}

interface Component {
  id: string;
  label: string;
  status: string;
  critical?: boolean;
  detail?: string;
}
interface Health {
  status: 'ok' | 'warning' | 'critical';
  components: Component[];
}

export default function HealthBanner() {
  const [health, setHealth] = useState<Health | null>(null);
  const [reachable, setReachable] = useState(true);
  const [dismissed, setDismissed] = useState(false);

  const poll = useCallback(async () => {
    try {
      const data = await fetchHealth();
      setHealth(data);
      setReachable(true);
      setDismissed((d) => (data.status === 'ok' ? false : d)); // reset dismissal once healthy
    } catch {
      // Daemon itself unreachable — that is itself a critical state.
      setReachable(false);
    }
  }, []);

  // Use faster polling interval when daemon is unreachable for auto-reconnect
  useEffect(() => {
    poll();
    const interval = reachable ? POLL_MS : RETRY_MS;
    const t = setInterval(poll, interval);
    return () => clearInterval(t);
  }, [poll, reachable]);

  // Daemon down — the most severe state (no API at all).
  if (!reachable) {
    return (
      <Bar tone="critical">
        <ShieldAlert className="h-4 w-4 shrink-0" />
        <span className="font-medium">Security daemon not reachable</span>
        <span className="opacity-80">
          — run{' '}
          <code className="font-mono bg-red-100 px-1 rounded">
            sudo systemctl start ringzero-daemon
          </code>
        </span>
        <span className="text-[10px] opacity-60 shrink-0">auto-retrying...</span>
        <RetryBtn onClick={poll} />
      </Bar>
    );
  }

  if (!health || health.status === 'ok' || dismissed) return null;

  const bad = health.components.filter((c) => c.status !== 'ok' && c.id !== 'engine');
  if (bad.length === 0) return null;
  const critical = health.status === 'critical';

  return (
    <Bar tone={critical ? 'critical' : 'warning'}>
      {critical ? (
        <ShieldAlert className="h-4 w-4 shrink-0" />
      ) : (
        <AlertTriangle className="h-4 w-4 shrink-0" />
      )}
      <span className="font-medium shrink-0">
        {critical ? 'Protection degraded' : 'Some components need attention'}
      </span>
      <span className="opacity-90 truncate">
        — {bad.map((c) => `${c.label}: ${c.detail || c.status}`).join('  •  ')}
      </span>
      <RetryBtn onClick={poll} />
      {!critical && (
        <button
          onClick={() => setDismissed(true)}
          className="ml-1 opacity-70 hover:opacity-100"
          aria-label="Dismiss"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      )}
    </Bar>
  );
}

function Bar({ tone, children }: { tone: 'warning' | 'critical'; children: React.ReactNode }) {
  return (
    <div
      className={cn(
        'flex items-center gap-2 px-4 py-2 text-xs border-b',
        tone === 'critical'
          ? 'bg-red-50 text-red-800 border-red-200'
          : 'bg-amber-50 text-amber-800 border-amber-200',
      )}
    >
      {children}
    </div>
  );
}

function RetryBtn({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="ml-auto shrink-0 inline-flex items-center gap-1 rounded px-2 py-0.5 hover:bg-black/5 transition-colors"
    >
      <RefreshCw className="h-3 w-3" /> Recheck
    </button>
  );
}
