// SPDX-License-Identifier: Apache-2.0
// Single path to the daemon's HTTP API that works in BOTH the packaged Tauri
// app and the browser-served UI.
//
// In the Tauri app the webview origin is tauri://localhost — the daemon's CORS
// rejects it, and the webview has no bearer token, so a direct fetch fails. We
// route through the Rust backend (invoke 'daemon_api'), which isn't subject to
// browser CORS and attaches the token. In the browser (UI served by the daemon,
// same origin) a direct fetch works.
const isTauri = !!(window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;

export async function daemonApi<T = unknown>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  if (isTauri) {
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<T>('daemon_api', { method, path, body: body ?? null });
  }
  const res = await fetch(`http://127.0.0.1:7700${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`daemon ${method} ${path} -> ${res.status}`);
  return (await res.json()) as T;
}

// Drop-in replacement for `fetch(`${DAEMON_API}/x`, opts)` against the daemon.
// Returns a minimal Response-like object so existing call sites (res.ok,
// res.json(), res.text()) keep working. In Tauri it routes through the backend
// (no CORS, tokened); in the browser it's a normal same-origin fetch.
interface DaemonResponse {
  ok: boolean;
  status: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json: () => Promise<any>;
  text: () => Promise<string>;
}

export async function daemonFetch(url: string, opts?: RequestInit): Promise<DaemonResponse> {
  if (!isTauri) {
    const r = await fetch(url, opts);
    return { ok: r.ok, status: r.status, json: () => r.json(), text: () => r.text() };
  }
  const path = url.replace(/^https?:\/\/127\.0\.0\.1:7700/, '');
  const method = (opts?.method ?? 'GET').toString();
  let body: unknown = null;
  if (opts?.body && typeof opts.body === 'string') {
    try {
      body = JSON.parse(opts.body);
    } catch {
      body = opts.body;
    }
  }
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    const data = await invoke<unknown>('daemon_api', { method, path, body });
    return {
      ok: true,
      status: 200,
      json: async () => data,
      text: async () => JSON.stringify(data),
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, status: 502, json: async () => ({ error: msg }), text: async () => msg };
  }
}
