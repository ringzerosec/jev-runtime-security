// SPDX-License-Identifier: Apache-2.0
//
// What this app is allowed to do.
//
// The installer leaves the operator a READ-ONLY API token on purpose: an AI
// agent runs as that same user, so a full-scope token sitting in their home
// would hand the agent the ability to turn enforcement off. Everything this app
// READS uses that token, and that has not changed.
//
// What changed is what happens when someone presses Save. The app does not hold
// a privileged token and never will; it runs the equivalent `rz` command
// through polkit, an administrator authenticates, and root applies it. So
// `readOnly` is no longer a reason to disable a control — see lib/privileged.ts.
// It still decides what the notice above a control says.
//
// `unreachable` is the one thing that does disable a control: with no daemon
// there is nothing to write to, and offering a button that cannot work is the
// behaviour we were trying to get rid of.
import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

const isTauri = !!(window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;

export type Scope = 'readonly' | 'full';

export interface TokenScope {
  /** Null while the answer is still in flight. */
  scope: Scope | null;
  /** True once we know the token cannot change anything. */
  readOnly: boolean;
  /** One line to show next to a disabled control. */
  reason: string;
  /** The daemon could not be reached; we assume read-only. */
  unreachable: boolean;
}

const FALLBACK_REASON =
  'Changing enforcement runs as root after an administrator authenticates. The same change by hand: sudo rz enforcement set-default <observe|alert|block>';

const Ctx = createContext<TokenScope>({
  scope: null,
  readOnly: true,
  reason: FALLBACK_REASON,
  unreachable: false,
});

export function TokenScopeProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<TokenScope>({
    // Assume read-only until told otherwise: enabling a control we then get a
    // 403 on is worse than starting disabled.
    scope: null,
    readOnly: true,
    reason: FALLBACK_REASON,
    unreachable: false,
  });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        let data: { scope?: string; unreachable?: boolean };
        if (isTauri) {
          const { invoke } = await import('@tauri-apps/api/core');
          data = await invoke('get_token_scope');
        } else {
          const res = await fetch('http://127.0.0.1:7700/api/v1/auth/scope');
          data = res.ok ? await res.json() : { scope: 'readonly', unreachable: true };
        }
        if (cancelled) return;
        const scope: Scope = data.scope === 'full' ? 'full' : 'readonly';
        setState({
          scope,
          readOnly: scope !== 'full',
          reason: FALLBACK_REASON,
          unreachable: !!data.unreachable,
        });
      } catch {
        if (!cancelled) {
          setState({
            scope: 'readonly',
            readOnly: true,
            reason: FALLBACK_REASON,
            unreachable: true,
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}

export function useTokenScope(): TokenScope {
  return useContext(Ctx);
}
