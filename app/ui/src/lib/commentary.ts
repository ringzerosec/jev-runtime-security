// SPDX-License-Identifier: Apache-2.0
// commentary.ts — live commentary as text: fetch lines from the daemon and
// keep the latest few for the captions. Each session's full commentary is on
// its Commentary tab in Sessions.

import { create } from 'zustand';
import { daemonApi } from './daemonApi';

export type Level = 'info' | 'notice' | 'alert';
export interface CommentaryLine {
  seq: number;
  at: string;
  level: Level;
  agent: string;
  kind: string;
  text: string;
}


function load(key: string, fallback: boolean): boolean {
  try {
    const v = localStorage.getItem(key);
    return v === null ? fallback : v === '1';
  } catch {
    return fallback;
  }
}
function save(key: string, v: boolean) {
  try {
    localStorage.setItem(key, v ? '1' : '0');
  } catch {
    /* per-viewer convenience only */
  }
}

interface CommentaryState {
  enabled: boolean;
  lines: CommentaryLine[];
  setEnabled: (v: boolean) => void;
}

export const useCommentary = create<CommentaryState>((set, get) => ({
  enabled: load('rz_commentary', false),
  lines: [],
  setEnabled: (v) => {
    save('rz_commentary', v);
    set({ enabled: v, lines: v ? get().lines : [] });
  },
}));

/** Run the fetch loop while commentary is on. Call once from App. */
export function startCommentaryLoop(): () => void {
  let stopped = false;
  let after = -1;

  const run = async () => {
    while (!stopped) {
      if (!useCommentary.getState().enabled) {
        after = -1;
        await new Promise((r) => setTimeout(r, 700));
        continue;
      }
      try {
        // Start from now: when switched on, history is not read out.
        if (after < 0) {
          const first = await daemonApi<{ last: number }>('GET', '/api/v1/commentary?after=0&wait=0');
          after = first.last;
          continue;
        }
        const r = await daemonApi<{ lines: CommentaryLine[]; last: number }>(
          'GET',
          `/api/v1/commentary?after=${after}&wait=5`,
        );
        // The daemon restarted and its numbering began again: start over.
        if (r.last < after) {
          after = 0;
          continue;
        }
        after = Math.max(after, r.last);
        if (r.lines.length && useCommentary.getState().enabled) {
          useCommentary.setState((s) => ({ lines: [...s.lines, ...r.lines].slice(-6) }));
        }
      } catch {
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
  };
  void run();
  return () => {
    stopped = true;
  };
}
