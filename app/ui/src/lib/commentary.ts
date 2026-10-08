// SPDX-License-Identifier: Apache-2.0
// commentary.ts — live commentary: fetch lines from the daemon, keep the
// latest few for captions, and speak them.
//
// Speaking rules, so the voice stays listenable on a busy agent:
//   alert  — always spoken, cuts off whatever is playing
//   notice — always spoken, after what is playing
//   info   — spoken only if nothing was said in the last few seconds;
//            otherwise it is shown as a caption and not spoken

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

const isTauri = !!(window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
const INFO_GAP_MS = 3500;

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
  voice: boolean;
  engine: 'kokoro' | 'piper' | 'espeak' | 'browser' | 'none' | 'unknown';
  lines: CommentaryLine[];
  setEnabled: (v: boolean) => void;
  setVoice: (v: boolean) => void;
}

export const useCommentary = create<CommentaryState>((set, get) => ({
  enabled: load('rz_commentary', false),
  voice: load('rz_commentary_voice', true),
  engine: 'unknown',
  lines: [],
  setEnabled: (v) => {
    save('rz_commentary', v);
    set({ enabled: v, lines: v ? get().lines : [] });
    if (!v) void stopSpeaking();
  },
  setVoice: (v) => {
    save('rz_commentary_voice', v);
    set({ voice: v });
    if (!v) void stopSpeaking();
  },
}));

let lastSpokenAt = 0;

async function speak(line: CommentaryLine) {
  const { voice } = useCommentary.getState();
  if (!voice) return;
  const now = Date.now();
  if (line.level === 'info' && now - lastSpokenAt < INFO_GAP_MS) return;
  lastSpokenAt = now;
  const interrupt = line.level === 'alert';
  if (isTauri) {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const engine = await invoke<string>('speak_line', { text: line.text, interrupt });
      useCommentary.setState({ engine: engine as CommentaryState['engine'] });
    } catch {
      useCommentary.setState({ engine: 'none' });
    }
    return;
  }
  // Browser preview: the browser's own voice.
  if ('speechSynthesis' in window) {
    if (interrupt) window.speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(line.text);
    u.rate = 1.05;
    window.speechSynthesis.speak(u);
    useCommentary.setState({ engine: 'browser' });
  }
}

async function stopSpeaking() {
  if (isTauri) {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('voice_stop');
    } catch {
      /* nothing playing */
    }
  } else if ('speechSynthesis' in window) {
    window.speechSynthesis.cancel();
  }
}

/** Run the fetch loop while commentary is on. Call once from App. */
export function startCommentaryLoop(): () => void {
  let stopped = false;
  let after = -1;

  const run = async () => {
    if (isTauri) {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        useCommentary.setState({ engine: (await invoke<string>('voice_engine')) as CommentaryState['engine'] });
      } catch {
        /* older backend */
      }
    } else if ('speechSynthesis' in window) {
      useCommentary.setState({ engine: 'browser' });
    }
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
          // When several arrive at once, speak alerts first, then the newest.
          const alerts = r.lines.filter((l) => l.level === 'alert');
          const rest = r.lines.filter((l) => l.level !== 'alert');
          for (const l of [...alerts, ...rest]) await speak(l);
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
