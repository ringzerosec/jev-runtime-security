// SPDX-License-Identifier: Apache-2.0
// LiveCommentary.tsx — live commentary captions, and the switch for them.

import { useEffect, useState } from 'react';
import { useCommentary, type CommentaryLine } from '../lib/commentary';
import { cn } from '../lib/utils';
import { ShieldAlert, Eye, Sparkles, Radio } from 'lucide-react';

const HIDE_AFTER_MS = 9000;

function LineView({ line, faded }: { line: CommentaryLine; faded?: boolean }) {
  const Icon = line.level === 'alert' ? ShieldAlert : line.level === 'notice' ? Eye : Sparkles;
  return (
    <div
      className={cn(
        'flex items-start gap-3 transition-opacity',
        faded ? 'opacity-45 text-sm' : 'text-base',
      )}
    >
      <div
        className={cn(
          'mt-0.5 rounded-lg p-1.5 shrink-0',
          line.level === 'alert' && 'bg-red-500/15 text-red-600',
          line.level === 'notice' && 'bg-amber-500/15 text-amber-600',
          line.level === 'info' && 'bg-primary/10 text-primary',
        )}
      >
        <Icon className={faded ? 'h-3.5 w-3.5' : 'h-4 w-4'} />
      </div>
      <div className="min-w-0">
        {!faded && (
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{line.agent}</div>
        )}
        <div className={cn('leading-snug', line.level === 'alert' && !faded && 'font-semibold text-red-700')}>
          {line.text}
        </div>
      </div>
    </div>
  );
}

/** Captions, bottom of the main area, shown while commentary is on. */
export function CommentaryCaptions() {
  const { enabled, lines } = useCommentary();
  const [visible, setVisible] = useState(false);
  const last = lines[lines.length - 1];
  const prev = lines[lines.length - 2];

  useEffect(() => {
    if (!last) return;
    setVisible(true);
    const t = setTimeout(() => setVisible(false), last.level === 'alert' ? HIDE_AFTER_MS * 2 : HIDE_AFTER_MS);
    return () => clearTimeout(t);
  }, [last?.seq]);

  if (!enabled || !last) return null;
  return (
    <div
      aria-live="polite"
      className={cn(
        'pointer-events-none fixed bottom-6 left-[calc(50%+7rem)] -translate-x-1/2 z-40 w-[min(720px,calc(100vw-16rem))] transition-all duration-300',
        visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-2',
      )}
    >
      <div
        className={cn(
          'rounded-2xl border bg-card/95 backdrop-blur shadow-xl px-5 py-4 space-y-2.5',
          last.level === 'alert' && 'border-red-500/40 shadow-red-500/10',
        )}
      >
        {prev && <LineView line={prev} faded />}
        <LineView line={last} />
      </div>
    </div>
  );
}

/** The switch, for the bottom of the sidebar. */
export function CommentarySwitch() {
  const { enabled, setEnabled } = useCommentary();
  return (
    <div className="mx-3 mb-3 rounded-lg border bg-card px-3 py-2.5 space-y-1">
      <div className="flex items-center gap-2">
        <Radio className={cn('h-4 w-4', enabled ? 'text-red-500' : 'text-muted-foreground')} />
        <span className="text-sm font-medium flex-1">Live commentary</span>
        <button
          role="switch"
          aria-checked={enabled}
          aria-label="Live commentary"
          onClick={() => setEnabled(!enabled)}
          className={cn(
            'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
            enabled ? 'bg-primary' : 'bg-muted-foreground/30',
          )}
        >
          <span className={cn('inline-block h-4 w-4 rounded-full bg-white shadow transition-transform', enabled ? 'translate-x-4' : 'translate-x-0.5')} />
        </button>
      </div>
      {enabled && <div className="text-[11px] text-muted-foreground">Captions while agents work. Full story per session in Sessions.</div>}
    </div>
  );
}
