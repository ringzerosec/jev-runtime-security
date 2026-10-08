// SPDX-License-Identifier: Apache-2.0
// BlockNotices.tsx — a quiet notice when Ring Zero Security refuses something.
//
// Replaces the old modal. It does not cover the screen, groups refusals that
// arrive together, says only what the record says (the agent, what it tried,
// the control that refused it, the category a classifier gave it), and offers
// only buttons that do something: open Threats, or open Policy to change the
// rule (which asks for the administrator password as usual).

import { useEffect, useState } from 'react';
import { cn } from '../lib/utils';
import { describeRefusal, refusalAgent, type RefusalEvent } from '../lib/refusals';
import { threatCategoryLabel } from '../lib/threatCategories';
import { useCommentary } from '../lib/commentary';
import { ShieldX, X, ChevronDown, ChevronRight } from 'lucide-react';

export interface NoticeGroup {
  key: string;
  agent: string;
  events: RefusalEvent[];
  last: number;
}

/** Fold new refusals into groups: same agent within a few seconds is one notice. */
export function addRefusals(groups: NoticeGroup[], fresh: RefusalEvent[]): NoticeGroup[] {
  const out = [...groups];
  for (const e of fresh) {
    const agent = refusalAgent(e);
    const at = Date.parse(e.timestamp) || Date.now();
    const g = out.find((x) => x.agent === agent && Math.abs(at - x.last) < 5000);
    if (g) {
      g.events = [...g.events, e];
      g.last = Math.max(g.last, at);
    } else {
      out.push({ key: e.id, agent, events: [e], last: at });
    }
  }
  return out.slice(-3);
}

const fmtTime = (ts: string) =>
  new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

function Notice({
  group,
  onDismiss,
  onView,
  onPolicy,
}: {
  group: NoticeGroup;
  onDismiss: () => void;
  onView: () => void;
  onPolicy: () => void;
}) {
  const [open, setOpen] = useState(false);
  const commentary = useCommentary((s) => s.enabled);
  const first = group.events[0];
  const r = describeRefusal(first);
  const n = group.events.length;
  const compact = commentary && !open;

  // Leave on screen long enough to read, then go; Threats keeps the record.
  useEffect(() => {
    const t = setTimeout(onDismiss, compact ? 12000 : 20000);
    return () => clearTimeout(t);
  }, [group.last, compact]);

  return (
    <div className="pointer-events-auto rounded-xl border border-red-500/30 bg-card shadow-lg overflow-hidden">
      <div className="flex items-start gap-3 px-4 py-3">
        <div className="rounded-lg bg-red-500/10 p-1.5 text-red-600 shrink-0">
          <ShieldX className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium leading-snug">{r.sentence}</div>
          {n > 1 && (
            <div className="text-xs text-muted-foreground mt-0.5">
              and {n - 1} more refusal{n > 2 ? 's' : ''} from {group.agent}
            </div>
          )}
          {!compact && (
            <dl className="mt-2 grid grid-cols-[72px_1fr] gap-x-2 gap-y-1 text-xs">
              <dt className="text-muted-foreground">Refused by</dt>
              <dd>{r.control}</dd>
              <dt className="text-muted-foreground">Target</dt>
              <dd className="font-mono break-all">{r.what}</dd>
              <dt className="text-muted-foreground">When</dt>
              <dd className="tabular-nums">{fmtTime(first.timestamp)}</dd>
              {first.category && (
                <>
                  <dt className="text-muted-foreground">Category</dt>
                  <dd>
                    {threatCategoryLabel(first.category)}
                    <span className="text-muted-foreground"> · labelled by built-in rules</span>
                  </dd>
                </>
              )}
            </dl>
          )}
        </div>
        <button onClick={onDismiss} aria-label="Dismiss" className="p-1 -m-1 rounded text-muted-foreground hover:bg-muted">
          <X className="h-4 w-4" />
        </button>
      </div>

      {n > 1 && !compact && (
        <div className="border-t px-4 py-2">
          <button onClick={() => setOpen((o) => !o)} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
            {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            All {n}
          </button>
          {open && (
            <ul className="mt-1.5 space-y-1 max-h-40 overflow-y-auto">
              {group.events.map((e) => (
                <li key={e.id} className="text-xs flex gap-2">
                  <span className="text-muted-foreground tabular-nums shrink-0">{fmtTime(e.timestamp)}</span>
                  <span>{describeRefusal(e).sentence}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className={cn('flex items-center gap-2 border-t px-4 py-2 bg-muted/30', compact && 'py-1.5')}>
        {compact && (
          <button onClick={() => setOpen(true)} className="text-xs text-muted-foreground hover:text-foreground mr-auto">
            Details
          </button>
        )}
        <div className="ml-auto flex gap-2">
          {r.changeable && (
            <button onClick={onPolicy} className="rounded-md px-2.5 py-1 text-xs hover:bg-muted">
              Change rule
            </button>
          )}
          <button onClick={onView} className="rounded-md bg-primary px-2.5 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90">
            View in Threats
          </button>
        </div>
      </div>
    </div>
  );
}

export default function BlockNotices({
  groups,
  onDismiss,
  onNavigate,
}: {
  groups: NoticeGroup[];
  onDismiss: (key: string) => void;
  onNavigate: (page: 'threats' | 'policy') => void;
}) {
  if (groups.length === 0) return null;
  return (
    <div className="pointer-events-none fixed top-4 right-4 z-50 flex w-[380px] max-w-[calc(100vw-2rem)] flex-col gap-2">
      {groups.map((g) => (
        <Notice
          key={g.key}
          group={g}
          onDismiss={() => onDismiss(g.key)}
          onView={() => {
            onDismiss(g.key);
            onNavigate('threats');
          }}
          onPolicy={() => {
            onDismiss(g.key);
            onNavigate('policy');
          }}
        />
      ))}
    </div>
  );
}
