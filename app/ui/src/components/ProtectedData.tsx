// SPDX-License-Identifier: Apache-2.0
// ProtectedData.tsx — the files and folders no agent may touch.
//
// One list, one add field, one-click common protections, and ONE save that asks
// for the administrator password once. Saving uses exactly the same path as
// before: the changed rules become `rz file-access add/remove` commands that
// polkit runs as root (see lib/privileged.ts and src-tauri/src/privileged.rs).
// The app never writes rules itself.

import { useCallback, useEffect, useMemo, useState } from 'react';
import { daemonFetch } from '../lib/daemonApi';
import { runPrivilegedSequence, describeFailure } from '@/lib/privileged';
import { toast } from './ui/toast';
import { cn } from '../lib/utils';
import { File, Folder, Plus, Trash2, Undo2, Lock, KeyRound, FileCode, AlertTriangle, Loader2 } from 'lucide-react';

interface Rule {
  id: string;
  pattern: string;
  action: 'allow' | 'block';
  source: 'template' | 'custom';
  kind?: 'file' | 'dir';
  description?: string;
  status?: 'enforced' | 'unresolved';
  status_reason?: string;
}

// Common protections, offered as one-click adds. Same patterns the old
// templates used; each becomes an ordinary rule you can see and remove.
const COMMON: { label: string; icon: typeof KeyRound; items: { pattern: string; description: string }[] }[] = [
  {
    label: 'SSH keys',
    icon: KeyRound,
    items: [{ pattern: '~/.ssh/*', description: 'SSH keys' }],
  },
  {
    label: 'Cloud credentials',
    icon: KeyRound,
    items: [
      { pattern: '~/.aws/*', description: 'AWS credentials' },
      { pattern: '~/.kube/*', description: 'Kubernetes config' },
      { pattern: '.git-credentials', description: 'Git credentials' },
    ],
  },
  {
    label: '.env files',
    icon: FileCode,
    items: [
      { pattern: '.env', description: 'Env file' },
      { pattern: '.env.local', description: 'Local env' },
      { pattern: '.env.production', description: 'Production env' },
    ],
  },
];

const kindOf = (pattern: string): 'file' | 'dir' => (pattern.trim().endsWith('/*') ? 'dir' : 'file');
let tmpId = 1;
const newId = () => `new-${tmpId++}`;

export default function ProtectedData() {
  const [server, setServer] = useState<Rule[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [draft, setDraft] = useState('');
  const [draftKind, setDraftKind] = useState<'file' | 'dir'>('file');

  const load = useCallback(async () => {
    try {
      const res = await daemonFetch('http://127.0.0.1:7700/api/v1/file-access-rules');
      if (res.ok) {
        const data = await res.json();
        const loaded: Rule[] = (data.rules || []).filter((r: Rule) => r.action === 'block');
        setServer(loaded);
        setRules(loaded);
      }
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  // What would change on save.
  const changes = useMemo(() => {
    const serverIds = new Set(server.map((r) => r.id));
    const localIds = new Set(rules.map((r) => r.id));
    const removed = server.filter((r) => !localIds.has(r.id));
    const added = rules.filter((r) => !serverIds.has(r.id) && r.pattern.trim());
    return { removed, added, count: removed.length + added.length };
  }, [server, rules]);

  const has = (pattern: string) => rules.some((r) => r.pattern.trim() === pattern.trim());

  const add = (pattern: string, kind: 'file' | 'dir', description: string, source: Rule['source']) => {
    const p = pattern.trim();
    if (!p || has(p)) return;
    setRules((rs) => [...rs, { id: newId(), pattern: p, action: 'block', kind, description, source }]);
  };

  const addCommon = (group: (typeof COMMON)[number]) => {
    for (const it of group.items) add(it.pattern, kindOf(it.pattern), it.description, 'template');
  };

  const addDraft = () => {
    let p = draft.trim();
    if (!p) return;
    if (draftKind === 'dir' && !p.endsWith('/*')) p = p.replace(/\/+$/, '') + '/*';
    add(p, draftKind, '', 'custom');
    setDraft('');
  };

  const remove = (id: string) => setRules((rs) => rs.filter((r) => r.id !== id));
  const revert = () => setRules(server);

  const save = async () => {
    const commands: string[][] = [];
    for (const r of changes.removed) commands.push(['file-access', 'remove', r.id]);
    for (const r of changes.added) {
      const base = ['file-access', 'add', r.pattern, 'block', r.kind === 'dir' ? '--dir' : '--file'];
      commands.push(r.description ? [...base, '-d', r.description] : base);
    }
    if (commands.length === 0) return;
    setSaving(true);
    try {
      const result = await runPrivilegedSequence(commands);
      if (result.ok) {
        await load();
        toast({
          variant: 'success',
          title: 'Protection updated',
          description: `${result.applied} change${result.applied === 1 ? '' : 's'} applied and enforced by the kernel.`,
        });
      } else {
        const { title, description } = describeFailure(result);
        toast({ variant: 'error', title, description });
        if (result.applied > 0) await load();
      }
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <div className="rounded-xl border bg-card p-6 text-sm text-muted-foreground">Loading protected data…</div>;
  }

  return (
    <div className="rounded-xl border bg-card overflow-hidden">
      {/* Common protections */}
      <div className="px-5 py-4 border-b bg-muted/30">
        <div className="text-xs text-muted-foreground mb-2">Common protections</div>
        <div className="flex flex-wrap gap-2">
          {COMMON.map((g) => {
            const on = g.items.every((it) => has(it.pattern));
            const Icon = g.icon;
            return (
              <button
                key={g.label}
                onClick={() => addCommon(g)}
                disabled={on}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors',
                  on
                    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 cursor-default'
                    : 'bg-background hover:bg-muted',
                )}
              >
                <Icon className="h-3.5 w-3.5" />
                {g.label}
                {on ? <Lock className="h-3 w-3" /> : <Plus className="h-3 w-3" />}
              </button>
            );
          })}
        </div>
      </div>

      {/* The list */}
      {rules.length === 0 ? (
        <div className="px-5 py-6 text-sm text-muted-foreground">
          Nothing is protected yet. Add a common protection above, or a file or folder below.
        </div>
      ) : (
        <ul className="divide-y">
          {rules.map((r) => {
            const isNew = !server.some((s) => s.id === r.id);
            const dir = r.kind === 'dir' || kindOf(r.pattern) === 'dir';
            return (
              <li key={r.id} className={cn('flex items-center gap-3 px-5 py-3', isNew && 'bg-blue-500/5')}>
                {dir ? (
                  <Folder className="h-4 w-4 text-muted-foreground shrink-0" />
                ) : (
                  <File className="h-4 w-4 text-muted-foreground shrink-0" />
                )}
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-sm truncate">{r.pattern}</div>
                  <div className="text-xs text-muted-foreground">
                    {dir ? 'Folder and everything in it' : 'File, by name, anywhere'}
                    {r.description?.replace(/^\s*\[(dir-?block|block-?dir)\]\s*/i, '').trim()
                      ? ` · ${r.description.replace(/^\s*\[(dir-?block|block-?dir)\]\s*/i, '').trim()}`
                      : ''}
                  </div>
                </div>
                {isNew ? (
                  <span className="text-[11px] font-medium text-blue-600">Not saved</span>
                ) : r.status === 'unresolved' ? (
                  <span className="inline-flex items-center gap-1 text-[11px] font-medium text-amber-600" title={r.status_reason}>
                    <AlertTriangle className="h-3 w-3" /> Not found on disk
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-600">
                    <Lock className="h-3 w-3" /> Enforced
                  </span>
                )}
                <button
                  onClick={() => remove(r.id)}
                  className="p-1.5 rounded-md text-muted-foreground hover:text-red-600 hover:bg-red-500/10"
                  aria-label={`Remove protection for ${r.pattern}`}
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </li>
            );
          })}
        </ul>
      )}

      {/* Add */}
      <div className="px-5 py-3 border-t flex items-center gap-2">
        <div className="inline-flex rounded-md border p-0.5 text-xs">
          {(['file', 'dir'] as const).map((k) => (
            <button
              key={k}
              onClick={() => setDraftKind(k)}
              className={cn('px-2.5 py-1 rounded', draftKind === k ? 'bg-muted font-medium' : 'text-muted-foreground')}
            >
              {k === 'file' ? 'File' : 'Folder'}
            </button>
          ))}
        </div>
        <input
          id="protected-data-new"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && addDraft()}
          placeholder={draftKind === 'file' ? 'id_rsa  or  ~/.config/app/token' : '~/finance  or  ~/customer-data'}
          className="flex-1 rounded-md border bg-background px-3 py-1.5 text-sm font-mono outline-none focus:ring-2 focus:ring-primary/30"
        />
        <button
          onClick={addDraft}
          disabled={!draft.trim()}
          className="inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-40"
        >
          <Plus className="h-4 w-4" /> Add
        </button>
      </div>

      {/* Save bar — only when something changed */}
      {changes.count > 0 && (
        <div className="px-5 py-3 border-t bg-primary/5 flex items-center gap-3">
          <span className="text-sm">
            <span className="font-medium">
              {changes.count} change{changes.count === 1 ? '' : 's'}
            </span>{' '}
            <span className="text-muted-foreground">— saving asks for the administrator password.</span>
          </span>
          <div className="ml-auto flex gap-2">
            <button onClick={revert} disabled={saving} className="inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted">
              <Undo2 className="h-4 w-4" /> Undo
            </button>
            <button
              onClick={save}
              disabled={saving}
              className="inline-flex items-center gap-1.5 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-60"
            >
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
              Save and enforce
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
