// SPDX-License-Identifier: Apache-2.0
import { useState, useCallback, useEffect } from 'react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Switch } from './ui/switch';
import { cn } from '../lib/utils';
import { toast } from './ui/toast';
import { daemonFetch } from '../lib/daemonApi';
import {
  KeyRound,
  FileCode,
  Lock,
  FolderOpen,
  Plus,
  Trash2,
  Save,
  Shield,
  ShieldCheck,
} from 'lucide-react';
import { useTokenScope } from '@/hooks/use-token-scope';
import { ReadOnlyNotice } from '@/components/ReadOnlyNotice';
import { runPrivilegedSequence, describeFailure } from '@/lib/privileged';

// ── Types ─────────────────────────────────────────────────────────────────────

interface FileAccessRule {
  id: string;
  pattern: string;
  action: 'allow' | 'block';
  source: 'template' | 'custom';
  /**
   * What the rule is about. A real field: this used to be decided by whether
   * the description happened to contain "[dir-block]", so a rule enforced or
   * did not depending on a human note, and a save that dropped the note
   * disarmed it silently.
   */
  kind?: 'file' | 'dir';
  description?: string;
  /** Read-only, from the daemon: is the kernel actually holding this rule? */
  status?: 'enforced' | 'unresolved';
  status_reason?: string;
}

// ── Templates ─────────────────────────────────────────────────────────────────

interface Template {
  id: string;
  name: string;
  description: string;
  icon: typeof KeyRound;
  patterns: { pattern: string; description: string }[];
}

const TEMPLATES: Template[] = [
  {
    id: 'credentials',
    name: 'Protect Credentials',
    description:
      'Block access to SSH keys, AWS credentials, Kubernetes configs, and git credentials',
    icon: KeyRound,
    patterns: [
      { pattern: '~/.ssh/*', description: 'SSH keys' },
      { pattern: '~/.aws/*', description: 'AWS credentials' },
      { pattern: '~/.kube/*', description: 'Kubernetes config' },
      { pattern: '.git-credentials', description: 'Git credentials' },
    ],
  },
  {
    id: 'environment',
    name: 'Protect Environment',
    description: 'Block access to environment files containing secrets and API keys',
    icon: FileCode,
    patterns: [
      { pattern: '.env*', description: 'Env files' },
      { pattern: '*.env', description: 'Env files (suffix)' },
      { pattern: '.env.local', description: 'Local env' },
      { pattern: '.env.production', description: 'Production env' },
    ],
  },
  // "Protect Keys" is gone, and this note is why.
  //
  // It offered *.pem, *.key, *.p12 and *.pfx. The kernel matches whole file
  // names, not extensions, so none of those four ever blocked anything: the
  // template switched on, the rules listed as BLOCK, and every key on the
  // machine stayed readable. The daemon now refuses a rule it cannot enforce,
  // so this template would fail on save instead of failing silently — which is
  // better, but still not a feature.
  //
  // What works today: name the file (a rule on `id_rsa` blocks that basename
  // anywhere), or block the directory the keys live in with a trailing /*.
  // "Protect Credentials" above already covers ~/.ssh, ~/.aws and ~/.kube that
  // way. Bringing this back means teaching the kernel side to match a suffix,
  // which is a change to the BPF programs and belongs in its own review.
  {
    id: 'blockdir',
    name: 'Block Directory',
    description: 'Block agent access to ALL files inside a specific folder',
    icon: FolderOpen,
    patterns: [{ pattern: '~/projects/*', description: 'Block: all files in directory' }],
  },
];

// ── Component ─────────────────────────────────────────────────────────────────

let nextRuleId = 1;
/**
 * What kind of rule a pattern describes.
 *
 * The same inference the daemon and the CLI make, in one place: a trailing `/*`
 * means the directory and everything under it. Getting this wrong is not
 * cosmetic — `~/.kube/*` sent as a file rule expands to no file name the kernel
 * can match, and the daemon refuses it.
 */
function kindFor(pattern: string): 'file' | 'dir' {
  return pattern.trim().endsWith('/*') ? 'dir' : 'file';
}

/** Does this rule belong to one of the templates above? */
function isTemplateRule(r: FileAccessRule): boolean {
  return r.source === 'template' || /^\[[\w-]+\]/.test(r.description ?? '');
}

function generateId(): string {
  return `rule-${Date.now()}-${nextRuleId++}`;
}

const READ_ONLY_HINT =
  'Read-only token. Change it with: sudo rz file-access add <path> block';

/**
 * What a rule is, and whether the kernel is actually holding it.
 *
 * `status` comes from the daemon and is the answer to "is anything enforcing
 * this right now". A stored rule the kernel holds nothing for — a directory
 * that does not exist yet, for instance — is legitimate and must never look
 * the same as a live one.
 */
function RuleState({ rule }: { rule: FileAccessRule }) {
  const kind = rule.kind ?? 'file';
  const unresolved = rule.status === 'unresolved';
  return (
    <div className="flex items-center gap-1.5 shrink-0">
      <span
        className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-mono uppercase"
        title={
          kind === 'dir'
            ? 'Blocks every file inside this directory'
            : 'Blocks this file name wherever it appears'
        }
      >
        {kind}
      </span>
      {unresolved && (
        <span
          className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 font-medium"
          title={rule.status_reason ?? 'The kernel is holding nothing for this rule'}
        >
          not enforcing
        </span>
      )}
    </div>
  );
}

export default function FileAccess() {
  const [rules, setRules] = useState<FileAccessRule[]>([]);
  // The daemon's copy, as last loaded. A save is the difference between this
  // and what is on screen, because the privileged path adds and removes rules
  // one at a time rather than replacing the whole list.
  const [serverRules, setServerRules] = useState<FileAccessRule[]>([]);
  const [enabledTemplates, setEnabledTemplates] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [workspacePath, setWorkspacePath] = useState('~/projects');

  // Load rules from daemon on mount
  useEffect(() => {
    (async () => {
      try {
        const res = await daemonFetch('http://127.0.0.1:7700/api/v1/file-access-rules');
        if (res.ok) {
          const data = await res.json();
          const loaded: FileAccessRule[] = data.rules || [];
          setServerRules(loaded);
          if (loaded.length > 0) {
            setRules(loaded);
            // Reconstruct enabled templates from loaded rules
            const templates = new Set<string>();
            for (const r of loaded) {
              if (isTemplateRule(r) && r.description) {
                // A directory rule is one whose kind says so. The old
                // "[dir-block]" note is still recognised so a machine upgraded
                // from an earlier release lights the same template back up.
                if (r.kind === 'dir' || r.description.includes('[dir-block]')) {
                  templates.add('blockdir');
                  // Extract the path from pattern (remove trailing /*)
                  const p = r.pattern.replace(/\/\*$/, '');
                  if (p) setWorkspacePath(p);
                } else {
                  const match = r.description.match(/^\[(\w+)\]/);
                  if (match) templates.add(match[1]);
                }
              }
            }
            setEnabledTemplates(templates);
          }
        }
      } catch {
        /* daemon may be offline */
      }
      setLoading(false);
    })();
  }, []);

  // Derived counts.
  //
  // A rule is a template rule if it carries a template tag in its description.
  // `source` alone is not enough: `rz file-access add` writes every rule as
  // "custom", so a rule that came back from a privileged save would otherwise
  // stop being recognised as part of the template that created it.
  const templateRules = rules.filter(isTemplateRule);
  const customRules = rules.filter((r) => !isTemplateRule(r));
  const blockedPaths = rules.filter((r) => r.action === 'block').length;

  // Toggle a template
  const toggleTemplate = useCallback(
    (template: Template) => {
      setEnabledTemplates((prev) => {
        const next = new Set(prev);
        if (next.has(template.id)) {
          // Disable — remove all rules from this template
          next.delete(template.id);
          setRules((r) =>
            r.filter(
              (rule) =>
                !(rule.source === 'template' && rule.description?.startsWith(`[${template.id}]`)),
            ),
          );
        } else {
          // Enable — add template rules
          next.add(template.id);
          const patterns =
            template.id === 'blockdir'
              ? [{ pattern: `${workspacePath}/*`, description: 'Block: all files in directory' }]
              : template.patterns;
          const newRules: FileAccessRule[] = patterns.map((p) => ({
            id: generateId(),
            pattern: p.pattern,
            action: 'block' as const,
            source: 'template' as const,
            // `kind` is what makes a directory block enforce. It used to be the
            // "[dir-block]" text in the description, which meant this template
            // produced a rule that listed as BLOCK and enforced nothing as soon
            // as anything dropped the note.
            //
            // Inferred from the pattern rather than from which template this
            // is: "Block Directory" is not the only template with a directory
            // pattern in it, and ~/.kube/* has no basename the kernel can match.
            kind: kindFor(p.pattern),
            description: `[${template.id}] ${p.description}`,
          }));
          setRules((r) => [...r, ...newRules]);
        }
        return next;
      });
    },
    [workspacePath],
  );

  // Add custom rule
  const addCustomRule = useCallback(() => {
    setRules((r) => [
      ...r,
      {
        id: generateId(),
        pattern: '',
        action: 'block',
        source: 'custom',
        kind: 'file',
      },
    ]);
  }, []);

  // Update custom rule pattern
  const updateRulePattern = useCallback((id: string, pattern: string) => {
    setRules((r) =>
      r.map((rule) =>
        rule.id === id
          ? {
              ...rule,
              pattern,
              kind: kindFor(pattern),
              // The daemon decides this; clear the stale answer while editing.
              status: undefined,
              status_reason: undefined,
            }
          : rule,
      ),
    );
  }, []);

  // A read-only token no longer means a control cannot be used: a write goes
  // through polkit and an administrator authenticates. Only an unreachable
  // daemon disables these, because then there is nothing to write to.
  const { unreachable } = useTokenScope();

  const toggleRuleAction = useCallback((id: string) => {
    setRules((r) =>
      r.map((rule) =>
        rule.id === id ? { ...rule, action: rule.action === 'block' ? 'allow' : 'block' } : rule,
      ),
    );
  }, []);

  // Delete rule
  const deleteRule = useCallback((id: string) => {
    setRules((r) => r.filter((rule) => rule.id !== id));
  }, []);

  /** Re-read the daemon's rules, so the screen shows what is actually enforced. */
  const refetch = useCallback(async () => {
    try {
      const res = await daemonFetch('http://127.0.0.1:7700/api/v1/file-access-rules');
      if (!res.ok) return;
      const data = await res.json();
      const loaded: FileAccessRule[] = data.rules || [];
      setServerRules(loaded);
      setRules(loaded);
    } catch {
      /* leave the screen alone if the daemon went away */
    }
  }, []);

  // Save runs `rz file-access add/remove` as root through polkit, one command
  // per change. The app holds the read-only token and cannot write to the
  // daemon itself; an administrator authenticates and root applies it.
  //
  // Removals go first so that a rule whose pattern or action changed is taken
  // out before its replacement goes in.
  const handleSave = useCallback(async () => {
    // The kind goes on the wire. Leaving the daemon to infer it would work for
    // a trailing /*, but a rule that says what it is cannot be disarmed by an
    // edit somewhere else.
    const argsFor = (r: FileAccessRule): string[] => {
      const kindFlag = r.kind === 'dir' ? '--dir' : '--file';
      const base = ['file-access', 'add', r.pattern.trim(), r.action, kindFlag];
      const description = r.description?.trim();
      return description ? [...base, '-d', description] : base;
    };

    const serverById = new Map(serverRules.map((r) => [r.id, r]));
    const localIds = new Set(rules.map((r) => r.id));
    const commands: string[][] = [];
    let emptyPatterns = 0;

    for (const s of serverRules) {
      if (!localIds.has(s.id)) commands.push(['file-access', 'remove', s.id]);
    }
    for (const r of rules) {
      if (!r.pattern.trim()) {
        emptyPatterns += 1;
        continue;
      }
      const before = serverById.get(r.id);
      if (!before) {
        commands.push(argsFor(r));
      } else if (
        before.pattern !== r.pattern ||
        before.action !== r.action ||
        (before.kind ?? 'file') !== (r.kind ?? 'file') ||
        (before.description ?? '') !== (r.description ?? '')
      ) {
        commands.push(['file-access', 'remove', before.id]);
        commands.push(argsFor(r));
      }
    }

    if (emptyPatterns > 0) {
      toast({
        variant: 'warning',
        title: `${emptyPatterns} rule${emptyPatterns === 1 ? '' : 's'} had no pattern`,
        description: 'Those were left out. Fill the pattern in or delete the row.',
      });
    }
    if (commands.length === 0) {
      toast({
        variant: 'info',
        title: 'Nothing to save',
        description: 'The rules on screen already match the daemon.',
      });
      return;
    }

    setSaving(true);
    try {
      const result = await runPrivilegedSequence(commands);
      if (result.ok) {
        await refetch();
        toast({
          variant: 'success',
          title: 'Rules enforced',
          description: `${result.applied} change${result.applied === 1 ? '' : 's'} applied as root and pushed to the kernel.`,
        });
      } else {
        const { title, description } = describeFailure(result);
        toast({ variant: 'error', title, description });
        if (result.applied > 0) await refetch();
      }
    } finally {
      setSaving(false);
    }
  }, [rules, serverRules, refetch]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-sm text-muted-foreground">Loading file access rules...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold text-foreground">File Access Control</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Control which files AI agents can access. Rules are enforced at the kernel level via eBPF.
        </p>
      </div>

      {/* Active rules summary */}
      <ReadOnlyNotice command="sudo rz file-access add <path> block" className="mb-3" />

      <div className="flex items-center gap-3 px-4 py-3 rounded-lg border bg-card">
        <ShieldCheck className="h-5 w-5 text-primary" />
        <span className="text-sm font-medium text-foreground">
          {blockedPaths} path{blockedPaths !== 1 ? 's' : ''} protected, {customRules.length} custom
          rule{customRules.length !== 1 ? 's' : ''} active
        </span>
        <div className="ml-auto">
          <Button
            size="sm"
            variant="default"
            className="text-xs h-8 px-4 rounded-full"
            onClick={handleSave}
            disabled={saving || unreachable}
            title={unreachable ? 'The daemon is not reachable' : 'Applying this asks for an administrator password'}
          >
            <Save className="h-3.5 w-3.5 mr-1.5" />
            {saving ? 'Saving...' : 'Save'}
          </Button>
        </div>
      </div>

      {/* Templates */}
      <div>
        <h2 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
          <Shield className="h-3.5 w-3.5" />
          Quick Templates
        </h2>
        <div className="grid grid-cols-2 gap-3">
          {TEMPLATES.map((template) => {
            const Icon = template.icon;
            const enabled = enabledTemplates.has(template.id);
            return (
              <div
                key={template.id}
                className={cn(
                  'rounded-lg border bg-card p-4 transition-colors',
                  enabled && 'border-primary/30 bg-primary/[0.02]',
                )}
              >
                <div className="flex items-start gap-3">
                  <div
                    className={cn(
                      'h-9 w-9 rounded-lg flex items-center justify-center shrink-0',
                      enabled ? 'bg-primary/10' : 'bg-muted',
                    )}
                  >
                    <Icon
                      className={cn('h-4 w-4', enabled ? 'text-primary' : 'text-muted-foreground')}
                    />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <p className="text-sm font-medium text-foreground">{template.name}</p>
                      <Switch
                        checked={enabled}
                        disabled={unreachable}
                        onCheckedChange={() => toggleTemplate(template)}
                        title={unreachable ? 'The daemon is not reachable' : undefined}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {template.description}
                    </p>
                    {enabled && template.id === 'blockdir' && (
                      <div className="mt-2">
                        <label className="text-[10px] text-muted-foreground mb-1 block">
                          Directory to block
                        </label>
                        <Input
                          disabled={unreachable}
                          title={unreachable ? 'The daemon is not reachable' : undefined}
                          value={workspacePath}
                          onChange={(e) => {
                            const newPath = e.target.value;
                            setWorkspacePath(newPath);
                            // Update existing blockdir rules to reflect new path
                            setRules((r) =>
                              r.map((rule) =>
                                rule.source === 'template' &&
                                rule.kind === 'dir' || rule.description?.includes('[dir-block]')
                                  ? { ...rule, pattern: `${newPath}/*`, kind: 'dir' as const }
                                  : rule,
                              ),
                            );
                          }}
                          placeholder="/home/user/my-project"
                          className="h-7 text-xs font-mono"
                        />
                      </div>
                    )}
                    {enabled && template.id !== 'blockdir' && (
                      <div className="flex flex-wrap gap-1.5 mt-2">
                        {template.patterns.map((p) => (
                          <span
                            key={p.pattern}
                            className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-mono"
                          >
                            {p.pattern}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Custom Rules */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xs font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
            <Lock className="h-3.5 w-3.5" />
            Custom Rules
          </h2>
          <Button
            size="sm"
            variant="outline"
            className="text-xs h-7 px-3 rounded-full"
            disabled={unreachable}
            title={unreachable ? 'The daemon is not reachable' : undefined}
            onClick={addCustomRule}
          >
            <Plus className="h-3 w-3 mr-1" />
            Add Rule
          </Button>
        </div>

        {customRules.length === 0 ? (
          <div className="rounded-lg border bg-card text-center py-10">
            <FolderOpen className="h-7 w-7 mx-auto mb-2 text-muted-foreground/30" />
            <p className="text-sm text-muted-foreground">No custom rules defined</p>
            <p className="text-xs text-muted-foreground/70 mt-0.5">
              Add rules to block or allow specific files or folders (use glob patterns like{' '}
              <code className="font-mono">~/.config/*</code>)
            </p>
          </div>
        ) : (
          <div className="rounded-lg border bg-card divide-y divide-border">
            {customRules.map((rule) => (
              <div key={rule.id} className="flex items-center gap-3 px-4 py-3">
                {/* Path pattern input */}
                <Input
                  value={rule.pattern}
                  disabled={unreachable}
                  title={unreachable ? 'The daemon is not reachable' : undefined}
                  onChange={(e) => updateRulePattern(rule.id, e.target.value)}
                  placeholder="e.g. ~/.config/secrets/*"
                  className="flex-1 h-8 text-xs font-mono"
                />

                {/* What it is, and whether the kernel is holding it. A rule
                    that reads BLOCK while enforcing nothing is the defect this
                    label exists to make impossible to miss. */}
                <RuleState rule={rule} />

                {/* Action toggle */}
                <button
                  disabled={unreachable}
                  title={unreachable ? 'The daemon is not reachable' : undefined}
                  onClick={() => toggleRuleAction(rule.id)}
                  className={cn(
                    'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold uppercase transition-colors border',
                    rule.action === 'block'
                      ? 'bg-red-50 text-red-700 border-red-200 hover:bg-red-100'
                      : 'bg-green-50 text-green-700 border-green-200 hover:bg-green-100',
                  )}
                >
                  <span
                    className={cn(
                      'w-1.5 h-1.5 rounded-full',
                      rule.action === 'block' ? 'bg-red-500' : 'bg-green-500',
                    )}
                  />
                  {rule.action}
                </button>

                {/* Delete */}
                <button
                  disabled={unreachable}
                  title={unreachable ? 'The daemon is not reachable' : undefined}
                  onClick={() => deleteRule(rule.id)}
                  className="p-1.5 rounded-md text-muted-foreground hover:text-red-600 hover:bg-red-50 transition-colors"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Template-derived rules (read-only view) */}
      {templateRules.length > 0 && (
        <div>
          <h2 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-3">
            Active Template Rules
          </h2>
          <div className="rounded-lg border bg-card divide-y divide-border">
            {templateRules.map((rule) => (
              <div key={rule.id} className="flex items-center gap-3 px-4 py-2.5 text-xs">
                <code className="font-mono text-[11px] text-foreground flex-1">{rule.pattern}</code>
                <span className="text-[10px] text-muted-foreground truncate w-32 text-right">
                  {rule.description?.replace(/^\[.*?\]\s*/, '') || ''}
                </span>
                <span
                  className={cn(
                    'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase',
                    rule.action === 'block'
                      ? 'bg-red-50 text-red-700'
                      : 'bg-green-50 text-green-700',
                  )}
                >
                  <span
                    className={cn(
                      'w-1.5 h-1.5 rounded-full',
                      rule.action === 'block' ? 'bg-red-500' : 'bg-green-500',
                    )}
                  />
                  {rule.action}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
