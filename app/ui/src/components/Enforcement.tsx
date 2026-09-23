// SPDX-License-Identifier: Apache-2.0
import { useState, useEffect } from 'react';
import { useStore, type EnforcementConfig, type EnforcementCategories } from '../store';
import { Button } from './ui/button';
import { cn } from '../lib/utils';
import { toast } from './ui/toast';
import {
  KeyRound,
  Upload,
  ShieldAlert,
  MessageSquareWarning,
  Package,
  Maximize2,
  FileOutput,
  BrainCircuit,
  Wrench,
  Bot,
  Eye,
  Plug,
  AlertTriangle,
  Save,
} from 'lucide-react';
import { useTokenScope } from '@/hooks/use-token-scope';
import { ReadOnlyNotice } from '@/components/ReadOnlyNotice';
import { runPrivilegedSequence, describeFailure } from '@/lib/privileged';

// ── Category metadata ────────────────────────────────────────────────────────

interface CategoryMeta {
  key: keyof EnforcementCategories;
  name: string;
  patterns: string;
  description: string;
  icon: typeof KeyRound;
}

const CATEGORIES: CategoryMeta[] = [
  {
    key: 'credential_access',
    name: 'Credential Access',
    patterns: 'PE3, E2',
    description: 'Access to SSH keys, API tokens, cloud credentials',
    icon: KeyRound,
  },
  {
    key: 'data_exfiltration',
    name: 'Data Exfiltration',
    patterns: 'E1, E3, E4',
    description: 'Sending data to external/unauthorized endpoints',
    icon: Upload,
  },
  {
    key: 'privilege_escalation',
    name: 'Privilege Escalation',
    patterns: 'PE1, PE2',
    description: 'Sudo, root execution, permission bypass',
    icon: ShieldAlert,
  },
  {
    key: 'prompt_injection',
    name: 'Prompt Injection',
    patterns: 'P1\u2013P5',
    description: 'Instruction override, hidden commands',
    icon: MessageSquareWarning,
  },
  {
    key: 'supply_chain',
    name: 'Supply Chain',
    patterns: 'SC1\u2013SC6',
    description: 'Vulnerable deps, remote code execution',
    icon: Package,
  },
  {
    key: 'excessive_agency',
    name: 'Excessive Agency',
    patterns: 'EA1\u2013EA4',
    description: 'Unrestricted tool access, autonomous decisions',
    icon: Maximize2,
  },
  {
    key: 'output_handling',
    name: 'Output Handling',
    patterns: 'OH1\u2013OH3',
    description: 'Unvalidated output injection, cross-context',
    icon: FileOutput,
  },
  {
    key: 'memory_poisoning',
    name: 'Memory Poisoning',
    patterns: 'MP1\u2013MP3',
    description: 'Persistent context injection, memory manipulation',
    icon: BrainCircuit,
  },
  {
    key: 'tool_misuse',
    name: 'Tool Misuse',
    patterns: 'TM1\u2013TM3',
    description: 'Parameter abuse, chaining, unsafe defaults',
    icon: Wrench,
  },
  {
    key: 'rogue_agent',
    name: 'Rogue Agent',
    patterns: 'RA1, RA2',
    description: 'Self-modification, session persistence',
    icon: Bot,
  },
  {
    key: 'system_prompt_leakage',
    name: 'System Prompt Leakage',
    patterns: 'P6\u2013P8',
    description: 'Exposing system prompts or internal rules',
    icon: Eye,
  },
  {
    key: 'mcp_tool_poisoning',
    name: 'MCP Tool Poisoning',
    patterns: 'TP1\u2013TP3',
    description: 'Hidden instructions in MCP tool metadata',
    icon: Plug,
  },
  {
    key: 'harmful_content',
    name: 'Harmful Content',
    patterns: 'P5',
    description: 'Instructions that could cause harm',
    icon: AlertTriangle,
  },
];

type Action = 'observe' | 'alert' | 'block';

const ACTION_CONFIG: Record<
  Action,
  { label: string; hint: string; color: string; bg: string; ring: string }
> = {
  observe: {
    label: 'Observe',
    hint: 'Monitor only \u2014 log events',
    color: 'text-green-700',
    bg: 'bg-green-50',
    ring: 'ring-green-300',
  },
  alert: {
    label: 'Alert',
    hint: 'Alert in UI \u2014 flag for review',
    color: 'text-amber-700',
    bg: 'bg-amber-50',
    ring: 'ring-amber-300',
  },
  block: {
    label: 'Block',
    // NOT a kernel block. Nothing in the event pipeline reads this posture
    // today (agent/src/enforcement.rs::evaluate_event is unreferenced), so
    // this records an intent and refuses nothing. File-access rules are the
    // only setting the kernel enforces. Saying otherwise put a false claim on
    // a screenshot.
    hint: 'Record as a violation (not enforced — use File Access rules to block)',
    color: 'text-red-700',
    bg: 'bg-red-50',
    ring: 'ring-red-300',
  },
};

const DEFAULT_CATEGORIES: EnforcementCategories = {
  credential_access: 'observe',
  data_exfiltration: 'observe',
  privilege_escalation: 'observe',
  prompt_injection: 'observe',
  supply_chain: 'observe',
  excessive_agency: 'observe',
  output_handling: 'observe',
  memory_poisoning: 'observe',
  tool_misuse: 'observe',
  rogue_agent: 'observe',
  system_prompt_leakage: 'observe',
  mcp_tool_poisoning: 'observe',
  harmful_content: 'observe',
};

export default function Enforcement() {
  // A read-only token no longer means a control cannot be used: a write goes
  // through polkit. Only an unreachable daemon disables these.
  const { unreachable } = useTokenScope();
  // updateEnforcement is intentionally not used: this app has no token that can
  // write. Saving goes through polkit instead (see handleSave).
  const { enforcement, fetchEnforcement } = useStore();

  const [defaultAction, setDefaultAction] = useState<Action>('observe');
  const [categories, setCategories] = useState<EnforcementCategories>(DEFAULT_CATEGORIES);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);

  // Load enforcement config from daemon on mount
  useEffect(() => {
    fetchEnforcement();
  }, [fetchEnforcement]);

  // Sync local state when store updates
  useEffect(() => {
    if (enforcement) {
      setDefaultAction(enforcement.default_action as Action);
      setCategories(enforcement.categories);
      setDirty(false);
    }
  }, [enforcement]);

  const setCategoryAction = (key: keyof EnforcementCategories, action: Action) => {
    setCategories((prev) => ({ ...prev, [key]: action }));
    setDirty(true);
  };

  const changeDefault = (action: Action) => {
    setDefaultAction(action);
    // Apply default to all categories
    const updated = { ...categories };
    for (const key of Object.keys(updated) as (keyof EnforcementCategories)[]) {
      updated[key] = action;
    }
    setCategories(updated);
    setDirty(true);
  };

  // Saving runs the equivalent `rz` commands as root through polkit. This app
  // holds the read-only token on purpose, so it cannot write to the daemon
  // itself; an administrator authenticates once and the changes are applied by
  // root. Only what actually changed is sent, so an untouched category is never
  // rewritten.
  const handleSave = async () => {
    const changes: string[][] = [];
    if (!enforcement || enforcement.default_action !== defaultAction) {
      changes.push(['enforcement', 'set-default', defaultAction]);
    }
    const before = (enforcement?.categories ?? {}) as Record<string, string>;
    for (const [key, action] of Object.entries(categories) as [string, Action][]) {
      if (before[key] !== action) {
        changes.push(['enforcement', 'set-category', key, action]);
      }
    }

    if (changes.length === 0) {
      setDirty(false);
      toast({
        variant: 'info',
        title: 'Nothing to save',
        description: 'The policy on screen already matches the daemon.',
      });
      return;
    }

    setSaving(true);
    try {
      const result = await runPrivilegedSequence(changes);
      if (result.ok) {
        await fetchEnforcement();
        setDirty(false);
        toast({
          variant: 'success',
          title: 'Enforcement policy saved',
          description: `${result.applied} change${result.applied === 1 ? '' : 's'} applied as root. Reload the daemon to apply: sudo systemctl reload ringzero-daemon`,
        });
      } else {
        const { title, description } = describeFailure(result);
        toast({ variant: 'error', title, description });
        // Anything that did apply is real. Refetch so the screen shows the
        // daemon's actual state rather than a half-applied guess; if nothing
        // applied, the edits stay exactly as they were.
        if (result.applied > 0) await fetchEnforcement();
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Enforcement Policy</h2>
        <p className="text-muted-foreground">
          Configure how Ring Zero responds to each threat category
        </p>
      </div>

      <ReadOnlyNotice command="sudo rz enforcement set-default <observe|alert|block>" />

      {/* Default action selector */}
      <div className="rounded-lg border bg-card px-5 py-4">
        <p className="text-sm font-medium mb-1">Default Action</p>
        <p className="text-xs text-muted-foreground mb-3">
          Applies to all categories. Override individually below.
        </p>
        <div className="flex gap-2">
          {(Object.keys(ACTION_CONFIG) as Action[]).map((action) => {
            const cfg = ACTION_CONFIG[action];
            const active = defaultAction === action;
            return (
              <button
                key={action}
                onClick={() => changeDefault(action)}
                disabled={unreachable}
                className={cn(
                  'flex-1 px-4 py-2.5 rounded-md text-sm font-medium transition-all border',
                  active
                    ? `${cfg.bg} ${cfg.color} ring-2 ${cfg.ring} border-transparent`
                    : 'bg-card text-muted-foreground border-border hover:bg-muted/50',
                )}
              >
                {cfg.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Category grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {CATEGORIES.map((cat) => {
          const Icon = cat.icon;
          const currentAction = (categories[cat.key] || defaultAction) as Action;
          const cfg = ACTION_CONFIG[currentAction];
          return (
            <div key={cat.key} className="rounded-lg border bg-card px-4 py-3.5 space-y-2.5">
              {/* Category header */}
              <div className="flex items-start gap-3">
                <div className={cn('p-2 rounded-md', cfg.bg)}>
                  <Icon className={cn('h-4 w-4', cfg.color)} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium">{cat.name}</p>
                  <p className="text-[11px] text-muted-foreground">{cat.description}</p>
                  <span className="text-[10px] font-mono text-muted-foreground/70">
                    {cat.patterns}
                  </span>
                </div>
              </div>

              {/* Action toggle */}
              <div className="flex gap-1.5">
                {(Object.keys(ACTION_CONFIG) as Action[]).map((action) => {
                  const acfg = ACTION_CONFIG[action];
                  const isActive = currentAction === action;
                  return (
                    <button
                      key={action}
                      onClick={() => setCategoryAction(cat.key, action)}
                      disabled={unreachable}
                      className={cn(
                        'flex-1 px-2 py-1.5 rounded text-[11px] font-medium transition-all border',
                        isActive
                          ? `${acfg.bg} ${acfg.color} ring-1 ${acfg.ring} border-transparent`
                          : 'bg-transparent text-muted-foreground border-border/50 hover:bg-muted/30',
                      )}
                    >
                      {acfg.label}
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 text-[11px] text-muted-foreground px-1">
        {(Object.keys(ACTION_CONFIG) as Action[]).map((action) => {
          const cfg = ACTION_CONFIG[action];
          return (
            <div key={action} className="flex items-center gap-1.5">
              <span
                className={cn(
                  'w-2.5 h-2.5 rounded-full',
                  cfg.bg,
                  'border',
                  action === 'observe'
                    ? 'border-green-300'
                    : action === 'alert'
                      ? 'border-amber-300'
                      : 'border-red-300',
                )}
              />
              <span className={cfg.color}>{cfg.label}</span>
              <span> &mdash; {cfg.hint}</span>
            </div>
          );
        })}
      </div>

      {/* Save button */}
      <div className="flex justify-end">
        <Button
          onClick={handleSave}
          disabled={saving || !dirty || unreachable}
          title={unreachable ? 'The daemon is not reachable' : 'Applying this asks for an administrator password'}
          className="min-w-[140px]"
        >
          <Save className="h-4 w-4 mr-2" />
          {saving ? 'Saving...' : 'Save Policy'}
        </Button>
      </div>
    </div>
  );
}
