// SPDX-License-Identifier: Apache-2.0
import { create } from 'zustand';
import { daemonFetch } from './lib/daemonApi';
import { toast } from './components/ui/toast';

// Detect Tauri vs browser environment
const isTauri = !!(window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;

// Unified invoke — lazily resolved for Tauri, direct fetch for browser
type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

// Browser-mode fetch adapter
function makeBrowserInvoke(): InvokeFn {
  const API = window.location.origin;
  return async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
    const routes: Record<string, { path: string; method?: string }> = {
      get_status: { path: '/api/v1/status' },
      get_skills: { path: '/api/v1/policy' },
      get_events: {
        path: `/api/v1/events?limit=${args?.limit ?? 100}${args?.kind ? `&kind=${args.kind}` : ''}`,
      },
      scan_skills_auto: { path: '/api/v1/skill-scan/auto', method: 'POST' },
      get_enforcement: { path: '/api/v1/enforcement' },
      update_enforcement: { path: '/api/v1/enforcement', method: 'POST' },
    };
    const route = routes[cmd];
    if (!route) return null as T;

    const resp = await fetch(`${API}${route.path}`, {
      method: route.method ?? 'GET',
      headers: route.method === 'POST' ? { 'Content-Type': 'application/json' } : undefined,
      body: route.method === 'POST' && args ? JSON.stringify(args) : undefined,
    });
    if (!resp.ok) throw new Error(`API error ${resp.status}`);
    const data = await resp.json();

    if (cmd === 'get_status') return data as T;
    if (cmd === 'get_skills') return (data.skills ?? []) as T;
    if (cmd === 'get_events') {
      // API returns SecurityEvent[] with 'kind'/'process' — map to UI Event format
      const raw = Array.isArray(data) ? data : (data.events ?? []);
      return raw.map((e: Record<string, unknown>) => ({
        id: e.id,
        type: e.kind ?? e.type ?? 'unknown',
        skill_name: e.process ?? e.skill_name ?? 'unknown',
        target: e.target,
        allowed: e.allowed,
        timestamp: e.timestamp,
        reason: e.reason,
        ppid: e.ppid,
        parent_process: e.parent_process,
        llm_context: e.llm_context,
      })) as T;
    }
    return data as T;
  };
}

// Lazy Tauri API loader — avoid top-level await
let _tauriInvoke: InvokeFn | null = null;

async function getTauriInvoke(): Promise<InvokeFn> {
  if (!_tauriInvoke) {
    const mod = await import('@tauri-apps/api/core');
    _tauriInvoke = mod.invoke;
  }
  return _tauriInvoke;
}

const browserInvoke = isTauri ? null : makeBrowserInvoke();

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (isTauri) {
    const fn = await getTauriInvoke();
    return fn<T>(cmd, args);
  }
  return browserInvoke!<T>(cmd, args);
}

interface Status {
  connected: boolean;
  version?: string;
  uptime?: number;
  threats_blocked?: number;
  skills_monitored?: number;
  ebpf_active?: boolean;
  kernel_monitoring?: string;
  enforce_mode?: boolean;
}

interface Skill {
  id: string;
  name: string;
  author: string;
  path: string;
  is_verified: boolean;
  last_scan: string;
  threat_level: string;
}

// ── Agent skill scan (auto-enumerated) ──────────────────────────────────────
export interface InjectionFinding {
  verdict: string;
  confidence: number;
  signals: string[];
  source: string;
  snippet: string;
}
export interface InjectionReport {
  path: string;
  clean: boolean;
  findings: InjectionFinding[];
}
export interface SupplyFinding {
  kind: string;
  detail: string;
  file: string;
}
export interface SupplyReport {
  path: string;
  risk_level: string;
  findings: SupplyFinding[];
}
export interface PatternFinding {
  rule_id: string;
  pattern_name: string;
  category: string;
  severity: string;
  confidence: number;
  message: string;
  file: string;
  start_line: number;
  matched_text?: string;
  explanation: string;
  remediation: string;
}
export interface SkillRootResult {
  agent: string;
  kind: string;
  path: string;
  owner: string;
  files_scanned: number;
  injection_reports: InjectionReport[];
  supply_findings: SupplyReport[];
  pattern_findings: PatternFinding[];
  risk: string;
}
export interface SkillScanResult {
  roots_found: number;
  files_scanned: number;
  results: SkillRootResult[];
  overall_risk: string;
}

interface LlmContext {
  provider: string;
  model?: string;
  response_text?: string;
  tool_call?: string;
  usage?: { input_tokens?: number; output_tokens?: number };
  response_ts: string;
}

interface Event {
  id: string;
  type: string;
  skill_name: string;
  target: string;
  allowed: boolean;
  timestamp: string;
  reason?: string;
  ppid?: number;
  parent_process?: string;
  llm_context?: LlmContext;
}

// ── Enforcement policy (per-category) ──────────────────────────────────────
export interface EnforcementCategories {
  credential_access: string;
  data_exfiltration: string;
  privilege_escalation: string;
  prompt_injection: string;
  supply_chain: string;
  excessive_agency: string;
  output_handling: string;
  memory_poisoning: string;
  tool_misuse: string;
  rogue_agent: string;
  system_prompt_leakage: string;
  mcp_tool_poisoning: string;
  harmful_content: string;
}

export interface EnforcementConfig {
  default_action: string;
  categories: EnforcementCategories;
}

interface Store {
  status: Status;
  skills: Skill[];
  events: Event[];
  daemonConnected: boolean;
  enforcement: EnforcementConfig | null;

  fetchStatus: () => Promise<void>;
  fetchSkills: () => Promise<void>;
  fetchEvents: () => Promise<void>;
  scanSkillsAuto: () => Promise<SkillScanResult>;
  setDaemonConnected: (connected: boolean) => void;
  initEventListener: () => void;
  fetchEnforcement: () => Promise<void>;
  updateEnforcement: (config: EnforcementConfig) => Promise<void>;
}

export const useStore = create<Store>((set, get) => ({
  status: { connected: false },
  skills: [],
  events: [],
  daemonConnected: false,
  enforcement: null,

  fetchStatus: async () => {
    try {
      const status = await invoke<Status>('get_status');
      // In browser mode, a successful fetch means the daemon is reachable
      const connected = isTauri ? (status.connected ?? true) : true;
      set({ status: { ...status, connected }, daemonConnected: connected });
    } catch (err) {
      console.error('[fetchStatus] error:', err);
      set({ daemonConnected: false });
      toast({
        variant: 'error',
        title: 'Daemon unreachable',
        description: 'Could not connect to ringzero-daemon',
      });
    }
  },

  fetchSkills: async () => {
    try {
      const skills = await invoke<Skill[]>('get_skills');
      set({ skills: Array.isArray(skills) ? skills.slice(0, 500) : [] });
    } catch (err) {
      console.error('Failed to fetch skills:', err);
    }
  },

  fetchEvents: async () => {
    try {
      const events = await invoke<Event[]>('get_events', { limit: 100 });
      set({ events });
    } catch (err) {
      console.error('Failed to fetch events:', err);
    }
  },

  scanSkillsAuto: async () => {
    const result = await invoke<SkillScanResult>('scan_skills_auto');
    // Normalise: the daemon returns snake_case JSON.
    return result ?? { roots_found: 0, files_scanned: 0, results: [], overall_risk: 'clean' };
  },

  setDaemonConnected: (connected: boolean) => {
    set({ daemonConnected: connected });
  },

  fetchEnforcement: async () => {
    try {
      const resp = await daemonFetch('/api/v1/enforcement');
      if (resp.ok) {
        const config = (await resp.json()) as EnforcementConfig;
        set({ enforcement: config });
      }
    } catch (err) {
      console.error('Failed to fetch enforcement config:', err);
    }
  },

  updateEnforcement: async (config: EnforcementConfig) => {
    const resp = await daemonFetch('/api/v1/enforcement', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    if (!resp.ok) throw new Error('Failed to save enforcement config');
    set({ enforcement: config });
  },

  initEventListener: () => {
    // In the Tauri app, App.tsx polls status/events every 10s through the
    // backend. In the browser-served UI (same origin as the daemon) poll a
    // little faster since there is no backend in between.
    if (!isTauri) {
      setInterval(async () => {
        try {
          await get().fetchStatus();
          await get().fetchEvents();
        } catch {
          /* ignore */
        }
      }, 5000);
    }
  },
}));
