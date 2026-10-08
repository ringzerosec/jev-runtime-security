// SPDX-License-Identifier: Apache-2.0
// refusals.ts — what a recorded refusal means, in plain words.
//
// Everything here is read off the event itself: which agent, what it tried,
// and which control refused it. No scores, no generated analysis. The
// sentences match what live commentary says, so captions, notices and the
// Threats screen tell the same story.

export interface RefusalEvent {
  id: string;
  type: string;
  skill_name: string; // the process that made the call
  target: string;
  allowed: boolean;
  timestamp: string;
  reason?: string;
  parent_process?: string;
  category?: string;
  classified_by?: string;
}

const AGENTS: [RegExp, string][] = [
  [/^claude/i, 'Claude Code'],
  [/^codex/i, 'Codex'],
  [/^gemini/i, 'Gemini'],
  [/^(cursor|agent$)/i, 'Cursor'],
  [/^copilot/i, 'Copilot'],
  [/^opencode/i, 'opencode'],
  [/^aider/i, 'Aider'],
  [/^windsurf/i, 'Windsurf'],
  [/^devin/i, 'Devin'],
  [/^chatgpt/i, 'ChatGPT'],
];

function asAgent(name?: string): string | null {
  if (!name) return null;
  for (const [re, label] of AGENTS) if (re.test(name.trim())) return label;
  return null;
}

/** The agent this refusal belongs to (not the helper program that made the call). */
export function refusalAgent(e: RefusalEvent): string {
  return asAgent(e.skill_name) ?? asAgent(e.parent_process) ?? 'An agent';
}

const base = (p: string) => p.replace(/\/+$/, '').split('/').pop() ?? p;
const ADMIN = ['sudo', 'su', 'pkexec', 'doas', 'run0'];
const ESCAPE = ['systemd-run', 'at', 'batch', 'crontab'];
const OWN = /^(api-token|daemon\.toml|profiles\.json|settings\.json|file-access-rules\.json|ringzero.*)$/i;
const INSTRUCTIONS = /^(claude\.md|claude\.local\.md|agents\.md|gemini\.md|\.cursorrules|\.windsurfrules|skill\.md|\.mcp\.json|copilot-instructions\.md)$/i;

export interface Refusal {
  /** One sentence, the same one the commentary speaks. */
  sentence: string;
  /** The thing it tried to reach: a file, a program, a host. */
  what: string;
  /** Which control refused it, as named on the Policy screen. */
  control: string;
  /** Where to change that control, if it can be changed. */
  changeable: boolean;
}

export function describeRefusal(e: RefusalEvent): Refusal {
  const agent = refusalAgent(e);
  const t = e.target || '';
  const kind = (e.type || '').toLowerCase();
  const name = base(t);

  if (t.startsWith('TAMPER:')) {
    return {
      sentence: 'Something tried to stop or inspect Ring Zero Security itself. Refused.',
      what: t.replace('TAMPER:', '').replace(/_/g, ' '),
      control: 'Tamper protection',
      changeable: true,
    };
  }
  if (t.endsWith(':prompt-secret')) {
    return {
      sentence: `A prompt to ${agent} had a secret in it. It was not sent.`,
      what: 'secret in a prompt (masked in the record)',
      control: 'Secrets in prompts',
      changeable: true,
    };
  }
  if (kind.includes('exec') || kind.includes('process')) {
    const prog = name.split(/\s+/)[0];
    if (ADMIN.includes(prog))
      return { sentence: `${agent} tried to become an administrator with ${prog}. Refused.`, what: prog, control: 'Agent controls · admin tools', changeable: true };
    if (ESCAPE.includes(prog))
      return { sentence: `${agent} tried to start work outside its own process with ${prog}. Refused.`, what: prog, control: 'Agent controls · work outside the agent', changeable: true };
    return { sentence: `${agent} tried to run ${prog}, which isn't on its approved list. Blocked.`, what: prog, control: `${agent} · approved programs`, changeable: true };
  }
  if (kind.includes('network') || kind.includes('dns')) {
    const host = t.replace(/:\d+$/, '');
    return { sentence: `${agent} tried to connect to ${host}, which isn't approved. Blocked.`, what: t, control: `${agent} · approved hosts`, changeable: true };
  }
  const verb = kind.includes('create') ? 'create' : kind.includes('delete') ? 'delete' : kind.includes('rename') ? 'move' : kind.includes('write') ? 'change' : 'read';
  if (OWN.test(name))
    return { sentence: `${agent} tried to ${verb} Ring Zero Security's own settings. Refused.`, what: name, control: 'Self-protection (always on)', changeable: false };
  if (INSTRUCTIONS.test(name))
    return { sentence: `${agent} tried to ${verb} its own instructions in ${name}. Blocked.`, what: name, control: 'Agent controls · instruction files', changeable: true };
  const secret = /^id_(rsa|ed25519|ecdsa|dsa)|^\.env|^credentials$|^\.git-credentials$|^\.netrc$/i.test(name);
  return {
    sentence: secret
      ? `${agent} tried to ${verb} ${name.startsWith('.env') ? 'a .env file full of secrets' : name.startsWith('id_') ? 'your SSH key' : 'saved credentials'}. Blocked.`
      : `${agent} tried to ${verb} ${name}, which is protected. Blocked.`,
    what: name,
    control: secret ? 'Protected data · always protected' : 'Protected data',
    changeable: true,
  };
}
