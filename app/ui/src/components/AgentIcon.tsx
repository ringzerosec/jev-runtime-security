// SPDX-License-Identifier: Apache-2.0
import { Terminal } from 'lucide-react';

export type AgentName =
  | 'claude-code'
  | 'cursor'
  | 'github-copilot'
  | 'openclaw'
  | 'gemini'
  | 'windsurf'
  | 'devin'
  | 'codex'
  | 'unknown';

const AGENTS: Record<AgentName, { bg: string; svg: JSX.Element }> = {
  'claude-code': {
    bg: '#D97757',
    svg: (
      <>
        <path
          d="M10 28L20 12L30 28"
          stroke="white"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path d="M14 23H26" stroke="white" strokeWidth="2.5" strokeLinecap="round" />
      </>
    ),
  },
  cursor: {
    bg: '#000000',
    svg: (
      <>
        <path d="M20 8L32 20L20 32L8 20L20 8Z" fill="white" />
        <path d="M20 14L26 20L20 26L14 20L20 14Z" fill="#000" />
      </>
    ),
  },
  'github-copilot': {
    bg: '#24292F',
    svg: (
      <>
        <circle cx="15" cy="18" r="3" fill="white" />
        <circle cx="25" cy="18" r="3" fill="white" />
        <path
          d="M12 23C12 23 14 28 20 28C26 28 28 23 28 23"
          stroke="white"
          strokeWidth="2"
          strokeLinecap="round"
        />
        <path
          d="M13 13C13 13 16 10 20 10C24 10 27 13 27 13"
          stroke="white"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
      </>
    ),
  },
  openclaw: {
    bg: '#01696F',
    svg: (
      <>
        <path
          d="M20 10C14.5 10 10 14.5 10 20C10 25.5 14.5 30 20 30C25.5 30 30 25.5 30 20"
          stroke="white"
          strokeWidth="2.5"
          strokeLinecap="round"
        />
        <path
          d="M25 10L30 10L30 15"
          stroke="white"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path d="M30 10L22 18" stroke="white" strokeWidth="2.5" strokeLinecap="round" />
      </>
    ),
  },
  gemini: {
    bg: '#1A73E8',
    svg: (
      <>
        <path
          d="M20 8C20 8 14 14 14 20C14 26 20 32 20 32C20 32 26 26 26 20C26 14 20 8 20 8Z"
          fill="white"
        />
        <path
          d="M8 20C8 20 14 14 20 14C26 14 32 20 32 20C32 20 26 26 20 26C14 26 8 20 8 20Z"
          fill="white"
          fillOpacity="0.5"
        />
      </>
    ),
  },
  windsurf: {
    bg: '#7C3AED',
    svg: (
      <path
        d="M10 20C10 20 15 12 20 12C25 12 25 20 20 20C15 20 15 28 20 28C25 28 30 20 30 20"
        stroke="white"
        strokeWidth="2.5"
        strokeLinecap="round"
      />
    ),
  },
  devin: {
    bg: '#F97316',
    svg: (
      <>
        <rect x="11" y="11" width="18" height="18" rx="3" stroke="white" strokeWidth="2" />
        <circle cx="20" cy="20" r="4" fill="white" />
        <circle cx="20" cy="20" r="2" fill="#F97316" />
      </>
    ),
  },
  codex: {
    bg: '#10A37F',
    svg: (
      <>
        <path
          d="M15 15L10 20L15 25"
          stroke="white"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M25 15L30 20L25 25"
          stroke="white"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path d="M22 13L18 27" stroke="white" strokeWidth="2" strokeLinecap="round" />
      </>
    ),
  },
  unknown: {
    bg: '#6b7280',
    svg: <></>,
  },
};

/** Guess agent name from a process/skill name string */
export function guessAgent(name: string): AgentName {
  const n = (name || '').toLowerCase();
  if (n.includes('claude') || n.includes('anthropic')) return 'claude-code';
  if (n.includes('cursor')) return 'cursor';
  if (n.includes('copilot')) return 'github-copilot';
  if (n.includes('openclaw') || n.includes('ringzero') || n.includes('rz')) return 'openclaw';
  if (n.includes('gemini') || n.includes('google')) return 'gemini';
  if (n.includes('windsurf') || n.includes('codeium')) return 'windsurf';
  if (n.includes('devin') || n.includes('cognition')) return 'devin';
  if (n.includes('codex') || n.includes('openai')) return 'codex';
  return 'unknown';
}

interface AgentIconProps {
  agent: AgentName;
  className?: string;
}

export default function AgentIcon({ agent, className = 'w-6 h-6' }: AgentIconProps) {
  const def = AGENTS[agent];
  if (!def) return null;

  if (agent === 'unknown') {
    return (
      <div
        className={`${className} rounded flex items-center justify-center`}
        style={{ backgroundColor: def.bg }}
      >
        <Terminal className="w-3/5 h-3/5 text-white" />
      </div>
    );
  }

  return (
    <svg
      viewBox="0 0 40 40"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`${className} rounded`}
    >
      <rect width="40" height="40" rx="10" fill={def.bg} />
      {def.svg}
    </svg>
  );
}
