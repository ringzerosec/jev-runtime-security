// SPDX-License-Identifier: Apache-2.0
//
// How this UI changes something it is not allowed to change.
//
// The app holds the READ-ONLY API token, deliberately: an AI coding agent runs
// as the same user, so a full-scope token within that user's reach would let
// the agent turn enforcement off. A write therefore does not go through the
// app's token at all. It runs the equivalent `rz` command through `pkexec`,
// polkit authenticates an administrator, and the command runs as root.
//
// The property that buys us: an agent running as the developer cannot answer
// an authentication dialog, so it cannot make this change non-interactively. A
// human sitting at the machine can.
//
// In a browser tab (the daemon serves this same UI read-only on loopback) there
// is no way to ask for authentication, so every call here reports `unavailable`
// and the caller shows the command to run in a terminal instead.

const isTauri = !!(window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;

export type PrivilegedStatus = 'ok' | 'cancelled' | 'unavailable' | 'failed';

export interface PrivilegedResult {
  ok: boolean;
  status: PrivilegedStatus;
  /** Plain words for a toast. Never empty. */
  message: string;
  /** The same change as a command someone can run by hand. */
  command: string;
}

/** `sudo rz …`, for showing as the fallback when we cannot run it ourselves. */
export function asCommand(args: string[]): string {
  return `sudo rz ${args.join(' ')}`;
}

/**
 * Run one `rz` command as root, via polkit. Resolves for every outcome,
 * including cancellation: there is no path here that fails silently.
 */
export async function runPrivileged(args: string[]): Promise<PrivilegedResult> {
  if (!isTauri) {
    return {
      ok: false,
      status: 'unavailable',
      message:
        'This page is served read-only and cannot ask for authentication. Run the command in a terminal.',
      command: asCommand(args),
    };
  }
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<PrivilegedResult>('privileged_rz', { args });
  } catch (e) {
    return {
      ok: false,
      status: 'failed',
      message: e instanceof Error ? e.message : String(e),
      command: asCommand(args),
    };
  }
}

export interface SequenceResult {
  /** Every command ran and succeeded. */
  ok: boolean;
  /** How many were applied before we stopped. */
  applied: number;
  /** How many were asked for in total. */
  total: number;
  /** The outcome that stopped us, if one did. */
  stoppedBy?: PrivilegedResult;
}

/**
 * Run several changes in order, stopping at the first one that does not apply.
 *
 * Stopping is the point. Carrying on after a refused or cancelled prompt would
 * leave enforcement in a state nobody chose, and the caller can say exactly how
 * far it got. The polkit action is `auth_admin` with no "keep", so each command
 * prompts: a remembered answer would be a window an agent could reuse, which is
 * the same weakness as sudo's cached credentials. Several changes therefore
 * mean several prompts, deliberately.
 */
export async function runPrivilegedSequence(commands: string[][]): Promise<SequenceResult> {
  let applied = 0;
  for (const args of commands) {
    const r = await runPrivileged(args);
    if (!r.ok) {
      return { ok: false, applied, total: commands.length, stoppedBy: r };
    }
    applied += 1;
  }
  return { ok: true, applied, total: commands.length };
}

/**
 * One description of what happened, for a toast. Says how far it got and what
 * to do instead, and never pretends a cancelled prompt was a success.
 */
export function describeFailure(r: SequenceResult): { title: string; description: string } {
  const stopped = r.stoppedBy;
  const progress =
    r.applied > 0
      ? ` ${r.applied} of ${r.total} change${r.total === 1 ? '' : 's'} had already been applied and ${r.applied === 1 ? 'is' : 'are'} still in effect.`
      : ' Nothing was changed.';

  if (!stopped) {
    return { title: 'Not applied', description: `Something stopped the change.${progress}` };
  }
  switch (stopped.status) {
    case 'cancelled':
      return {
        title: 'Authentication cancelled',
        description: `Nothing further was changed.${progress}`,
      };
    case 'unavailable':
      return {
        title: 'Cannot change this from the app',
        description: `${stopped.message}${progress} Run: ${stopped.command}`,
      };
    default:
      return {
        title: 'Change failed',
        description: `${stopped.message}${progress} You can run it by hand: ${stopped.command}`,
      };
  }
}
