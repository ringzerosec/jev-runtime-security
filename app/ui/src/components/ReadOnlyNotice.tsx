// SPDX-License-Identifier: Apache-2.0
//
// The line shown above controls that change enforcement.
//
// This app holds the read-only token, so it cannot write to the daemon itself.
// It does not hide the control for that reason any more: applying a change runs
// the equivalent `rz` command through polkit, an administrator authenticates,
// and root applies it. What this notice does is tell someone that before they
// press the button, and name the command for anyone who would rather type it.
import { useTokenScope } from '@/hooks/use-token-scope';

interface Props {
  /** The `sudo rz …` command that does this particular thing. */
  command?: string;
  className?: string;
}

export function ReadOnlyNotice({ command, className }: Props) {
  const { unreachable } = useTokenScope();

  return (
    <div
      className={`rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-900 dark:text-amber-200 ${className ?? ''}`}
      role="note"
    >
      {unreachable ? (
        <>The daemon is not reachable, so nothing here can be changed.</>
      ) : (
        <>
          Changing this needs an administrator. Saving will ask for a password,
          then apply the change as root
          {command ? (
            <>
              {' '}
              — the same thing as running{' '}
              <code className="font-mono font-medium text-amber-950 dark:text-amber-100">
                {command}
              </code>
            </>
          ) : (
            <> — the same thing as running the `rz` command with sudo</>
          )}
          .
        </>
      )}
    </div>
  );
}
