# policies — example policy files

A policy is `agent × verb × object × decision`, versioned, and it is the only
thing that decides what the kernel refuses. No model writes one; a model may
propose a stricter policy, never a looser one, and a human applies it.

`example.toml` is the shape the agent reads. The installed default lives at
`/etc/ringzero/daemon.toml`.

Remember what the kernel actually enforces in this release: file open, create,
delete and rename. An `exec` or `connect` rule is recorded, not refused.

## Authentication for changes made from the desktop app

The app holds the read-only token, so a change it makes runs through `pkexec`
and polkit asks an administrator to authenticate. The shipped action is
`auth_admin`: it asks every time, because `auth_admin_keep` remembers an answer
for a few minutes and that window is exactly when an agent is running beside
you.

`49-ringzero-relax-auth.rules` is a commented, optional override that switches
it to remember for the default retention window. It is not installed by the
package. Copy it into `/etc/polkit-1/rules.d/` and restart polkit if you want
it, and delete it to go back. Editing the installed action file works too, but
an upgrade overwrites it.
