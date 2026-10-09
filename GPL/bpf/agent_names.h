/* SPDX-License-Identifier: GPL-2.0 */
// agent_names.h — which process names are AI agents. Shared by ringzero.bpf.c
// and stdiocap.bpf.c so both objects agree on what an agent is.
#ifndef RZ_AGENT_NAMES_H
#define RZ_AGENT_NAMES_H

#ifndef MAX_COMM_LEN
#define MAX_COMM_LEN 16
#endif

// End of the first word of a comm: NUL or space.
#define RZ_WORD_END(c, i) ((c)[i] == '\0' || (c)[i] == ' ')

// Package managers. They are never an agent by their own name: npm sets its
// process name to its command line ("npm i openclaw@"), so the package being
// installed would otherwise make npm look like the agent it installs. A package
// manager an agent starts is still part of that agent's tree (inherited at fork).
static __always_inline int is_package_manager(const char *c) {
    // npm, npx
    if (c[0] == 'n' && c[1] == 'p' && (c[2] == 'm' || c[2] == 'x') && RZ_WORD_END(c, 3))
        return 1;
    // pnpm, pnpx
    if (c[0] == 'p' && c[1] == 'n' && c[2] == 'p' && (c[3] == 'm' || c[3] == 'x') && RZ_WORD_END(c, 4))
        return 1;
    // yarn
    if (c[0] == 'y' && c[1] == 'a' && c[2] == 'r' && c[3] == 'n' && RZ_WORD_END(c, 4))
        return 1;
    // bun, bunx
    if (c[0] == 'b' && c[1] == 'u' && c[2] == 'n' && (RZ_WORD_END(c, 3) || (c[3] == 'x' && RZ_WORD_END(c, 4))))
        return 1;
    // pip, pip3, pipx
    if (c[0] == 'p' && c[1] == 'i' && c[2] == 'p' &&
        (RZ_WORD_END(c, 3) || ((c[3] == '3' || c[3] == 'x') && RZ_WORD_END(c, 4))))
        return 1;
    // uv, uvx
    if (c[0] == 'u' && c[1] == 'v' && (RZ_WORD_END(c, 2) || (c[2] == 'x' && RZ_WORD_END(c, 3))))
        return 1;
    // poetry
    if (c[0] == 'p' && c[1] == 'o' && c[2] == 'e' && c[3] == 't' && c[4] == 'r' && c[5] == 'y' && RZ_WORD_END(c, 6))
        return 1;
    // cargo
    if (c[0] == 'c' && c[1] == 'a' && c[2] == 'r' && c[3] == 'g' && c[4] == 'o' && RZ_WORD_END(c, 5))
        return 1;
    // gem
    if (c[0] == 'g' && c[1] == 'e' && c[2] == 'm' && RZ_WORD_END(c, 3))
        return 1;
    return 0;
}

static __always_inline int is_ai_agent(const char *comm) {
    if (is_package_manager(comm))
        return 0;

    // Known AI agent process names

    // "claude" (matches claude, claude.real, claude-code, etc.)
    if (comm[0] == 'c' && comm[1] == 'l' && comm[2] == 'a' && comm[3] == 'u' && comm[4] == 'd' && comm[5] == 'e')
        return 1;

    // "cursor"
    if (comm[0] == 'c' && comm[1] == 'u' && comm[2] == 'r' && comm[3] == 's' && comm[4] == 'o' && comm[5] == 'r')
        return 1;

    // "copilot"
    if (comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'p' && comm[3] == 'i' && comm[4] == 'l' && comm[5] == 'o')
        return 1;

    // "codex"
    if (comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'e' && comm[4] == 'x')
        return 1;

    // "ChatGPT" — OpenAI ChatGPT/Codex desktop app (Electron). Every process it
    // spawns (main, zygote, renderer, gpu, network/storage utility) shares the
    // comm "ChatGPT", so this one prefix covers the whole app. comm is compared
    // case-sensitively, so match the app's real casing, plus the lowercase form.
    if (comm[0] == 'C' && comm[1] == 'h' && comm[2] == 'a' && comm[3] == 't' &&
        comm[4] == 'G' && comm[5] == 'P' && comm[6] == 'T')
        return 1;
    if (comm[0] == 'c' && comm[1] == 'h' && comm[2] == 'a' && comm[3] == 't' &&
        comm[4] == 'g' && comm[5] == 'p' && comm[6] == 't')
        return 1;

    // "devin"
    if (comm[0] == 'd' && comm[1] == 'e' && comm[2] == 'v' && comm[3] == 'i' && comm[4] == 'n')
        return 1;

    // "aider"
    if (comm[0] == 'a' && comm[1] == 'i' && comm[2] == 'd' && comm[3] == 'e' && comm[4] == 'r')
        return 1;

    // "windsurf" (Codeium IDE)
    if (comm[0] == 'w' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'd' && comm[4] == 's')
        return 1;

    // "agy" (Antigravity CLI — Google Gemini successor)
    if (comm[0] == 'a' && comm[1] == 'g' && comm[2] == 'y')
        return 1;

    // "antigravity"
    if (comm[0] == 'a' && comm[1] == 'n' && comm[2] == 't' && comm[3] == 'i' && comm[4] == 'g')
        return 1;

    // "gemini" (legacy)
    if (comm[0] == 'g' && comm[1] == 'e' && comm[2] == 'm' && comm[3] == 'i' && comm[4] == 'n' && comm[5] == 'i')
        return 1;

    // "gemini" (Gemini CLI)
    if (comm[0] == 'g' && comm[1] == 'e' && comm[2] == 'm' && comm[3] == 'i' && comm[4] == 'n' && comm[5] == 'i')
        return 1;

    // "agent" — Cursor CLI binary (cursor-agent renames to "agent")
    if (comm[0] == 'a' && comm[1] == 'g' && comm[2] == 'e' && comm[3] == 'n' && comm[4] == 't' && comm[5] == '\0')
        return 1;

    // "MainThread" — Cursor/Python agent main process (Python renames comm via prctl).
    // Must be in is_ai_agent (not just is_runtime) because this IS the top-level
    // agent process — it has no agent ancestor, so is_agent_child() would fail.
    if (comm[0] == 'M' && comm[1] == 'a' && comm[2] == 'i' && comm[3] == 'n' &&
        comm[4] == 'T' && comm[5] == 'h' && comm[6] == 'r' && comm[7] == 'e')
        return 1;

    // "opencode"
    if (comm[0] == 'o' && comm[1] == 'p' && comm[2] == 'e' && comm[3] == 'n' && comm[4] == 'c')
        return 1;

    // "hermes"
    if (comm[0] == 'h' && comm[1] == 'e' && comm[2] == 'r' && comm[3] == 'm' && comm[4] == 'e' && comm[5] == 's')
        return 1;

    // Any "claw"-family agent: the comm's FIRST WORD contains "claw"
    // (nanoclaw, nemoclaw, openclaw, closedclaw, trustclaw, ...). Only the first
    // word: a later word is an argument a program put in its own name, not who
    // it is. Bounded scan over the 16-byte comm; unrolled for the verifier.
    #pragma unroll
    for (int i = 0; i + 3 < MAX_COMM_LEN; i++) {
        if (comm[i] == '\0' || comm[i] == ' ')
            break;
        if (comm[i] == 'c' && comm[i+1] == 'l' && comm[i+2] == 'a' && comm[i+3] == 'w')
            return 1;
    }

    return 0;
}

#endif
