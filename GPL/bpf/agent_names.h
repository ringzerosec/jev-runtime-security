/* SPDX-License-Identifier: GPL-2.0 */
// agent_names.h — which process names are AI agents. Shared by ringzero.bpf.c
// and stdiocap.bpf.c so both objects agree on what an agent is.
#ifndef RZ_AGENT_NAMES_H
#define RZ_AGENT_NAMES_H

#ifndef MAX_COMM_LEN
#define MAX_COMM_LEN 16
#endif

static __always_inline int is_ai_agent(const char *comm) {
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

    // Any "claw"-family agent: comm CONTAINS the substring "claw"
    // (nanoclaw, nemoclaw, openclaw, closedclaw, trustclaw, ...). Bounded
    // substring scan over the 16-byte comm; unrolled for the verifier.
    #pragma unroll
    for (int i = 0; i + 3 < MAX_COMM_LEN; i++) {
        if (comm[i] == '\0')
            break;
        if (comm[i] == 'c' && comm[i+1] == 'l' && comm[i+2] == 'a' && comm[i+3] == 'w')
            return 1;
    }

    return 0;
}

#endif
