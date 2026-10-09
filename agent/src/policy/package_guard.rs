// SPDX-License-Identifier: Apache-2.0
//! Agents can't install packages.
//!
//! The kernel stops a process in an agent's tree the moment it becomes a
//! package manager (npm, pip, uv, cargo, ...). This module reads its command
//! line and says whether it adds or fetches packages. If it does, the daemon
//! kills it; if not (`npm test`, `npm run build`, `pip list`), it resumes.
//!
//! Why refuse installs outright rather than check packages against a list of
//! known-bad ones: a list only knows what someone has already caught. A package
//! published this morning is on no list, and its install script runs with the
//! agent's access the moment it lands. An agent that needs a dependency can ask
//! the person, who installs it.
//!
//! The rule is about adding or fetching packages, so it is strict on purpose:
//! `npx`, `bunx`, `pnpm dlx` and friends fetch and run a package, and count.

/// One package-manager command, as the person will read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    /// "npm", "pip", "uv", ...
    pub tool: String,
    /// The command, shortened for a sentence: "npm install left-pad".
    pub command: String,
}

/// Interpreters a package manager runs under. `node /usr/bin/npm install x`,
/// `/usr/bin/env node /usr/bin/npm install x`, `python3 -m pip install x`.
fn is_interpreter(word: &str) -> bool {
    word == "env"
        || word == "node"
        || word == "nodejs"
        || word == "bun"
        || word.starts_with("python")
}

fn program(arg: &str) -> String {
    let base = arg
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(arg)
        .to_ascii_lowercase();
    // The scripts node runs for them.
    match base.as_str() {
        "npm-cli.js" => "npm".into(),
        "npx-cli.js" => "npx".into(),
        "yarn.js" | "yarn.cjs" => "yarn".into(),
        "pnpm.cjs" | "pnpm.mjs" => "pnpm".into(),
        _ => base,
    }
}

const TOOLS: &[&str] = &[
    "npm", "npx", "pnpm", "pnpx", "yarn", "bun", "bunx", "pip", "pip3", "pipx", "uv", "uvx",
    "poetry", "cargo", "gem",
];

/// Does this command line add or fetch packages? `argv` is the process's
/// argv, as in /proc/<pid>/cmdline.
pub fn install_command(argv: &[String]) -> Option<Install> {
    // Find the package manager: argv[0], or past the interpreters in front.
    let mut i = 0;
    let tool = loop {
        let a = argv.get(i)?;
        let p = program(a);
        if TOOLS.contains(&p.as_str()) {
            break p;
        }
        // `python -m pip ...`
        if p.starts_with("python") {
            if let Some(m) = argv.iter().skip(i + 1).position(|x| x == "-m") {
                let j = i + 1 + m + 1;
                if argv
                    .get(j)
                    .is_some_and(|x| x == "pip" || x == "pip3" || x == "uv")
                {
                    i = j;
                    break program(&argv[j]);
                }
            }
        }
        if !is_interpreter(&p) || i >= 3 {
            return None;
        }
        i += 1;
    };
    let rest: Vec<&str> = argv[i + 1..].iter().map(String::as_str).collect();
    let positional: Vec<&str> = rest
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-'))
        .collect();
    let sub = positional.first().copied().unwrap_or("");
    let has = |flag: &str| {
        rest.iter()
            .any(|a| *a == flag || a.starts_with(&format!("{flag}=")))
    };

    let adds = match tool.as_str() {
        // Fetch a package and run it.
        "npx" | "pnpx" | "bunx" | "uvx" => true,
        "npm" => {
            matches!(
                sub,
                "install"
                    | "i"
                    | "in"
                    | "ins"
                    | "inst"
                    | "insta"
                    | "instal"
                    | "isnt"
                    | "isnta"
                    | "isntal"
                    | "isntall"
                    | "add"
                    | "ci"
                    | "clean-install"
                    | "ic"
                    | "install-clean"
                    | "isntall-clean"
                    | "install-test"
                    | "it"
                    | "cit"
                    | "clean-install-test"
                    | "sit"
                    | "update"
                    | "up"
                    | "upgrade"
                    | "udpate"
                    | "exec"
                    | "x"
                    | "create"
                    | "innit"
            ) || (sub == "init" && positional.len() > 1)
        }
        "pnpm" => matches!(
            sub,
            "add"
                | "install"
                | "i"
                | "update"
                | "up"
                | "upgrade"
                | "dlx"
                | "create"
                | "install-test"
                | "it"
        ),
        // Bare `yarn` installs.
        "yarn" => {
            sub.is_empty()
                || matches!(
                    sub,
                    "add" | "install" | "up" | "upgrade" | "upgrade-interactive" | "dlx" | "create"
                )
        }
        "bun" => matches!(
            sub,
            "add" | "a" | "install" | "i" | "update" | "x" | "create" | "c"
        ),
        "pip" | "pip3" => matches!(sub, "install" | "download" | "wheel"),
        "pipx" => matches!(
            sub,
            "install" | "run" | "inject" | "upgrade" | "upgrade-all" | "reinstall"
        ),
        "uv" => match sub {
            "add" | "sync" => true,
            "pip" => matches!(positional.get(1).copied(), Some("install" | "sync")),
            "tool" => matches!(
                positional.get(1).copied(),
                Some("install" | "run" | "upgrade")
            ),
            "run" => has("--with") || has("--with-requirements"),
            _ => false,
        },
        "poetry" => matches!(sub, "add" | "install" | "update" | "sync"),
        "cargo" => matches!(sub, "install" | "add" | "binstall"),
        "gem" => matches!(sub, "install" | "update"),
        _ => false,
    };
    if !adds {
        return None;
    }
    let mut words = vec![tool.clone()];
    words.extend(rest.iter().take(5).map(|s| s.to_string()));
    let mut command = words.join(" ");
    if command.len() > 80 {
        let mut cut = 77;
        while !command.is_char_boundary(cut) {
            cut -= 1;
        }
        command.truncate(cut);
        command.push_str("...");
    }
    Some(Install { tool, command })
}

/// Read a live process's argv.
pub fn argv_of(pid: u32) -> Option<Vec<String>> {
    let data = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let v: Vec<String> = data
        .split(|&b| b == 0)
        .filter(|t| !t.is_empty())
        .map(|t| String::from_utf8_lossy(t).into_owned())
        .collect();
    (!v.is_empty()).then_some(v)
}

/// The prefix that marks a refused install in an event's target, the way
/// "TAMPER:" marks tamper refusals. Narration and the UI read it.
pub const TARGET_PREFIX: &str = "PKG_INSTALL:";

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn installs_are_recognised() {
        for c in [
            "npm install left-pad",
            "npm i",
            "npm ci",
            "npm add express",
            "npm update",
            "node /usr/lib/node_modules/npm/bin/npm-cli.js install x",
            "/usr/bin/env node /usr/bin/npm install --global openclaw@latest",
            "npx create-react-app app",
            "pnpm add zod",
            "pnpm dlx cowsay",
            "yarn",
            "yarn add react",
            "bun add hono",
            "bunx cowsay",
            "pip install requests",
            "pip3 install -r requirements.txt",
            "/usr/bin/python3 -m pip install requests",
            "python3 -m pip download x",
            "uv add httpx",
            "uv sync",
            "uv pip install x",
            "uv tool install ruff",
            "uv run --with rich script.py",
            "uvx ruff",
            "poetry add flask",
            "cargo install ripgrep",
            "cargo add serde",
            "gem install rails",
            "pipx run black",
            "npm init vite",
        ] {
            assert!(
                install_command(&cmd(c)).is_some(),
                "{c:?} adds or fetches packages"
            );
        }
    }

    #[test]
    fn everyday_work_is_not_an_install() {
        for c in [
            "npm test",
            "npm run build",
            "npm run install-deps-docs",
            "npm ls",
            "npm init -y",
            "npm --version",
            "pnpm run dev",
            "yarn test",
            "yarn run lint",
            "bun run index.ts",
            "bun test",
            "pip list",
            "pip show requests",
            "pip freeze",
            "python3 -m pytest",
            "python3 script.py install",
            "node server.js install",
            "uv run pytest",
            "uv pip list",
            "poetry run pytest",
            "cargo build",
            "cargo test",
            "gem list",
            "bash -c npm install",
        ] {
            assert!(
                install_command(&cmd(c)).is_none(),
                "{c:?} is not an install"
            );
        }
    }

    #[test]
    fn the_sentence_is_short_and_readable() {
        let i = install_command(&cmd("/usr/bin/env node /usr/bin/npm install left-pad")).unwrap();
        assert_eq!(i.tool, "npm");
        assert_eq!(i.command, "npm install left-pad");
        let p = install_command(&cmd("python3 -m pip install requests")).unwrap();
        assert_eq!(p.command, "pip install requests");
    }
}
