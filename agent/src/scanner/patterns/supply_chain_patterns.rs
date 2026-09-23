// SPDX-License-Identifier: Apache-2.0
// Pattern detection: Supply Chain (SC1-SC3, SC5-SC6, TR1-TR3)
// Ported from NVIDIA SkillSpector static_patterns_supply_chain.py
// Note: SC4 (OSV lookup) is handled by the existing osv.rs module.

use once_cell::sync::Lazy;
use regex::Regex;

use super::models::{get_explanation, get_line_number, get_remediation, PatternFinding, Severity};

struct PatternEntry {
    regex: Regex,
    confidence: f32,
}

fn compile_patterns(patterns: &[(&str, f32)]) -> Vec<PatternEntry> {
    patterns
        .iter()
        .map(|(pat, conf)| PatternEntry {
            regex: Regex::new(&format!("(?i){}", pat)).expect("invalid regex"),
            confidence: *conf,
        })
        .collect()
}

fn compile_patterns_multiline(patterns: &[(&str, f32)]) -> Vec<PatternEntry> {
    patterns
        .iter()
        .map(|(pat, conf)| PatternEntry {
            regex: Regex::new(&format!("(?im){}", pat)).expect("invalid regex"),
            confidence: *conf,
        })
        .collect()
}

// SC1: Unpinned Dependencies (only checked on dependency files)
static SC1_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns_multiline(&[
        (r"^[a-zA-Z][a-zA-Z0-9_-]*\s*$", 0.6),
        (r"^[a-zA-Z][a-zA-Z0-9_-]*\s*>=\s*[\d.]+\s*$", 0.5),
        (r"^[a-zA-Z][a-zA-Z0-9_-]*\s*==\s*\*\s*$", 0.7),
        (r#""[^"]+"\s*:\s*"(?:\*|latest)""#, 0.7),
        (r#""[^"]+"\s*:\s*"\^[\d.]+""#, 0.4),
        (
            r"install\s+(?:the\s+)?latest\s+(?:version\s+)?(?:of\s+)?(?:all\s+)?(?:packages?|dependencies)",
            0.6,
        ),
        (
            r"(?:don't|do\s+not)\s+(?:pin|lock|specify)\s+(?:package\s+)?versions?",
            0.7,
        ),
    ])
});

// SC2: External Script Fetching
static SC2_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (r"curl\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh", 0.9),
        (r"wget\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh", 0.9),
        (
            r"curl\s+[^|]*\|\s*(?:sudo\s+)?(?:python|python3|node|ruby|perl)",
            0.9,
        ),
        (
            r"wget\s+[^|]*\|\s*(?:sudo\s+)?(?:python|python3|node|ruby|perl)",
            0.9,
        ),
        (r"curl\s+[^&]*-o\s+\S+\s*&&\s*(?:sudo\s+)?(?:ba)?sh", 0.8),
        (r"wget\s+[^&]*-O\s+\S+\s*&&\s*(?:sudo\s+)?(?:ba)?sh", 0.8),
        (
            r"exec\s*\(\s*(?:urllib|requests|httpx)\.[^)]+\.(?:read|text|content)",
            0.95,
        ),
        (
            r"eval\s*\(\s*(?:urllib|requests|httpx)\.[^)]+\.(?:read|text|content)",
            0.95,
        ),
        (r"eval\s*\(\s*(?:await\s+)?fetch\s*\(", 0.9),
        (r"new\s+Function\s*\([^)]*fetch\s*\(", 0.9),
        (r"subprocess\.[^(]+\([^)]*(?:curl|wget)\s+https?://", 0.8),
        (r"download\s+and\s+(?:run|execute)\s+(?:the\s+)?script", 0.7),
        (
            r"run\s+(?:this|the)\s+(?:following\s+)?(?:curl|wget)\s+command",
            0.6,
        ),
    ])
});

// SC3: Obfuscated Code
static SC3_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (r"exec\s*\(\s*(?:base64\.)?b64decode\s*\(", 0.95),
        (r"eval\s*\(\s*(?:base64\.)?b64decode\s*\(", 0.95),
        (
            r#"exec\s*\(\s*codecs\.decode\s*\([^)]*['"]hex['"]\s*\)"#,
            0.95,
        ),
        (r"marshal\.loads\s*\(", 0.9),
        (r"exec\s*\(\s*marshal\.loads\s*\(", 0.95),
        (r"exec\s*\(\s*compile\s*\([^)]*base64", 0.9),
        (r"exec\s*\(\s*bytes\.fromhex\s*\(", 0.9),
        (r"exec\s*\(\s*bytearray\.fromhex\s*\(", 0.9),
        (r"exec\s*\(\s*(?:zlib|gzip)\.decompress\s*\(", 0.9),
        (r"eval\s*\(\s*atob\s*\(", 0.9),
        (r"new\s+Function\s*\(\s*atob\s*\(", 0.9),
        (r"_0x[a-f0-9]{4,}\s*\(", 0.8),
        (r#"['"][A-Fa-f0-9]{200,}['"]"#, 0.6),
        (r#"['"][A-Za-z0-9+/=]{200,}['"]"#, 0.5),
        (r"\(lambda\s+_:\s*exec\s*\(", 0.9),
        (r#"__import__\s*\(['"]os['"]\s*\)\.system"#, 0.85),
        (
            r"decode\s+(?:this|the)\s+(?:base64|hex)\s+(?:and\s+)?(?:run|execute)",
            0.8,
        ),
    ])
});

// SC5: Abandoned Dependencies — known abandoned package names
static ABANDONED_PACKAGES: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        // Python
        "pycrypto",
        "nose",
        "optparse",
        "distribute",
        "mimetools",
        "multifile",
        "popen2",
        "rfc822",
        "sets",
        "sha",
        "md5",
        "commands",
        "dircache",
        "fpformat",
        "htmllib",
        "ihooks",
        "linuxaudiodev",
        "mhlib",
        "mimify",
        "mutex",
        "new",
        "posixfile",
        "pre",
        "regsub",
        "sgmllib",
        "stat",
        "statvfs",
        "stringold",
        "sunaudiodev",
        "sv",
        "timing",
        "toaiff",
        "user",
        "xmllib",
        // npm
        "request",
        "nomnom",
        "optimist",
        "dominion",
        "npm-conf",
    ]
});

// SC6: Typosquatting — popular package names for edit-distance check
static POPULAR_PYPI: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "requests",
        "numpy",
        "pandas",
        "flask",
        "django",
        "boto3",
        "setuptools",
        "pip",
        "urllib3",
        "pyyaml",
        "cryptography",
        "pillow",
        "pydantic",
        "sqlalchemy",
        "pytest",
        "click",
        "jinja2",
        "httpx",
        "aiohttp",
        "fastapi",
        "celery",
        "paramiko",
        "beautifulsoup4",
        "lxml",
        "scrapy",
        "redis",
        "pymongo",
        "psycopg2",
        "matplotlib",
        "scipy",
        "scikit-learn",
        "tensorflow",
        "torch",
        "keras",
        "transformers",
        "openai",
        "langchain",
        "gunicorn",
        "uvicorn",
        "rich",
        "typer",
        "black",
        "ruff",
        "mypy",
        "pylint",
        "flake8",
        "isort",
    ]
});

static POPULAR_NPM: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "express",
        "react",
        "react-dom",
        "next",
        "vue",
        "angular",
        "lodash",
        "axios",
        "moment",
        "chalk",
        "commander",
        "inquirer",
        "webpack",
        "babel",
        "eslint",
        "prettier",
        "typescript",
        "jest",
        "mocha",
        "chai",
        "puppeteer",
        "socket.io",
        "mongoose",
        "sequelize",
        "passport",
        "jsonwebtoken",
        "dotenv",
        "cors",
        "body-parser",
        "nodemon",
        "pm2",
    ]
});

// Trusted domains for SC2 false-positive suppression
static TRUSTED_DOMAINS: &[&str] = &[
    "deb.nodesource.com",
    "rpm.nodesource.com",
    "get.docker.com",
    "install.python-poetry.org",
    "raw.githubusercontent.com",
    "brew.sh",
    "rustup.rs",
    "pypa.io",
    "pip.pypa.io",
    "astral.sh",
    "pypi.org",
    "npmjs.com",
    "github.com",
];

fn is_trusted_source(text: &str) -> bool {
    let lower = text.to_lowercase();
    TRUSTED_DOMAINS.iter().any(|d| lower.contains(d))
}

static SAFE_INSTALL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:pip|npm)\s+install").unwrap());

fn is_safe_supply_chain_pattern(text: &str) -> bool {
    is_trusted_source(text) || SAFE_INSTALL_RE.is_match(text)
}

fn is_dep_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    [
        "requirements",
        "package.json",
        "pyproject.toml",
        "setup.py",
        "pipfile",
    ]
    .iter()
    .any(|n| lower.contains(n))
}

// Edit distance (Levenshtein)
fn edit_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let (m, n) = (a_chars.len(), b_chars.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    for i in 0..m {
        let mut curr = vec![i + 1];
        for j in 0..n {
            let cost = if a_chars[i] == b_chars[j] { 0 } else { 1 };
            curr.push((curr[j] + 1).min(prev[j + 1] + 1).min(prev[j] + cost));
        }
        prev = curr;
    }
    prev[n]
}

fn is_typosquat(pkg_name: &str, popular: &[&str]) -> Option<String> {
    let normalized = pkg_name.to_lowercase().replace('_', "-");
    for &pop in popular {
        let pop_norm = pop.to_lowercase().replace('_', "-");
        if normalized == pop_norm {
            return None;
        }
        if normalized.len() < 3 || pop_norm.len() < 3 {
            continue;
        }
        let dist = edit_distance(&normalized, &pop_norm);
        if dist > 0 && dist <= 2 {
            return Some(pop.to_string());
        }
    }
    None
}

static REQ_LINE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([a-zA-Z][a-zA-Z0-9._-]*)(?:\[.*?\])?\s*(?:[=<>!~]=?\s*[\d.*]+)?").unwrap()
});

static PKG_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([a-zA-Z][a-zA-Z0-9._-]*)").unwrap());

/// Extract package names from requirements.txt-style content
fn extract_packages_requirements(content: &str) -> Vec<(String, usize)> {
    let mut results = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        if let Some(m) = REQ_LINE_RE.find(trimmed) {
            if let Some(cap) = PKG_NAME_RE.captures(m.as_str()) {
                results.push((cap[1].to_string(), i + 1));
            }
        }
    }
    results
}

/// Extract package names from package.json content
fn extract_packages_package_json(content: &str) -> Vec<(String, usize)> {
    let dep_re = Regex::new(r#""(?:dependencies|devDependencies|peerDependencies)""#).unwrap();
    let pkg_re = Regex::new(r#""([^"]+)"\s*:\s*"[^"]*""#).unwrap();
    let mut results = Vec::new();
    let mut in_deps = false;
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if dep_re.is_match(trimmed) {
            in_deps = true;
            continue;
        }
        if in_deps && trimmed.starts_with('}') {
            in_deps = false;
            continue;
        }
        if in_deps {
            if let Some(cap) = pkg_re.captures(trimmed) {
                results.push((cap[1].to_string(), i + 1));
            }
        }
    }
    results
}

// TR1-TR3: Trigger analysis patterns
static OVERLY_BROAD_WORDS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "the", "a", "an", "is", "it", "do", "go", "make", "thing", "stuff", "code", "file", "data",
        "text", "work", "good", "bad", "yes", "no", "ok", "please", "thanks", "hi", "hello", "hey",
    ]
});

static BUILTIN_COMMANDS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "help", "search", "find", "run", "test", "build", "deploy", "install", "create", "delete",
        "update", "list", "show", "get", "set", "open", "close", "start", "stop", "restart",
        "status", "log", "debug", "commit", "push", "pull", "merge", "branch", "checkout",
        "rebase", "diff", "blame", "stash", "tag", "release", "version", "lint", "format", "fix",
        "refactor", "review", "explain", "chat", "ask", "edit", "write", "read", "save", "load",
        "copy", "move",
    ]
});

static TR3_BAITING_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)^(?:anything|everything|whatever|always|any\s+(?:question|request|task|input))$").unwrap(),
        Regex::new(r"(?i)^(?:when(?:ever)?|if|every\s+time)\s+(?:the\s+)?user\s+(?:says?|asks?|types?|sends?)\s+(?:anything|something|a\s+message)$").unwrap(),
        Regex::new(r"(?i)^(?:all|any|every)\s+(?:messages?|inputs?|requests?|queries?|questions?)$").unwrap(),
    ]
});

pub fn scan(content: &str, file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // SC1: Unpinned Dependencies — LOW (only on dependency files)
    if is_dep_file(file_path) {
        for entry in SC1_PATTERNS.iter() {
            for mat in entry.regex.find_iter(content) {
                let line = get_line_number(content, mat.start());
                findings.push(PatternFinding {
                    rule_id: "SC1".to_string(),
                    pattern_name: "Unpinned Dependencies".to_string(),
                    category: "Supply Chain".to_string(),
                    severity: Severity::Low,
                    confidence: entry.confidence,
                    message: "Unpinned Dependencies".to_string(),
                    file: file_path.to_string(),
                    start_line: line,
                    matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                    explanation: get_explanation("SC1").to_string(),
                    remediation: get_remediation("SC1").to_string(),
                });
            }
        }
    }

    // SC2: External Script Fetching — HIGH (or LOW if trusted)
    for entry in SC2_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            let matched = &mat.as_str()[..mat.as_str().len().min(200)];
            let (confidence, severity) = if is_safe_supply_chain_pattern(matched) {
                (entry.confidence.min(0.15), Severity::Low)
            } else {
                (entry.confidence, Severity::High)
            };
            findings.push(PatternFinding {
                rule_id: "SC2".to_string(),
                pattern_name: "External Script Fetching".to_string(),
                category: "Supply Chain".to_string(),
                severity,
                confidence,
                message: "External Script Fetching".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(matched.to_string()),
                explanation: get_explanation("SC2").to_string(),
                remediation: get_remediation("SC2").to_string(),
            });
        }
    }

    // SC3: Obfuscated Code — HIGH
    for entry in SC3_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "SC3".to_string(),
                pattern_name: "Obfuscated Code".to_string(),
                category: "Supply Chain".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Obfuscated Code".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("SC3").to_string(),
                remediation: get_remediation("SC3").to_string(),
            });
        }
    }

    // SC5 & SC6: Dependency-level checks on dependency files
    if is_dep_file(file_path) {
        let lower_path = file_path.to_lowercase();
        let is_python = ["requirements", "pyproject.toml", "setup.py", "pipfile"]
            .iter()
            .any(|n| lower_path.contains(n));
        let is_npm = lower_path.contains("package.json");

        let packages = if is_python {
            extract_packages_requirements(content)
        } else if is_npm {
            extract_packages_package_json(content)
        } else {
            Vec::new()
        };

        let popular = if is_python {
            POPULAR_PYPI.as_slice()
        } else {
            POPULAR_NPM.as_slice()
        };

        for (pkg_name, line_num) in &packages {
            let pkg_lower = pkg_name.to_lowercase().replace('_', "-");

            // SC5: Abandoned Dependencies
            if ABANDONED_PACKAGES
                .iter()
                .any(|a| a.to_lowercase().replace('_', "-") == pkg_lower)
            {
                findings.push(PatternFinding {
                    rule_id: "SC5".to_string(),
                    pattern_name: "Abandoned Dependency".to_string(),
                    category: "Supply Chain".to_string(),
                    severity: Severity::Medium,
                    confidence: 0.75,
                    message: format!("Abandoned Dependency: {} is unmaintained and no longer receives security updates", pkg_name),
                    file: file_path.to_string(),
                    start_line: *line_num,
                    matched_text: Some(pkg_name.clone()),
                    explanation: get_explanation("SC5").to_string(),
                    remediation: get_remediation("SC5").to_string(),
                });
            }

            // SC6: Typosquatting
            if let Some(similar) = is_typosquat(pkg_name, popular) {
                findings.push(PatternFinding {
                    rule_id: "SC6".to_string(),
                    pattern_name: "Typosquatting Dependency".to_string(),
                    category: "Supply Chain".to_string(),
                    severity: Severity::High,
                    confidence: 0.7,
                    message: format!(
                        "Possible Typosquatting: '{}' resembles popular package '{}'",
                        pkg_name, similar
                    ),
                    file: file_path.to_string(),
                    start_line: *line_num,
                    matched_text: Some(pkg_name.clone()),
                    explanation: get_explanation("SC6").to_string(),
                    remediation: get_remediation("SC6").to_string(),
                });
            }
        }
    }

    findings
}

/// Scan trigger strings for TR1-TR3 patterns.
/// Call this separately with extracted trigger strings from manifest.
pub fn scan_triggers(triggers: &[String], file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    for (i, trigger) in triggers.iter().enumerate() {
        let trigger_lower = trigger.to_lowercase();
        let trigger_trimmed = trigger_lower.trim();
        let words: Vec<&str> = trigger_trimmed.split_whitespace().collect();
        let line_num = i + 1;

        // TR1: Overly broad triggers
        if words.len() == 1 && OVERLY_BROAD_WORDS.contains(&words[0]) {
            findings.push(PatternFinding {
                rule_id: "TR1".to_string(),
                pattern_name: "Overly Broad Trigger".to_string(),
                category: "Trigger Abuse".to_string(),
                severity: Severity::Low,
                confidence: 0.75,
                message: format!("Overly Broad Trigger: '{}' is a common word that will activate in many unintended contexts", trigger),
                file: file_path.to_string(),
                start_line: line_num,
                matched_text: Some(trigger.clone()),
                explanation: get_explanation("TR1").to_string(),
                remediation: get_remediation("TR1").to_string(),
            });
        } else if trigger_trimmed.len() <= 2 {
            findings.push(PatternFinding {
                rule_id: "TR1".to_string(),
                pattern_name: "Overly Broad Trigger".to_string(),
                category: "Trigger Abuse".to_string(),
                severity: Severity::Low,
                confidence: 0.7,
                message: format!(
                    "Overly Broad Trigger: '{}' is too short and may match unintended inputs",
                    trigger
                ),
                file: file_path.to_string(),
                start_line: line_num,
                matched_text: Some(trigger.clone()),
                explanation: get_explanation("TR1").to_string(),
                remediation: get_remediation("TR1").to_string(),
            });
        }

        // TR2: Shadow commands
        if BUILTIN_COMMANDS.contains(&trigger_trimmed)
            || (!words.is_empty() && BUILTIN_COMMANDS.contains(&words[0]) && words.len() <= 2)
        {
            findings.push(PatternFinding {
                rule_id: "TR2".to_string(),
                pattern_name: "Shadow Command Trigger".to_string(),
                category: "Trigger Abuse".to_string(),
                severity: Severity::Medium,
                confidence: 0.7,
                message: format!(
                    "Shadow Command Trigger: '{}' conflicts with built-in command '{}'",
                    trigger, words[0]
                ),
                file: file_path.to_string(),
                start_line: line_num,
                matched_text: Some(trigger.clone()),
                explanation: get_explanation("TR2").to_string(),
                remediation: get_remediation("TR2").to_string(),
            });
        }

        // TR3: Keyword baiting
        for bp in TR3_BAITING_PATTERNS.iter() {
            if bp.is_match(trigger_trimmed) {
                findings.push(PatternFinding {
                    rule_id: "TR3".to_string(),
                    pattern_name: "Keyword Baiting Trigger".to_string(),
                    category: "Trigger Abuse".to_string(),
                    severity: Severity::Medium,
                    confidence: 0.8,
                    message: format!("Keyword Baiting Trigger: '{}' is designed to match all or most user inputs", trigger),
                    file: file_path.to_string(),
                    start_line: line_num,
                    matched_text: Some(trigger.clone()),
                    explanation: get_explanation("TR3").to_string(),
                    remediation: get_remediation("TR3").to_string(),
                });
                break;
            }
        }
    }

    findings
}
