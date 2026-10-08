// SPDX-License-Identifier: Apache-2.0
// voice.rs — speaks live commentary, on this machine.
//
// One speech process stays running with its voice loaded, and its raw audio
// is piped into the system player, so a new line starts in about a second.
// Preferred: Kokoro-82M through rz-kokoro (voice af_heart), the natural one.
// Then Piper, then espeak-ng; with none, the app shows captions only. Each is
// a separate program found on disk and is not linked into this app (their
// phonemizers use espeak-ng, which is GPL-3.0).
//
// An interrupting line (Ring Zero refused something) stops whatever is
// playing and starts fresh.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

const VOICE_DIRS: &[&str] = &["/usr/lib/ringzero/voice", "/opt/ringzero/voice"];
const VOICE_FILE: &str = "en_US-joe-medium.onnx";
const PIPER_RATE: u32 = 22050;
const KOKORO_RATE: u32 = 24000;
/// Kokoro speaker: 3 = af_heart.
const KOKORO_SPEAKER: &str = "3";

struct Pipeline {
    piper: Child,
    player: Child,
}

impl Pipeline {
    fn stop(mut self) {
        let _ = self.player.kill();
        let _ = self.piper.kill();
        let _ = self.player.wait();
        let _ = self.piper.wait();
    }
    fn alive(&mut self) -> bool {
        matches!(self.piper.try_wait(), Ok(None)) && matches!(self.player.try_wait(), Ok(None))
    }
}

static PIPE: Mutex<Option<Pipeline>> = Mutex::new(None);

fn piper_paths() -> Option<(PathBuf, PathBuf)> {
    for d in VOICE_DIRS {
        let bin = Path::new(d).join("piper").join("piper");
        let model = Path::new(d).join(VOICE_FILE);
        if bin.is_file() && model.is_file() {
            return Some((bin, model));
        }
    }
    None
}

fn kokoro_paths() -> Option<(PathBuf, PathBuf)> {
    for d in VOICE_DIRS {
        let bin = Path::new(d).join("kokoro").join("rz-kokoro");
        let model = Path::new(d).join("kokoro").join("model");
        if bin.is_file() && model.join("model.onnx").is_file() {
            return Some((bin, model));
        }
    }
    None
}

fn on_path(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(cmd).is_file()))
        .unwrap_or(false)
}

/// The command that plays raw 16-bit mono audio from stdin.
fn player_command(rate: u32) -> Option<Command> {
    if on_path("paplay") {
        let mut c = Command::new("paplay");
        c.args(["--raw", &format!("--rate={rate}"), "--channels=1", "--format=s16le"]);
        return Some(c);
    }
    if on_path("pw-play") {
        let mut c = Command::new("pw-play");
        c.args(["--raw", "--rate", &rate.to_string(), "--channels", "1", "--format", "s16", "-"]);
        return Some(c);
    }
    if on_path("aplay") {
        let mut c = Command::new("aplay");
        c.args(["-q", "-r", &rate.to_string(), "-f", "S16_LE", "-t", "raw", "-c", "1"]);
        return Some(c);
    }
    None
}

/// Which voice this machine can use: "kokoro", "piper", "espeak" or "none".
pub fn engine() -> &'static str {
    if kokoro_paths().is_some() && player_command(KOKORO_RATE).is_some() {
        "kokoro"
    } else if piper_paths().is_some() && player_command(PIPER_RATE).is_some() {
        "piper"
    } else if on_path("espeak-ng") {
        "espeak"
    } else {
        "none"
    }
}

fn start_pipeline() -> Result<Pipeline, String> {
    let (mut cmd, rate) = if let Some((bin, model)) = kokoro_paths() {
        let mut c = Command::new(&bin);
        c.arg(&model).arg(KOKORO_SPEAKER).arg("4").arg("1.0").arg("1.0");
        c.current_dir(bin.parent().unwrap_or(Path::new("/")));
        (c, KOKORO_RATE)
    } else {
        let (bin, model) = piper_paths().ok_or("no voice installed")?;
        let mut c = Command::new(&bin);
        c.arg("--model").arg(&model).arg("--output-raw").arg("--sentence_silence").arg("0.15");
        c.current_dir(bin.parent().unwrap_or(Path::new("/")));
        (c, PIPER_RATE)
    };
    let mut piper = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start the voice: {e}"))?;
    let audio = piper.stdout.take().ok_or("no audio from the voice")?;
    let player = player_command(rate)
        .ok_or("no audio player found")?
        .stdin(Stdio::from(audio))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            let _ = piper.kill();
            format!("could not start audio playback: {e}")
        })?;
    Ok(Pipeline { piper, player })
}

/// One line of text, safe to hand to a speech engine: a single line, bounded.
fn clean(text: &str) -> String {
    let t: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(400).collect();
    t.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Speak one line. `interrupt` stops whatever is playing first.
pub fn speak(text: &str, interrupt: bool) -> Result<&'static str, String> {
    let text = clean(text);
    if text.is_empty() {
        return Ok(engine());
    }
    match engine() {
        e @ ("kokoro" | "piper") => {
            let mut guard = PIPE.lock().map_err(|_| "voice busy")?;
            if interrupt {
                if let Some(p) = guard.take() {
                    p.stop();
                }
            }
            if guard.as_mut().map(|p| !p.alive()).unwrap_or(true) {
                if let Some(p) = guard.take() {
                    p.stop();
                }
                *guard = Some(start_pipeline()?);
            }
            let p = guard.as_mut().ok_or("voice unavailable")?;
            let stdin = p.piper.stdin.as_mut().ok_or("voice input closed")?;
            if writeln!(stdin, "{text}").and_then(|_| stdin.flush()).is_err() {
                // The process died between the check and the write; try once more.
                if let Some(p) = guard.take() {
                    p.stop();
                }
                let mut fresh = start_pipeline()?;
                if let Some(s) = fresh.piper.stdin.as_mut() {
                    let _ = writeln!(s, "{text}");
                    let _ = s.flush();
                }
                *guard = Some(fresh);
            }
            Ok(e)
        }
        "espeak" => {
            if interrupt {
                let _ = Command::new("pkill").args(["-x", "espeak-ng"]).status();
            }
            Command::new("espeak-ng")
                .args(["-s", "165", "--", &text])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| e.to_string())?;
            Ok("espeak")
        }
        _ => Ok("none"),
    }
}

/// Stop speaking now.
pub fn stop() {
    if let Ok(mut g) = PIPE.lock() {
        if let Some(p) = g.take() {
            p.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_one_bounded_line() {
        assert_eq!(clean("a\nb\tc\u{7}  d"), "a b c d");
        assert_eq!(clean(&"x".repeat(1000)).len(), 400);
    }
}
