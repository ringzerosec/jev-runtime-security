#!/usr/bin/env bash
# install-voice.sh — the on-device voice for Ring Zero's live commentary.
#
# Downloads Piper (text to speech) and one English voice from their official
# release pages and installs them under /usr/lib/ringzero/voice. Run as root.
#
# Licences, installed next to the files:
#   Piper          MIT, but the release bundles espeak-ng, which is GPL-3.0.
#                  It is installed as a separate program the app runs; it is
#                  not linked into Ring Zero. Source: github.com/rhasspy/piper
#                  and github.com/espeak-ng/espeak-ng.
#   Voice "joe"    trained on a CC0 dataset (OHF-Voice/voice-datasets).
set -euo pipefail

PIPER_VERSION=2023.11.14-2
VOICE=en_US-joe-medium
DEST=/usr/lib/ringzero/voice

case "$(uname -m)" in
  aarch64|arm64) PIPER_ASSET=piper_linux_aarch64.tar.gz ;;
  x86_64|amd64)  PIPER_ASSET=piper_linux_x86_64.tar.gz ;;
  *) echo "No Piper release for $(uname -m)"; exit 1 ;;
esac

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo $0)"; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
base=https://huggingface.co/rhasspy/piper-voices/resolve/main/en/en_US/joe/medium

echo "Downloading Piper $PIPER_VERSION and the $VOICE voice..."
curl -fsSL -o "$tmp/piper.tgz" "https://github.com/rhasspy/piper/releases/download/$PIPER_VERSION/$PIPER_ASSET"
curl -fsSL -o "$tmp/$VOICE.onnx" "$base/$VOICE.onnx"
curl -fsSL -o "$tmp/$VOICE.onnx.json" "$base/$VOICE.onnx.json"
curl -fsSL -o "$tmp/VOICE_MODEL_CARD" "https://huggingface.co/rhasspy/piper-voices/raw/main/en/en_US/joe/medium/MODEL_CARD"
curl -fsSL -o "$tmp/PIPER_LICENSE.md" "https://raw.githubusercontent.com/rhasspy/piper/master/LICENSE.md"
curl -fsSL -o "$tmp/ESPEAK_NG_COPYING" "https://raw.githubusercontent.com/espeak-ng/espeak-ng/master/COPYING"

install -d -m 0755 "$DEST"
tar xzf "$tmp/piper.tgz" -C "$DEST"
install -m 0644 "$tmp/$VOICE.onnx" "$tmp/$VOICE.onnx.json" "$tmp/VOICE_MODEL_CARD" \
  "$tmp/PIPER_LICENSE.md" "$tmp/ESPEAK_NG_COPYING" "$DEST/"
cat > "$DEST/README" <<TXT
Ring Zero live commentary voice.
piper/      Piper $PIPER_VERSION (MIT, bundles espeak-ng under GPL-3.0; see
            PIPER_LICENSE.md and ESPEAK_NG_COPYING). Source:
            https://github.com/rhasspy/piper  https://github.com/espeak-ng/espeak-ng
$VOICE.onnx Piper voice "joe", dataset CC0 (see VOICE_MODEL_CARD).
TXT

echo "Testing..."
echo "Ring Zero live commentary is ready." | "$DEST/piper/piper" --model "$DEST/$VOICE.onnx" --output_file "$tmp/t.wav" 2>/dev/null
echo "Installed to $DEST. Turn on Live commentary in the Ring Zero app."
