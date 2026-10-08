# rz-kokoro

The commentary voice: Kokoro-82M (Apache-2.0, trained on permissive audio),
run through the sherpa-onnx C API and kept loaded, reading one line of text
per stdin line and writing raw s16le mono PCM at 24 kHz to stdout.

- `c-api.h` is vendored unchanged from sherpa-onnx v1.13.8 (Apache-2.0,
  https://github.com/k2-fsa/sherpa-onnx).
- Runtime files, installed under `/usr/lib/ringzero/voice/kokoro/`:
  `rz-kokoro`, `lib/` (libsherpa-onnx-c-api.so, libonnxruntime.so from the
  sherpa-onnx linux shared release) and `model/` (kokoro-multi-lang-v1_0,
  full precision: the int8 build is ~5x slower on ARM64).
- sherpa-onnx phonemizes with espeak-ng (GPL-3.0); ship its licence and
  source offer with the runtime files. rz-kokoro is a separate program the
  app runs, never linked into the app.

Build: `gcc -O2 -o rz-kokoro rz-kokoro.c -I. -L<sherpa>/lib -lsherpa-onnx-c-api -Wl,-rpath,'$ORIGIN/lib'`
