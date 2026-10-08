// SPDX-License-Identifier: Apache-2.0
// rz-kokoro — Ring Zero's commentary voice: Kokoro-82M, loaded once.
//
// Reads one line of text at a time from stdin and writes the speech for it to
// stdout as raw signed 16-bit little-endian mono PCM at the model's sample
// rate (24000 Hz for Kokoro), flushing after every line. The app pipes this
// into the system audio player, exactly as it does with Piper, so the model
// is loaded once and each new line starts in about a second.
//
//   rz-kokoro <model-dir> [speaker-id] [threads] [speed] [gain]
//
// Built against the sherpa-onnx C API (Apache-2.0); c-api.h is vendored from
// sherpa-onnx v1.13.8. Kokoro-82M weights are Apache-2.0.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "c-api.h"

static char *join(const char *dir, const char *name) {
  size_t n = strlen(dir) + strlen(name) + 2;
  char *p = malloc(n);
  snprintf(p, n, "%s/%s", dir, name);
  return p;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <model-dir> [speaker-id] [threads] [speed] [gain]\n", argv[0]);
    return 2;
  }
  const char *dir = argv[1];
  int sid = argc > 2 ? atoi(argv[2]) : 3;          /* 3 = af_heart */
  int threads = argc > 3 ? atoi(argv[3]) : 4;
  float speed = argc > 4 ? (float)atof(argv[4]) : 1.0f;
  float gain = argc > 5 ? (float)atof(argv[5]) : 1.0f;

  SherpaOnnxOfflineTtsConfig config;
  memset(&config, 0, sizeof(config));
  config.model.kokoro.model = join(dir, "model.onnx");
  config.model.kokoro.voices = join(dir, "voices.bin");
  config.model.kokoro.tokens = join(dir, "tokens.txt");
  config.model.kokoro.data_dir = join(dir, "espeak-ng-data");
  config.model.kokoro.dict_dir = join(dir, "dict");
  config.model.kokoro.lexicon = join(dir, "lexicon-us-en.txt");
  config.model.kokoro.length_scale = 1.0f;
  config.model.num_threads = threads > 0 ? threads : 4;
  config.model.provider = "cpu";
  config.max_num_sentences = 1;

  const SherpaOnnxOfflineTts *tts = SherpaOnnxCreateOfflineTts(&config);
  if (!tts) {
    fprintf(stderr, "rz-kokoro: could not load the model from %s\n", dir);
    return 1;
  }
  fprintf(stderr, "rz-kokoro: ready, %d Hz\n", SherpaOnnxOfflineTtsSampleRate(tts));

  char line[4096];
  int16_t *pcm = NULL;
  size_t cap = 0;
  while (fgets(line, sizeof(line), stdin)) {
    line[strcspn(line, "\r\n")] = 0;
    if (!line[0]) continue;
    const SherpaOnnxGeneratedAudio *a = SherpaOnnxOfflineTtsGenerate(tts, line, sid, speed);
    if (!a) continue;
    if ((size_t)a->n > cap) {
      cap = (size_t)a->n;
      pcm = realloc(pcm, cap * sizeof(int16_t));
    }
    for (int32_t i = 0; i < a->n; i++) {
      float s = a->samples[i] * gain;
      if (s > 1.0f) s = 1.0f;
      if (s < -1.0f) s = -1.0f;
      pcm[i] = (int16_t)(s * 32767.0f);
    }
    fwrite(pcm, sizeof(int16_t), (size_t)a->n, stdout);
    fflush(stdout);
    SherpaOnnxDestroyOfflineTtsGeneratedAudio(a);
  }
  free(pcm);
  SherpaOnnxDestroyOfflineTts(tts);
  return 0;
}
