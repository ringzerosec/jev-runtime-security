#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
A TEST DOUBLE for the Jev scoring contract. Not a client, not a mock of a real
service in any production path — it exists so the checks layer can be exercised
end to end on a machine with no API key and no network.

It implements the one route the provider calls:

    POST /v1/systemone
    Authorization: Bearer <anything non-empty>
    {"state": ..., "model": "...", "questions": {"<qid>": {"type": ...}}}

and answers with the typed shape the provider expects: a `choice` with
`probabilities` and `confidence` for a choice question, a `noul` with
`confidence` for a noul question.

Modes, so the failure paths can be exercised too:

    --mode ok         typed answers (default)
    --mode 429        rate limited
    --mode 401        unauthorized
    --mode 529        overloaded
    --mode malformed  HTTP 200 with a body that is not valid JSON
    --mode slow       sleep past the client timeout, to exercise the timeout path

Usage:
    python3 tests/jev-stub.py --port 8099 --mode ok
"""
import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = "ok"
DELAY = 0.0

# What this double claims about any tool call it is shown. Deliberately severe
# so an escalation over the deterministic floor is visible in the trace.
# The scanner asks one `choice` question per file, keyed by a content hash, so
# the stub cannot match on question id. Any question id it does not recognise is
# answered with SCANNER_ANSWER, which is how the evasion demo works: a file the
# public patterns do not match still gets classified.
SCANNER_ANSWER = {
    "type": "choice",
    "choice": "instructs_exfiltration",
    "probabilities": {"instructs_exfiltration": 0.93, "documentation": 0.02},
    "confidence": 0.88,
}

ANSWERS = {
    "tool_call_argument_risk": {
        "type": "choice",
        "choice": "reads_sensitive_path",
        "probabilities": {"reads_sensitive_path": 0.91, "benign": 0.04},
        "confidence": 0.86,
    },
    "sensitive_data_exposure": {
        "type": "noul",
        "noul": 0.88,
        "confidence": 0.79,
    },
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        if self.path != "/v1/systemone":
            self._send(404, json.dumps({"error": "no such route"}))
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"

        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not auth[7:].strip():
            self._send(401, json.dumps({"error": "missing bearer token"}))
            return

        if MODE == "401":
            self._send(401, json.dumps({"error": "invalid api key"}))
            return
        if MODE == "429":
            self._send(429, json.dumps({"error": "rate limited"}))
            return
        if MODE == "529":
            self._send(529, json.dumps({"error": "overloaded"}))
            return
        if MODE == "malformed":
            self._send(200, "this is not json{{{", ctype="text/plain")
            return
        if MODE == "slow":
            time.sleep(DELAY)

        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            self._send(422, json.dumps({"error": "request was not json"}))
            return

        # Echo back only the questions that were actually asked.
        asked = req.get("questions", {})
        answers = {}
        for q in asked:
            if q in ANSWERS:
                answers[q] = ANSWERS[q]
            elif q.startswith("f"):
                # A scanner file question.
                answers[q] = SCANNER_ANSWER

        # Loud on stdout so a human running this can see what the agent sent,
        # which is also how you check that redaction did its job.
        print(f"[stub] asked={list(asked)} state_bytes={len(raw)}", flush=True)
        state = req.get("state", {})
        print(f"[stub] state={json.dumps(state)[:400]}", flush=True)

        self._send(
            200,
            json.dumps(
                {
                    "model": req.get("model", "jev-latest"),
                    "answers": answers,
                    "usage": {"input_tokens": 0, "output_tokens": 0},
                }
            ),
        )

    def log_message(self, *_):
        pass  # the prints above are the useful log


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument(
        "--mode",
        default="ok",
        choices=["ok", "401", "429", "529", "malformed", "slow"],
    )
    ap.add_argument("--delay", type=float, default=5.0, help="seconds, for --mode slow")
    a = ap.parse_args()
    MODE, DELAY = a.mode, a.delay
    print(f"[stub] listening on 127.0.0.1:{a.port} mode={a.mode}", flush=True)
    HTTPServer(("127.0.0.1", a.port), Handler).serve_forever()
