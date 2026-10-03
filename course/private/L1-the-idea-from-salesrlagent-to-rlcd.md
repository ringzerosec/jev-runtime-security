# L1 — The idea: from SalesRLAgent to RLCD

> **Laya track, chapter 1 of 10.** Goal: before reading a line of Laya's code,
> understand the *idea* it implements — where it came from (a 2025 paper by the
> same author), what a "System 1 decision model" is, and the three design moves
> that turn the paper's prototype into something you can ship on a laptop. By the
> end you should be able to say, in one sentence each, what Laya *is* and what it
> deliberately *is not*.

## L1.1 The problem both the paper and Laya attack

Most "AI decides something" systems do it by **asking a language model to write
the answer** — a next-token model generates text, and you parse a decision out of
it. That has three costs that matter when the decision has to be made constantly,
fast, and under adversarial pressure:

1. **Latency.** Generation is autoregressive — one token at a time, hundreds of
   milliseconds to seconds.
2. **No real probability.** "I'm 90% sure" from a chat model is prose, not a
   calibrated number. You can't threshold it honestly.
3. **Persuadability.** The thing deciding also *reads instructions*, so the input
   can argue with it. In a security setting that is the attack surface.

The alternative is a **System 1** model: read the situation once, in a single
forward pass, and emit a **distribution over a fixed, small set of options**. No
generation, no text channel to argue through, and — if you train it the right way
— probabilities that mean what they say.

## L1.2 The paper: SalesRLAgent (arXiv 2503.23303, Mar 2025)

Nandakishor M's paper is the prototype. Strip away the sales vocabulary and it
says: treat a sequential task as a **sequential decision problem** —

- **states** = the situation at each turn (an embedding of the history plus
  engineered features),
- **actions** = probability estimates,
- **reward** = how accurate the estimate turned out to be.

The architecture is a **state encoder → policy network** (the probability) **+
value network** (expected cumulative reward) **+ a meta-learning module** that
estimates the model's own confidence from similarity to training data, ensemble
agreement, and novelty. Trained on 1.2M synthetic conversations on CPU in ~6
hours; served at **85 ms on CPU** against 3,450 ms for GPT-4; 8-bit quantized
with incremental state updates. Ablations: sequential modelling worth −10.7
points if removed, meta-learning −2.7.

Two ideas from it survive unchanged into Laya and into our brain:

- **A decision is a distribution over options, produced in one pass.**
- **The model should know when it doesn't know** — and say so as a number.

Read it as a design pattern, not an evidence base: single author, no code, the
reward and algorithm never written down, headline numbers on a private
synthetic benchmark. The *shape* is what matters.

## L1.3 The three moves that make Laya

Laya (`convaiinnovations/laya`, Apache-2.0) is the same author making the
prototype rigorous and local. Three changes carry all the weight:

**Move 1 — Own the encoder.** The paper used a hosted embedding API (Azure
OpenAI, 3072-d). Laya replaces it with a **bidirectional transformer encoder you
run yourself** — ModernBERT-large (421M) for English, mmBERT-base (322M) for
100+ languages. No network call, no vendor in the loop, exportable to ONNX. For a
product whose rule is "nothing leaves the machine," this is the move that makes
it usable at all.

**Move 2 — Typed questions, scored at markers.** Instead of a single "conversion
probability" head, Laya answers **typed questions** — `choice` (pick one of K),
`score` (an ordinal level 0..K−1), `noul` (a yes/no statement) — and it does it by
**writing the options into the input sequence** and scoring each at its own
`[MASK]` position (Chapter L2). The same model answers any question you can
phrase as a small option set. That is why our 13 enforcement categories are 13
question templates, not 13 models.

**Move 3 — A strictly proper scoring rule as the objective.** The paper's "reward
measures accuracy" becomes a precise thing: the model is trained to maximize a
**strictly proper scoring rule** (log score + spherical score, plus a ranked
probability score for ordinal questions — Chapter L4). A strictly proper rule has
one property that is the whole reason to use it: *the expected score is
maximized only by reporting your true belief.* Honest probabilities aren't a
hope; they're the optimum. Laya calls this training recipe **RLCD**, and it
reports **ECE** (expected calibration error) as a first-class number — 0.081 on
its benchmark versus 0.246 for the hosted alternative it compares against.

And one thing it kept from the paper: an explicit **"act or escalate"**
decision. The model has a second head that, given how peaked its own
distribution is, decides whether to answer or to escalate — with costs set in
the config (`act_costs: {escalate: 0.5}`, `cost_wrong_act: 3.0`). That is the
paper's meta-learning module, implemented as decision theory (Chapter L3, L5).

## L1.4 What Laya is, and is not

- **Is:** an encoder + typed decision heads; one forward pass; a calibrated
  distribution over options; ~33 ms on a GPU, ~160 ms on a laptop CPU as int8;
  fine-tuneable on your own labelled rows; self-hosted.
- **Is not:** a language model. It cannot write, explain, or follow an
  instruction embedded in the state. That limitation is a *feature* for a
  security brain: there is no text channel through which an input can talk it out
  of a verdict. (The judgment tier that *can* explain itself is a different,
  off-device model — `THE-BRAIN.md`.)

## L1.5 The map of the track

| Chapter | What you read | The question it answers |
|---|---|---|
| L2 | `common.py` — `render_options`, `build_head`, `build_sequence` | How does a question become encoder input, and where do the options live? |
| L3 | `common.py` — `DecisionModel`, `build_model` | What does the forward pass compute, marker by marker? |
| L4 | `common.py` — `proper_reward`, `td_lambda_targets`; the trainer's loss step | What is the objective, and what is "RL" doing in it? |
| L5 | `common.py` confidence/temperatures; `calibrate.py`; `confidence.py` | Why does 0.9 mean 0.9, and what happens when the model isn't sure? |
| L6 | `agent.py` — `load`, `Agent`, `predict*`, `decide`; `shortlist.py`, `structured.py` | How does a request flow through the runtime? |
| L7 | the MPS trainer; our `laya_feed.py` | How do you actually train it, on what, on this machine? |
| L8 | `evals.py`; our `laya_eval.py` | How do you know it works — and know when it doesn't? |
| L9 | `export_onnx.py`, `onnx_agent.py`, `fast.py`, `serve.py`, `router.py` | How does it ship? |
| L10 | `checks/src/registry.rs`, `write_scan`, `THE-BRAIN.md` | How does it become the brain of Ring Zero? |

## Try it

Everything in this track runs in the venv already on this machine:

```sh
~/laya-venv/bin/python -c "
import laya
a = laya.load('/Users/jarvis/laya_base/typed-decisions', device='cpu')
print(a.predict({'situation': 'the agent opened ~/.aws/credentials and base64-encoded it'},
                {'exfil': {'type': 'score',
                           'instructions': 'Is data being staged or sent outside its boundary?',
                           'criteria': ['none', 'staging_for_exfiltration', 'exfiltration']}}))
"
```

Look at the shape of the answer: a `score`, a `legend`, `probabilities` over the
three levels, two confidences, and an `action`. By L5 you will know what every
one of those numbers is and which of them you may threshold.

## Exercise

1. In one sentence each: what is a System 1 decision model, and why can't a
   next-token model be made into one by fine-tuning?
2. Of the three moves (own encoder / typed markers / proper scoring rule), which
   one makes Laya *shippable on an endpoint*, which makes it *reusable across
   questions*, and which makes it *trustworthy as a number*?
3. Why is "it cannot follow an instruction in the state" a feature here?

---

Next: **[L2 — A question becomes a sequence](L2-a-question-becomes-a-sequence.md)**.
