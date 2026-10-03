# L4 — The objective: proper scoring rules and RLCD

> **Laya track, chapter 4 of 10.** Goal: understand *what the model is being
> paid for* during training — why the target is a probability distribution and
> not a label, what makes a scoring rule "strictly proper," why the ordinal
> `score` type needs its own rule, and what the "RL" in RLCD is actually doing.
> This chapter is deliberately **math-and-concepts only.** The implementation
> — `proper_reward` (`common.py:604`), `td_lambda_targets` (633), and the
> trainer's loss step (`laya_finetune_typed_decisions_mps.py` ~300–337) — is
> short, and you will get more from reading those forty lines yourself with
> this chapter beside you than from a paraphrase. The exercises at the end are
> how you check you read them.

## L4.1 Why the target is a distribution

L7's gold contract makes every training item a **probability vector over the
options**, normalized, with `label = argmax`. A classifier trained with plain
cross-entropy against the argmax would learn to *rank* options correctly; it
would not learn to *report how sure it is* in a way you can act on. We need the
second thing, because the whole enforce/contain/review policy (`THE-BRAIN.md`
§5, P1) is a threshold on reported confidence. So the training signal has to
reward the model for being **honest about uncertainty**, not just for being
right.

The tool for that is a hundred years old: a **proper scoring rule**.

## L4.2 Proper scoring rules, in one page

A scoring rule `S(p, y)` pays a forecaster who announced distribution `p` when
outcome `y` happened. It is **proper** if, whenever the truth is distributed as
`q`, the expected payout is maximized by announcing `p = q` — you cannot gain
by shading your forecast. It is **strictly proper** if `p = q` is the *unique*
maximizer: every lie costs something.

Three classical strictly proper rules, over `k` options:

| Rule | Pays | Character |
|---|---|---|
| **Logarithmic** | `log p_y` | Unbounded penalty for putting ~0 on the truth; the rule behind cross-entropy. Punishes confident wrongness hardest. |
| **Spherical** | `p_y / ‖p‖₂` | Bounded in `[0, 1]`; gentler at the tails; still strictly proper. Stabilizes training where log alone would blow up on a single bad item. |
| **Ranked probability score (RPS)** | `−Σ_j (F_j − 𝟙[y ≤ j])²` over the **cumulative** distribution `F` | The one that knows the options are **ordered**. Putting mass on the neighbour of the truth is penalized less than putting it on the far end. |

Why RPS exists: for `choice` the options are nominal — "apple vs car" has no
*nearer* wrong answer. For `score` the options are **ordinal** (`none →
staging → exfiltration`; `benign → referenced → accessed`). A model that says
"staging" when the truth is "exfiltration" is *less* wrong than one that says
"none," and log/spherical cannot express that: they only look at `p_y`. RPS
looks at the cumulative mass on each side of the truth, so it rewards being
*close* on the scale. That is exactly the shape of our 13 categories — every one
is a severity ladder — which is why our feeder (L7) emits them as `score` and
why the option *order* in `schema.py` is load-bearing: it is the metric the
objective is computed over.

Laya's `proper_reward` combines rules of these three kinds, with RPS entering
only for the ordinal type. **Which rules, how they are weighted, and how the
type gates them is in the function — read it** (exercise 1).

## L4.3 What "RL" is doing here (RLCD)

The decision is a single step: emit a distribution, get paid by the rule. There
is no environment to roll out, so why reinforcement learning at all?

Because a proper score is a **reward**, not a differentiable loss on a label.
You *can* differentiate `log p_y` directly (that's cross-entropy), but the
spherical and RPS terms are functions of the whole vector, and treating the
combined score as a reward lets the trainer optimise it the way you optimise
any reward: a **policy-gradient-style update with a baseline**. In the trainer's
step the logits are perturbed several times with Gaussian noise, each perturbed
distribution is scored, the scores are **normalised across the perturbations**,
and the model is pushed toward the perturbations that scored above their peers.
The thing being estimated by that normalisation is an *advantage* — "better
than what I'd typically have said here" — which is what removes the variance a
raw reward would carry. The perturbation scale **shrinks across epochs**:
explore the neighbourhood early, refine late.

This is the direct descendant of SalesRLAgent's conversion-probability training
(L1, P3): a state encoder emitting a probability, trained against an outcome
with an RL-flavoured objective and a confidence estimate on top. Laya's move was
to make the "outcome" a *typed decision* and the reward a *proper rule*, so the
same machinery produces calibratable confidences for arbitrary questions.

`td_lambda_targets` (633) is the second RL idea: for **sequences** of decisions
(a multi-turn session, several dependent questions), targets can be
bootstrapped across steps with a λ-weighted mixture, the standard TD(λ)
construction. Our per-artifact reflex is single-step and doesn't use it; the
session-level judgment tier would. Know it exists and what it is for.

## L4.4 Two loss terms

The trainer's step adds two terms. One is the RL term above (the proper score as
reward, baseline-normalised over perturbations). The other is a **supervised
anchor** on the unperturbed logits against the gold distribution. Hold the two in
mind as *exploration* and *anchor*: without the first, you have a cross-entropy
classifier whose confidences are whatever fell out; without the second, a
reward-only objective on nine rows can wander — the anchor keeps the
unperturbed forward pass tied to the target. The act head (L3) is trained
alongside under its asymmetric costs (`escalate: 0.5` vs `cost_wrong_act: 3.0`):
wrongly answering costs six times more than escalating.

Which term is which, how they are weighted, and what the act head's loss looks
like in the step: **read ~300–337 and answer exercise 3.**

## L4.5 What the objective does and does not give you

- It gives you a model whose *raw* distribution is pushed toward honesty. It
  does **not** give you calibration for free: the proper score is optimised on
  the training rows, and the shipped `answer_confidence` is only trustworthy
  **after temperature scaling on held-out data** (L5). Objective first,
  calibration second, threshold third — never skip the middle.
- It gives you *ordinal awareness* for `score` questions. It does **not** know
  that index 2 means "set the enforce bit." Severity semantics live in
  `schema.py` and `THE-BRAIN.md`; the objective only knows "closer is better."
- Soft gold (`{"1": 0.3, "2": 0.7}`) is first-class: a proper rule scores a
  distribution against a distribution naturally. Use it when two reviewers of a
  miss disagree instead of forcing a label.

## Where this lives

- `laya/common.py` — `proper_reward` (604), `td_lambda_targets` (633).
- Trainer: `laya_finetune_typed_decisions_mps.py` — the loss step (~300–337),
  `build_training_item` (58) for the gold contract it consumes.
- Background (public): Gneiting & Raftery, *Strictly Proper Scoring Rules,
  Prediction, and Estimation* (2007); Epstein (1969) for RPS; Sutton & Barto
  ch. 12 for TD(λ); Williams (1992) for REINFORCE-with-baseline.
- Ours: `models/schema.py` (`OPTIONS` order = the ordinal metric),
  `models/THE-BRAIN.md` §5 (why calibrated confidence is the product).

## Exercise (answer from the source, in your own words)

1. Open `proper_reward`. Name the three scoring rules it combines and write
   each one's formula from memory. Which question type gets RPS, and what would
   go wrong — concretely, for `exfiltration` — if `score` questions were scored
   with log alone?
2. In the trainer's step, say what quantity the normalisation across perturbed
   samples estimates, why it lowers variance, and what you would expect to
   change if the perturbation scale did *not* shrink across epochs.
3. Identify the two loss terms and the act-head term. For each, state what
   breaks if it is removed. Then say which term you would scale up if the model
   were under-confident on held-out rows — and why the honest answer is "none;
   fix it in calibration."
4. Prove (two lines) that the logarithmic rule is strictly proper: show the
   expected score under truth `q` is maximised uniquely at `p = q`.
5. Our seed rows skew severe (L8). Under a proper scoring rule, does that bias
   the *confidence* the model learns, the *ranking*, or both? What does the
   shuffled-context control measure that this question does not?

---

Next: **[L5 — Calibration, confidence, and abstention](L5-calibration-confidence-and-abstention.md)**.
