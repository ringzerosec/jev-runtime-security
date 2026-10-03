# Private research track — model IP, never in a public zip

The public course (Chapters 1–17, `../`) teaches the open-source kernel
enforcement and userspace. **This directory is different: it is model IP.** It
documents the brain — the decision model, why it is the product's USP, where
its authority comes from, the research it is built on, and the lab plan. Per the
rule set on 2026-10-03, anything related to model IP lives only in the private
fork (`abhiabhijit/jev-runtime-security`, branch `models-rnd`) and is **never
pushed to the public upstream and never included in a zip handed to learners.**

| Chapter | What it teaches |
|---|---|
| [P1 — The brain: where a decision model fits](P1-the-brain-where-a-decision-model-fits.md) | the indirect-attack gap a rule can't see; System 1 vs System 2; 13 categories = one model; where the model may act and the one place it may not; tighten-only ≠ advisory-only; the calibrated-confidence tiers; shipped vs designed |
| [P2 — Why the state space doesn't hit the model](P2-why-the-state-space-does-not-hit-the-model.md) | the standard doubter's objection ("millions of states / changing context / OOD / persistent state") answered clause by clause from the mechanisms; where state actually persists; the real gaps and why a bigger model fixes none of them; **the eight-question drill** |
| [P3 — Research basis and the lab plan](P3-research-basis-and-the-lab-plan.md) | SalesRLAgent → Laya → the brain; what transfers and what doesn't; what we have *measured* on our own hardware (and its honest label); the six-stage lab plan for Inception compute; why we don't pretrain a System 1 now |

Read P1 → P2 → P3. The drill in P2.8 is the test: if you can answer all eight
cold, you can defend the design to anyone.

## Producing the public zip (learners get this; never the directory above)

From the repo root, excluding this track *and* the lab build artifacts:

```sh
cd /Users/jarvis/rgs/rgs-linux-oss
zip -r ~/Desktop/ring-zero-course.zip course \
  -x "course/private/*" \
  -x "course/labs/*/vmlinux.h" -x "course/labs/*/*.o" -x "course/labs/*/target/*" \
  -x "course/labs/00-setup/hello" -x "*.DS_Store"
unzip -l ~/Desktop/ring-zero-course.zip | grep -c "course/private/"   # must print 0
```

The last line is the check. If it prints anything but `0`, do not send the zip.
