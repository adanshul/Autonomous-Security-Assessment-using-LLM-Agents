# Study protocol

## Questions and preregistration

The primary question is whether LLM-directed assessment improves recall at a prespecified minimum precision relative to a named static tool and qualified human participants under matched conditions. A secondary question is whether it reduces time to a correct, reproducible report. A 30% relative recall improvement is a target, not repository evidence.

Before collecting results, record hypotheses, primary endpoint, baseline versions, model IDs/inference profiles, prompts, budgets, inclusion rules, stopping criteria and analysis plan. Preserve a configuration and source revision for every run. Do not select only successful trials or change labels after viewing model performance without recording the adjudication.

## Dataset and ground truth

Build a held-out corpus of isolated AWS lab configurations spanning positive, negative, ambiguous, conditional and multi-step cases. Use independent reviewers and AWS authorization checks where appropriate to establish the ground truth. Record uncertainty separately. Keep labels and review notes outside the planner's snapshot. Public bundled labs are a synthetic regression suite and cannot establish generalization.

Label discovery units consistently. A source-to-terminal role escalation is one finding even if several routes exist. Keep configuration weaknesses distinct from demonstrated exploitation. The current harness scores accepted finding keys; false hypotheses rejected by the verifier are visible in the trace but are not accepted findings.

## Baselines

- `static` is the built-in single-resource ablation. It shares verifier logic with `reference`, so their difference measures graph coverage, not LLM intelligence.
- `reference` is deterministic and must never be described as an LLM trial.
- Run real models separately and import their exported records under provider/model/trial identifiers.
- Run independently versioned static tools on the same scoped environment. Adjudicate and map their output to the common finding keys, including valid out-of-label findings after review.
- Recruit consented human testers with documented experience. Assign cases in a randomized crossover or blocked design. Provide equivalent scope, documentation and time budgets. Avoid exposing ground truth or previous reports.

## Imported run format

`aegis benchmark --runs observations.json --candidate human --out runs/study` reads a JSON array. The following illustrates the shape; replace the digest with the normalized snapshot SHA-256 and record actual observations. Example numbers are not study data.

```json
[
  {
    "case_id": "exposed",
    "participant": "anonymized-participant-01",
    "method": "human",
    "snapshot_sha256": "REPLACE_WITH_THE_64_CHARACTER_SNAPSHOT_HASH",
    "finding_keys": ["IAM_ADMIN:admin"],
    "elapsed_seconds": 600.0,
    "report_seconds": 180.0,
    "status": "completed"
  }
]
```

`elapsed_seconds` is wall time from assessment start to discovery stop; `report_seconds` is the separately measured time to finish a reviewable report after discovery. Unmeasured report time must be null. `export-run` leaves report time null because rendering duration is not human authoring time. To compare human and Bedrock runs, import both groups and select `--baseline human --candidate bedrock`. The CLI also runs its built-in baselines, reported separately.

Unknown cases, duplicate method/participant/case observations and snapshot hash mismatches are rejected. Duplicate finding keys within a run are deduplicated. Missing cases are not silently scored as failures; paired coverage is shown explicitly. Incomplete runs remain included and counted as incomplete, avoiding optimistic exclusion of failed trials.

## Metrics

- Precision = TP / (TP + FP); recall = TP / (TP + FN); F1 = 2TP / (2TP + FP + FN).
- Undefined ratios are null, including recall for a case with no positive labels. Negative cases still contribute false positives.
- Micro metrics pool finding counts. Macro recall averages participants within cases, then averages labeled cases equally.
- Relative recall lift = (candidate recall - baseline recall) / baseline recall on matched labeled cases. When baseline recall is zero, lift is null, not infinity.
- The paired bootstrap resamples case-level mean recall differences 2,000 times with a recorded seed and reports a percentile 95% interval. Negative-only cases are excluded from recall differences but remain in precision counts.
- Timings are observational medians. Collect model usage/cost and report quality in a separate study ledger; there is no automatic currency price estimator.

This simple case bootstrap does not fully model participant clustering, learning effects, model stochasticity or nested trials. Use a preregistered hierarchical analysis for publishable human/LLM comparisons. A small synthetic suite's interval has no external-validity interpretation.

## Report quality and reproducibility

Have blinded reviewers score technical correctness, evidence completeness, reproducibility, remediation specificity and unintended-impact awareness. Time is meaningful only for reports that pass a stated quality threshold. Preserve original tool output, adjudication decisions, hashes, prompts, source revision and trial budgets. Publish anonymized data where consent permits.

## Honest project/resume language

Until a study is completed: "Built a Python framework for evaluating LLM-directed AWS security assessments, with bounded orchestration, evidence-backed IAM path analysis, and reproducible static/model/human benchmark imports."

After the study, report the actual denominator, sample size, model, baseline, interval and conditions. Do not replace an unachieved 30% target with a synthetic ablation result or describe imported example timings as empirical findings.
