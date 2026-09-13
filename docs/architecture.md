# Architecture

Aegis separates planning from evidence validation. The package has one process and no background workers. A planner is a strategy object, not an independently privileged identity.

## Data flow

1. `aws.collect` or an offline lab produces a strict, versioned `Snapshot`.
2. `ReferencePlanner` or `BedrockPlanner` chooses an `Action` from a small vocabulary.
3. `orchestrator.assess` binds resources to the snapshot, rejects repeated actions, and enforces the step budget.
4. `Verifier` evaluates the registered rule and supplies the accepted finding, evidence pointers and remediation text.
5. `reporting` writes portable artifacts. `benchmark` compares finding keys to a separate label manifest.

Ground truth is read only by the benchmark runner. No expected labels, benchmark scores or case descriptions are included in observations. The bundled labs are public training-sized examples; use private held-out cases for credible experiments.

## Contracts and evidence

`models.py` uses Pydantic contracts with strict types and forbidden extra fields. Resource dictionaries contain stable IDs; each resource also carries its AWS ARN. Evidence uses RFC 6901 JSON pointers into the normalized `snapshot.json`. Finding identity is `RULE:resource`, or `RULE:source->terminal` for paths. The graph returns a shortest path per reachable terminal administrator and does not inflate discovery counts with equivalent paths.

Snapshots are canonically serialized before hashing. Every event contains the previous event hash and its own digest. `aegis verify` checks the snapshot, the event chain and the duplicate JSONL export. A person able to rewrite the entire bundle can recompute hashes: these are integrity checks, not signatures or trusted timestamps. Store trusted digests separately or sign artifacts when chain of custody matters.

## Policy semantics

- IAM action matching is case insensitive; resource matching is case sensitive. Only IAM's `*` and `?` wildcard syntax is supported.
- Identity permission and target role trust must both allow each modeled `sts:AssumeRole` edge.
- Unconditional explicit deny overrides allow. Boundary permissions intersect identity permissions.
- Conditions, policy variables, `NotAction`, `NotResource` and `NotPrincipal` remain unresolved. Unknown statements conservatively suppress confirmation.
- Administrator detection requires a universal unconditional `Action=*`, `Resource=*` grant with no limiting boundary or deny in the supported model. It is deliberately narrower than a general privilege-equivalence detector.
- The graph is built once, with quadratic role-pair evaluation and breadth-first search. Path analysis is capped at 250 roles; snapshots at 5,000 resources. Split larger inventories. No cycle can create an infinite traversal.
- Organizations SCPs/RCPs, resource-based direct role-session grants, session policies, account-root delegation and full principal evaluation are outside the model.

These choices prioritize explicit evidence over speculative findings. They create known false negatives; the benchmark must include unresolved and supported cases separately. A completed run means the planner finished, not that every resource or rule was checked. Inspect the trace to measure check coverage.

## Boundaries and budgets

The model only receives catalog IDs, inspected normalized resources, completed check keys and remaining steps. `inspect`, `check`, and `finish` are the only tools. It has no route to the AWS collector. SDK exceptions stop planning; they are not retried by the orchestrator. SDK clients use one attempt, a 10-second connection timeout and 45-second read timeout. Conservative token reservations are checked before each Converse request; service tokenization and overhead may differ, so AWS billing controls remain the source of spending enforcement.

## Extension points

Add a deterministic rule to `RULES` and `Verifier.check`, then add independent positive, negative and uncertainty cases. Extend the normalized schema and collector together. Implement `Planner.next_action` for another provider; preserve the action contract and budgets. Import adjudicated external results through `Run` instead of presenting built-in static checks as a commercial-tool comparison.

## Status

- `configuration_observed`: a configuration fact was verified; exploitation was not attempted.
- `simulated`: an IAM path was proved in a synthetic snapshot declaring complete model controls.
- `needs_review`: live controls or collection context are missing.

Run statuses `completed`, `budget_exhausted` and `planner_error` are distinct. Exit code 0 means the command completed, even when findings exist. Exit code 2 means invalid input, incomplete collection, partial assessment, or failed integrity validation. No findings-based build failure threshold is imposed.
