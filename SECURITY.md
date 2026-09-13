# Security policy

This project supports authorized security research and defensive assessment. The default lab is synthetic and offline. The live collector contains only allowlisted read operations and cannot be reached by the planner. No live exploit, resource mutation, credential retrieval, shell execution or arbitrary model-selected network request is implemented.

Treat policies, resource names and model responses as untrusted data. The action schema rejects extra fields and unsupported tools, and resource IDs must exist in the loaded snapshot. Deterministic verification owns finding content. Prompt injection may still influence which allowed checks a model chooses or cause early stopping; inspect coverage and retain the event trace. This architecture does not make an LLM immune to prompt injection.

Do not commit credentials, real-account snapshots, or sensitive reports. `.gitignore` excludes `.env`, `snapshots/`, and `runs/`; it cannot prevent disclosure through differently named files. The optional Bedrock mode sends inspected configuration to the chosen model service only after an explicit CLI data-transfer flag.

Reports escape untrusted values in HTML, contain no external scripts or telemetry, and render locally. JSON/Markdown/SARIF are data artifacts; review them before sharing. Hash checks detect inconsistency, not a malicious party rewriting and rehashing every artifact.

For a suspected vulnerability in this project, use the repository's private vulnerability reporting facility if enabled. Do not publish credentials or affected-account data in a public issue. Describe the affected version, a minimal synthetic reproduction and expected impact.
