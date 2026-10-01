---
name: fixture-probe
description: Activate only for the deterministic Kimi adapter native-surface probe.
type: prompt
when-to-use: The local fixture provider requests the fixture-probe skill.
disable-model-invocation: false
---

This is a run-local, credential-free conformance fixture. After activation,
return the exact text `fixture-skill-loaded` and do not access the network or
any path outside the current probe workspace.
