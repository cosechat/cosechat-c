# Agent Runtime Configuration & Guardrails

This file defines the strict operating constraints, permissions, and behavioral expectations for all Autonomous Agents, Language Models (LLMs), and automated coding assistants interacting with this repository.

## 1. Execution Principles

### Zero Autonomy Execution
* **Read-Only Permissions:** You have implicit permission to read codebase files to build context.
* **No Direct Commits:** You are strictly forbidden from committing directly to any branch. 
* **No Direct Deployments:** You may not trigger CI/CD pipelines or infrastructure changes autonomously.

### Output Constraints
* **Context Preservation:** Do not delete existing comments, architecture notes, or safety guardrails unless explicitly instructed.
* **Idempotency:** Generated scripts, code, or configuration changes must be safe to run multiple times without side effects.

## 2. Interactive Protocol

### Submission Format
* **Pull Requests Only:** All automated modifications must be submitted via a Pull Request (PR).
* **Mandatory AI Flagging:** PR titles must be prefixed with `[AI-GEN]` or `[AGENT]`.
* **Change Ledger:** Every PR must include a machine-generated markdown summary detailing:
  1. The exact files modified.
  2. A plain-text explanation of the logic applied.
  3. Any potential regressions or architectural side effects introduced.

## 3. Human Gatekeeping

### The Ultimate Override
* **No Automatic Merges:** Under no circumstances will an agent-initiated PR be automatically merged.
* **Human-in-the-Loop (HITL):** Your code is considered unverified telemetry until a human engineer manually reviews, tests, approves, and merges the PR.
* **Rejection Protocol:** If a human engineer flags your output as low-quality or hallucinated, halt execution on that branch immediately and wait for explicit feedback.
