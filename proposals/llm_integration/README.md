LLM Integration Proposal — Non-invasive review

Purpose

This folder contains a set of non-invasive proposal artifacts that describe how to add an LLM backend abstraction to SploitGPT so you can use Opencode's default API models (or other providers) without breaking current behavior. Nothing in this directory modifies existing code — it's for review only.

Contents

- llm_abstraction.py — Concrete implementation sketches: BaseLLMClient, OllamaAdapter, OpencodeAPIClient, and factory get_llm_client().
- agent_patch.diff — Proposed patch to replace direct `OllamaClient` usage in `Agent._call_llm` with `get_llm_client()`.
- boot_patch.diff — Proposal for updating boot LLM checks to use the client abstraction's health_check.
- tests/test_llm_abstraction.py — Pytest-style tests to validate Opencode client behavior (mocked HTTP). For review; they are not run automatically.
- notes.md — Rollout plan, safety checklist, and how to apply patches.

How to review

Open files and verify the approach and the code sketches. If you approve, I can either apply the changes as a PR or implement them behind a feature flag in a branch for further testing.

If you want changes or more detail in any piece (authentication, function-calling capability sampling, TUI commands), tell me which and I will refine the proposal.
