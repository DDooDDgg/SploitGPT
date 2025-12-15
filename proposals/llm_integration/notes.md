Notes / Rollout Plan / Safety Checklist

1) Purpose

- Provide a safe, reviewed proposal to add pluggable LLM backends (Opencode, Ollama, etc.) while keeping current behavior unchanged.

2) Files in this proposal (read-only in `proposals/llm_integration`)

- `llm_abstraction.py` — the core abstraction and two example adapters (OllamaAdapter and OpencodeAPIClient).
- `agent_patch.diff` — sample diff showing the minimal change to `Agent._call_llm` to use the factory.
- `boot_patch.diff` — sample diff showing how to call `health_check` via the factory.
- `tests/test_llm_abstraction.py` — a small pytest that validates Opencode adapter behavior using `httpx.MockTransport`.
- `README.md` — this file describing the proposal.

3) Safety checklist (do not merge until all checks pass)

- [ ] Smoke test: run existing test suite; ensure no regressions.
- [ ] Integration test: run agent with Ollama still as default and confirm behavior unchanged.
- [ ] Access control: ensure API keys are only read from env (`.env`) and not logged.
- [ ] Capability flags: mark whether a backend supports function-calling tools; do not expose unsupported features.
- [ ] Error handling & timeouts: test 401/429/timeout scenarios and present user-friendly errors.

4) How to apply

- If you like the proposal, I can:
  a) Implement Option 1 in a feature branch, add unit/integration tests, and open a PR for review.
  b) Or implement the minimal Option 2 change and tests as a short-term patch.

- To try locally without changing current code, you can copy `proposals/llm_integration/llm_abstraction.py` into `sploitgpt/core/llm.py` and apply the patches under `agent_patch.diff` & `boot_patch.diff` in a feature branch.

5) Next steps

Tell me whether you'd like me to implement Option 1 as a branch and PR (recommended) or produce a minimal inline change (Option 2). I will then run tests, add docs to README, and update `.env` examples accordingly.
