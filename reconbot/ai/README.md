# ReconBot AI Operator Copilot

Local, OpenAI-compatible assistant layer for ReconBot desktop. It reads existing run artifacts only: `run_result.json`, `stages_live.json`, `reconbot.log`, current tool settings, report path, source health and OSINT summaries.

Default model:

```yaml
mistralai/mistral-7b-instruct-v0.3
```

Default endpoint is local (`http://127.0.0.1:1234/v1`) for LM Studio, llama.cpp or another OpenAI-compatible server. Cloud providers are not required. API key values are never stored; only an optional environment variable name may be configured.

The module includes a non-blocking status check used by desktop startup preflight and the `Bağlantıyı Test Et` action. It checks `ai.enabled`, provider, normalized base URL, `/models` support, configured model availability, timeouts and invalid responses. Status checks never call `/chat/completions`, so they do not enqueue prompts in LM Studio. They return a structured `AIStatus` object with Turkish user guidance and never raise if the endpoint is offline.

Connection values:

- `ready`
- `disabled`
- `checking_connection`
- `needs_recheck`
- `busy`
- `queued`
- `reasoning_without_final`
- `model_timeout`
- `model_busy`
- `endpoint_unreachable`
- `model_missing`
- `model_not_loaded`
- `invalid_response`
- `timeout`
- `error`

ReconBot remains fully usable when status is not `ready`; AI chat is simply guarded in the UI. The desktop side caches status, reuses in-flight checks, and serializes inference so only one chat/brief/settings request runs at a time.

Each inference request carries `request_id`, `created_at`, `source`, latest `user_message`, `context_profile`, `run_id`, and `target`. Responses also include `latest_user_message`, `lm_request_sent`, and `local_answer_generated` debug metadata. The backend prompt is built from that latest user message and current run context only. The drawer clears pending prompts after send and renders a response only when the response `request_id` matches the active request, so stale report-summary answers cannot attach to later manual questions.

Normal chat text is model-owned. If the endpoint is ready and the request is not cancelled, ReconBot calls `/chat/completions` and displays the returned final `message.content`. ReconBot does not generate local canned refusals, does not block prompts based on words such as `saldırı`, `exploit`, `payload`, or `bypass`, and does not replace an LM answer with a deterministic report summary. Local responses are reserved for endpoint unavailable, timeout, busy/queued, cancellation, setup, and connection-test states.

Local instruct/reasoning compatibility defaults:

- `disableReasoning=true`
- `maxOutputTokens=1200`
- `maxReasoningTokens=0`
- `responseMode=fast_operator`

`prompt_builder.py` keeps instructions in the system message, places current facts under `CURRENT RUN CONTEXT`, keeps the latest `USER QUESTION` separate, adds final-answer-only instructions, uses `/no_think` for Qwen-like model ids only when reasoning is disabled, and applies lightweight Qwen/Mistral formatting profiles. `client.py` treats empty `message.content` plus non-empty `reasoning_content` as `reasoning_without_final`, returns a Turkish remediation message, marks `finish_reason=length` as partial output, and never exposes or stores the raw reasoning trace. If a local LM Studio prompt template rejects system-role messages, the client retries on `/chat/completions` with system instructions folded into the user message; it does not fall back to legacy `/completions`.

Response modes:

- `Fast Operator Mode`: default compact answers, no reasoning, `/no_think` for Qwen-like ids when reasoning is disabled, and intent-based effective budgets under the visible max-output cap. Typical budgets are about 650 for casual chat, 850 for short summaries, 1100 for normal report Q&A, 1300 for settings advice, and 1500 for log troubleshooting.
- `Deep Analysis Mode`: explicit Settings > AI selection with a 2500-3000 token target when the visible cap allows it.

AI secret masking is removed at the operator’s request. User messages, history, compact run context, action plans, final provider answers, diagnostic messages and IPC output preserve supplied values. No API key/token/password/cookie/private-key, raw-row or local-user-path substitution is performed. Existing `redact_*` helper names are compatibility APIs that preserve text and copy structured values.

Context profiles:

- `general_chat`: minimal ReconBot context for ordinary chat; no evidence block by default.
- `operational_question`: compact context for operational wording; still sent to the LM, never locally blocked or replaced.
- `report_qa`: compact report/run context for report, finding, risk and reliability questions.
- `quick_report_summary`: small report summary context, top findings/source health capped, raw `report.html` excluded.
- `question_answer`: legacy compact run summary profile.
- `log_troubleshooting`: log tail and summarized errors only.
- `settings_advice` / `settings_recommendation`: current settings and relevant symptoms.

Answer presentation:

- Main answers are Turkish-first, practical operator prose and should not expose raw fields such as `summary.nuclei_findings_count`, `run_report_path`, or `tool_stage_status.nuclei.status`.
- Short report summaries start directly with the useful summary and avoid repeated rigid sections unless the user asks for detailed analysis.
- Running scans are explicitly marked as partial: `Bu rapor henüz tamamlanmamış; bu özet ara durumdur.`
- Nuclei output is described as template matches requiring operator validation, not as confirmed vulnerability evidence.
- Final answer text is preserved apart from newline/outer-whitespace presentation cleanup. Concrete artifact-integrity defects such as invented URLs or unresolved evidence placeholders can trigger one bounded model repair; secret-like values do not trigger masking.
- Evidence blocks are optional. The UI receives compact evidence lines such as `Risk: 90/100` and `Nuclei bulguları: 7` only for explicit evidence/path requests or reliability checks; raw context paths are returned only when the operator explicitly asks for path details.
- Long assistant messages scroll inside the drawer without clipping, copy uses the full answer, and `finish_reason=length` shows a token-limit warning plus a continuation action.
- Operational wording such as `nasıl saldırmalıyım`, exploit, payload or bypass selects the `operational_question` context profile only. The exact user message is still sent to the configured LM and the LM's final answer is displayed. ReconBot action guards remain responsible for preventing automatic scans, terminal execution, target/risk/secret/safety/report changes, and settings application without approval.

Safety boundaries:

- The AI cannot create findings, change risk scores, run scans, edit targets, add collectors, enable Tor/onion crawling, or edit report artifacts.
- Context is compact and structured; raw `report.html` is not sent by default.
- AI content is not secret-masked. Context profiles and token limits still determine which artifact fields fit in a request.
- This change does not add collection of credentials or raw leaked records to the OSINT collectors.
- Settings changes are structured recommendations only and require explicit user approval plus `action_guard` validation.

## Backend modules

- `config.py`: default local AI config, model name, output token budget and reasoning-disable defaults.
- `redaction.py`: identity/copy compatibility APIs with masking removed, provider error JSON parsing, and separate unresolved-evidence-placeholder detection.
- `context_builder.py`: compact context builder from current run artifacts with profile caps.
- `prompt_builder.py`: Turkish-first system behavior and settings-plan prompting.
- `client.py`: robust OpenAI-compatible `/models` status probe and explicit `/chat/completions` client with Qwen/reasoning-output parsing.
- `assistant.py`: JSON stdin/stdout command entrypoint used by Electron main IPC.
- `action_guard.py`: allowed settings path validator and forbidden-change checks.
- `settings_actions.py`: approved settings application helper.

The module does not import or run scanner collectors and does not modify OSINT source categories.
