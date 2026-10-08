# AI Operator Copilot

ReconBot's optional local assistant opens from the RECONBOT AI sidebar card. Scanning, reports, SQL validation and authentication testing work independently of the model server.

This document describes the current implementation. Earlier secret-masking and local conversational-fallback behavior is no longer used.

## Set up a local model

1. Start an OpenAI-compatible model server, such as LM Studio, and load a chat model.
2. Open **Settings → Operator Copilot** in ReconBot.
3. Set **Base URL** (default `http://127.0.0.1:1234/v1`) and select the loaded model. The configured default is `mistralai/mistral-7b-instruct-v0.3`; this is a configuration default, not a model-quality endorsement.
4. Choose **Test connection**, then send a question or use **Explain report**.

ReconBot does not download, install or load model files automatically. Settings are persisted in the application's user-data directory. The shared source of default values and limits is `reconbot/ai/settings_contract.json`.

Test connection and background status checks verify endpoint/model availability; they do not prove technical answer quality. Status checks do not enqueue chat prompts. Loading a report or selecting a historical run does not trigger inference. Report-ready prompts invite the operator to request a summary.

## How questions reach the model

```text
Sidebar/report/chat action
 → preload IPC
 → desktop/src/main/aiAssistant.ts
 → reconbot.ai.assistant
 → context_builder + prompt_builder + request_planner
 → configured local /chat/completions endpoint
 → provider answer + diagnostics
 → chat drawer
```

The messages contain one combined system message, bounded prior user/assistant turns and the exact latest user question. The system message holds operator guidance and relevant reference data, explicitly distinguished from instructions. Request IDs and transport bookkeeping remain diagnostics, not prose added to the user's question. The provider owns its model's chat template.

Context comes from selected run artifacts, relevant findings, stage state, log excerpts and current tool settings. Raw report HTML is not sent by default. A focused finding question includes available evidence and missing evidence fields. Reference data takes precedence over earlier assistant assertions.

`reconbot/ai/prompt_builder.py` defines the guidance. It asks the model to use the user's language, follow requested formatting, avoid inventing artifacts and distinguish unverified matches from exploitation. Relevant questions also receive these product facts:

- A CVE identifier is a record ID, not severity or proof of exploitation. Specific product/version/mechanism attribution requires a supplied verified record. ReconBot does not perform a live CVE web lookup for the conversation.
- Automatic authentication response comparison produces a candidate requiring manual login verification, not accepted credentials.
- SQLmap's Payload field contains the tested parameter assignment and injection expression. Detection does not imply a database dump or change the baseline scan score.
- RCE means remote code execution. A test string appearing in the response is insufficient proof of RCE; missing request/matcher evidence must not be invented.

These are instructions to the model, not guarantees that it will obey them.

## Values, answers and actions

Supplied user/context/history values and final provider answers are preserved without secret masking. The UI provides original provider messages and returned text in Technical details. Markdown and links affect presentation; copied answer text preserves the original values.

A concrete integrity defect can trigger one focused model repair. A successful answer comes from the model or repaired model; ReconBot does not invent a local conversational replacement. If the request or repair fails, it shows a recoverable technical error. This check does not comprehensively validate the factual correctness of every technical explanation.

The copilot does not execute terminal commands, start security tests or rewrite findings/risk scores. Settings recommendations require the operator's explicit approval before eligible settings changes are applied.

## Budgets and recovery

`reconbot/ai/request_planner.py` is authoritative for serialized message budgets. Planning uses the loaded runtime context window when available and records configured/effective values and their sources. It reserves space for system instructions, the full latest question, output and a safety margin; oldest history and injected context can be compacted to fit. Token estimates are conservative estimates rather than the model's exact tokenizer.

Fast Operator, Adaptive and Deep Analysis modes have different allocations. Output/context/timeout settings and provider capabilities constrain the request. A server may still be slow or incompatible despite a successful connection check.

The chat shows request status and cancellation controls. Recoverable errors offer retry, draft restoration and copy. A new chat clears conversation memory without deleting scan artifacts or changing the selected target. Reasoning-only output without a usable final answer is classified as a format failure; thinking text is not substituted for the final answer.

Technical details include the selected model/endpoint, request plan, exact latest user message, answer source, HTTP/finish status, history compaction and repair diagnostics. These help distinguish network failure, context limits, incompatible output and model quality.

## Actual live acceptance status — 8 October 2026

Natural Turkish operator conversations were run through Electron, Python and the user's local LM Studio server. Questions covered report evaluation, false positives, a selected finding, next steps, CVE identity, authentication candidates and SQL payload interpretation. Original questions, provider messages and returned/displayed answers were recorded locally.

Mistral 7B completed both conversations but gave incorrect CVE identities, inverted a negative instruction and confused authentication candidates with confirmed login. Existing Qwen 3.5 9B Q4 produced clearer Turkish but also gave incorrect CVE attribution and reflection-based RCE verification advice; its critical conversation then exceeded the harness wait on a later turn. A final two-turn Qwen rerun completed in 8.4 minutes with clearer template-first advice but still unreliable reflection-based verification reasoning. **Neither model has passed semantic release acceptance.** Prompt clarification alone did not establish reliability.

See the [verification record](testing.md) for final runs and package evidence. Transcripts and screenshots remain in ignored local test-results; they are not public release material. Automated transport/raw-display checks are separate from manual semantic review.
