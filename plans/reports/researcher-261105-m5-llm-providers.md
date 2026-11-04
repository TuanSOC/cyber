# M5 LLM Providers: Research Report (2026-11-05)

Sources: platform.claude.com docs (models, pricing, rate-limits, citations, refusals, data-retention) and aistudio.google.com docs (models, pricing, structured-output, safety, rate-limits, terms). **[?]** = not confirmed.

## 1. Anthropic

**Models (live docs).** The 5.5 generation is current: 1M context, 128K output, adaptive thinking.

| Model | ID | $/MTok in/out | Note |
|---|---|---|---|
| Opus 5.5 | `claude-opus-5-5` | 4 / 20 | thinking can't be disabled; effort default `medium` |
| Sonnet 5.5 | `claude-sonnet-5-5` | 2 / 10 | **suggested default** |
| Haiku 5.5 | `claude-haiku-5-5` | 0.10 / 0.50 (≤100K prompt), 0.50 / 2.50 above | |
| Haiku 4.5 (legacy) | `claude-haiku-4-5` (`-20251001`) | 1 / 5 | 200K context |

`claude-sonnet-5` is now legacy. Batch is 50% off. Keep model IDs in config.

**Structured output.** Use `output_config.format` (JSON schema). In Python, `client.messages.parse(output_format=PydanticModel)` validates the result for you.
- Every object needs `additionalProperties:false`.
- Not supported: recursion, `min/maxLength`, `minimum/maximum` (the SDK strips them and checks client-side).
- Schemas compile once and are cached for 24h.
- Check `stop_reason` (`refusal`, `max_tokens`) before parsing.
- Opus 5.5 returns 400 on forced `tool_choice`, so use `output_config` rather than tool-as-schema.

**Native citations.** Custom-content `document` blocks give one content block per record, and the model cites them by `content_block_location`. This works under ZDR. However, **citations + `output_config.format` returns a 400**. Decision: put `evidence_refs[]` in the schema and validate them in code. Native citations remain an option for M6 prose reports.

**Refusals (DFIR risk).** The 5.5 models run safety classifiers. A `cyber` refusal comes back as HTTP 200 with `stop_reason:"refusal"` and `stop_details.category`. The docs say benign security work can trigger it, and malware strings or exploit payloads are likely triggers. Cyber refusals before any output are not billed. Mitigations:
- Send `fallbacks:"default"` with beta `server-side-fallback-2026-07-01`.
- Map the refusal to a typed `ProviderRefusal` → status `refused`; never retry in a loop.
- Defang payloads before sending (`hxxp`, `[.]`, truncated blobs).

**Caching, tokens, streaming.**
- Put `cache_control` on the frozen system prompt; the evidence pack goes after it. The cache minimum is roughly 286–512 tokens on 5.x. Cache reads don't count toward ITPM.
- `messages.count_tokens` is free and covered by ZDR. Never use tiktoken.
- Stream (`.stream().get_final_message()`) whenever `max_tokens` is above 16K. Thinking is billed as output and counts toward `max_tokens`, so allow 16–32K.

**Rate limits and errors.** Start tier for the 5.5 models: 4K RPM, 2M ITPM, 400K OTPM per model. Headers are `anthropic-ratelimit-{requests,input-tokens,output-tokens}-{limit,remaining,reset}` plus `retry-after`.
- 429: honor `retry-after`.
- 429 with `details.error_code=enforced_spend_limit_reached`: monthly spend cap. No `retry-after`; do not retry.
- 529 overloaded: retry with backoff.

The SDK retries twice by default; Celery owns retries beyond that.

**Retention.** No training without permission. Content is not retained by default except for Covered Models (Fable/Mythos), which require 30 days, so **don't offer Fable**. ZDR comes through sales and covers messages, count_tokens, citations and structured outputs (the schema is cached 24h). Batch and Files are not ZDR. Never put case data in schema `enum`/`const`. The exact abuse-log period is **[?]**.

**SDK.** Use the official `anthropic` SDK (`AsyncAnthropic`) for typed errors, `parse`, retries and version headers. Docs examples now send `anthropic-version: 2026-10-21` **[?]**. SDK 1.x needs Python ≥3.10 (we run 3.12) and moved to `httpx2`, so the repo's `httpx.MockTransport` pattern may not plug in **[?]**. Mock at the provider interface instead.

## 2. Gemini

**Models [? volatile].** Stable: `gemini-4-argon` (flagship), `gemini-3.8-flash` (recommended default), `gemini-3.6-flash`, `gemini-3.5-flash-lite`, `gemini-3.1-flash-lite`. `gemini-2.5-pro` and `gemini-2.5-flash` auto-route to newer models from 2026-12-01.

Paid pricing per MTok:
- 3.8 Flash: $0.75 / $3.75 until 2026-12-31, then $1.50 / $7.50.
- 4 Argon: $2 / $10 until 2026-11-30, then $4 / $20.
- Batch: 50% off.

**API.** Google recommends the new **Interactions API**: `client.interactions.create(model, input, response_format={"type":"text","mime_type":"application/json","schema":M.model_json_schema()})`. `generate_content` (`response_mime_type` + `response_json_schema`) is "fully supported". I prefer the stateless `generate_content` **[?]**.
- Supports `minimum/maximum/minItems`; strips `minLength`.
- Big or nested schemas return 400 `INVALID_ARGUMENT`.
- Only JSON syntax is guaranteed, so always re-validate with Pydantic.

**Safety.** Adjustable filters (including "Dangerous") are Off by default on 2.5+. A block is an HTTP 400 with `safety`/`jailbreak`/`prohibited_content`; map it to `ProviderRefusal`. Leave the filters off.

**Rate limits.** RPM, input TPM and RPD (RPD resets at midnight Pacific). Tiers: free, Tier 1 (billing on), Tier 2 ($100 spent + 3 days), Tier 3 ($1K spent + 30 days). Over the limit: `429 RESOURCE_EXHAUSTED` with no documented retry header, so use exponential backoff with jitter.

**SDK.** `google-genai` (`client.aio` for async). Not the deprecated `google-generativeai`.

**⚠ Privacy.** On the free tier ("Unpaid Services"), Google uses prompts and responses to improve products, human reviewers may read them, and the terms say "Do not submit sensitive, confidential, or personal information". The paid tier has no training use, only limited abuse logging. EEA, UK and Swiss users get paid-tier terms everywhere.

**Requirement:** the Gemini provider refuses to run unless `GEMINI_BILLING_ENABLED=true`, and the UI shows a privacy notice.

## 3. Cost per analysis

The evidence pack is compact JSON-lines with short IDs:
- 200 findings ≈ 90 tokens each ≈ 18K.
- 500 IOCs ≈ 45 tokens each (hashes tokenize badly) ≈ 22K.
- Flows ≈ 5K.
- Prompt + schema ≈ 3K.
- **Input ≈ 48K.** Output (JSON + thinking) ≈ 10K.

| Model | ≈ $ per run |
|---|---|
| Opus 5.5 | 0.39 |
| Sonnet 5.5 | 0.20 |
| Haiku 5.5 | 0.01 |
| Gemini 3.8 Flash | 0.07 → 0.15 after promo |
| Gemini 4 Argon | 0.20 → 0.40 |

Measure with `count_tokens` and persist `usage` per run (an `ai_runs` table).

**Budgeting.**
1. Build the pack deterministically: dedupe, sort by severity and time, assign short IDs (`F12`/`I45`/`N7`), and keep the ID → UUID map server-side.
2. Hard cap of about 80K input tokens (under Haiku 5.5's 100K price step). Above that, map-reduce: chunk by host or time window (~40K each), run a cheap model on each chunk, then reduce on the main model with the partial results plus the top-N critical records.
3. Truncate payload snippets to 256 chars and use aggregates for long tails.
4. Record `truncated` and omitted counts in the run and show them in the UI. No silent truncation.

## 4. Output contract

One Pydantic `AnalysisResult` for both providers. Each claim has:

| Field | Type |
|---|---|
| `observed_evidence` | `[{statement, evidence_refs[]}]` |
| `interpretation` | text + refs |
| `hypothesis` | text |
| `confidence` | enum `low`/`medium`/`high` (portable across providers) |
| `next_steps[]` | list |
| `attack_techniques[]` | ATT&CK ID + refs |

**Post-validation:**
- Every ref must exist in the pack. Drop or flag evidence with no valid ref; this is how "must not invent evidence" is enforced.
- ATT&CK IDs are checked against the local STIX data.
- No tools and no network for the model.
- Evidence goes in delimited untrusted-data blocks (see `researcher-261105-m5-injection-eval.md`).

## 5. Offline and dev mode

- `LLMProvider` Protocol: `async analyze(pack, schema) -> ProviderResult(parsed, usage, model, raw)`. Implementations: `AnthropicProvider`, `GeminiProvider`, `FakeProvider`.
- **FakeProvider** is the default when `AI_PROVIDER=fake` or no key is set. It deterministically cites the top findings and is used in CI, integration and e2e tests.
- **Recorded fixtures:** an opt-in script records sanitized real responses to `tests/fixtures/llm/`. Replay tests exercise parsing and error mapping (refusal, 429, 529, safety-400, max_tokens).
- Live tests run only with `@pytest.mark.live` and a key present.
- **Ollama:** out of scope. Structured output is weaker, there is no usage or refusal parity, and it needs a GPU. The Protocol leaves room for a later OpenAI-compatible provider for air-gapped deployments.

## 6. Open questions

- Pursue ZDR with Anthropic sales, or document standard retention?
- Default to Sonnet 5.5 at `medium` effort, with Haiku 5.5 for map steps?
- Re-verify Gemini model names and the Interactions vs `generate_content` choice at implementation time.
