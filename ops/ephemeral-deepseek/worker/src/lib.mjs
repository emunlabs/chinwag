// Pure helpers for the chinwag-deepseek-v41 Worker (unit-testable without Workers runtime).

export const DEFAULT_MODEL = "@cf/deepseek-ai/deepseek-v4.1-flash-1017";
export const REASONING_EFFORTS = ["none", "low", "high", "max"];
export const DEFAULT_REASONING_EFFORT = "low";
// Workers AI documents no numeric output default for this model; the old Worker
// fell back to 2048, which starved reasoning (finish_reason=length, empty content).
export const DEFAULT_MAX_COMPLETION_TOKENS = 16384;
export const MAX_COMPLETION_TOKENS_CEILING = 65536;

/** Validate per-request knobs. Returns {ok:true, effort, maxCompletionTokens} or {ok:false, error}. */
export function normalizeRequest(body) {
  let effort = DEFAULT_REASONING_EFFORT;
  if (body.reasoning_effort !== undefined && body.reasoning_effort !== null) {
    if (typeof body.reasoning_effort !== "string" || !REASONING_EFFORTS.includes(body.reasoning_effort)) {
      return { ok: false, error: `invalid reasoning_effort (allowed: ${REASONING_EFFORTS.join(", ")})` };
    }
    effort = body.reasoning_effort;
  }
  // max_completion_tokens is canonical; max_tokens is accepted from older clients only.
  const raw = body.max_completion_tokens ?? body.max_tokens ?? DEFAULT_MAX_COMPLETION_TOKENS;
  if (!Number.isInteger(raw) || raw < 1) {
    return { ok: false, error: "max_completion_tokens must be a positive integer" };
  }
  return { ok: true, effort, maxCompletionTokens: Math.min(raw, MAX_COMPLETION_TOKENS_CEILING) };
}

function contentToText(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content.map((p) => (p && typeof p.text === "string" ? p.text : "")).join("");
  }
  return "";
}

/**
 * Normalize a Workers AI result. Never falls back to JSON.stringify(res): an empty
 * `content` stays empty so callers can see finish_reason instead of a raw envelope.
 */
export function extractCompletion(res) {
  const choice = res?.choices?.[0];
  const message = choice?.message ?? {};
  const content = choice ? contentToText(message.content) : (typeof res?.response === "string" ? res.response : "");
  const reasoning = message.reasoning_content ?? message.reasoning ?? "";
  return {
    content,
    finishReason: choice?.finish_reason ?? res?.finish_reason ?? null,
    usage: res?.usage ?? null,
    reasoningChars: typeof reasoning === "string" ? reasoning.length : 0,
  };
}
