import { DEFAULT_MODEL, normalizeRequest, extractCompletion } from "./lib.mjs";

const JSON_HEADERS = { "Content-Type": "application/json" };
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });

export default {
  async fetch(request, env) {
    const auth = request.headers.get("Authorization") || "";
    if (!env.AUTH_SECRET || auth !== `Bearer ${env.AUTH_SECRET}`) {
      return json({ error: "unauthorized" }, 401);
    }
    if (request.method !== "POST") {
      return json({ ok: true, engine: "cloudflare-workers-ai", default_model: DEFAULT_MODEL });
    }
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, error: "invalid JSON body" }, 400);
    }
    const knobs = normalizeRequest(body);
    if (!knobs.ok) return json({ ok: false, error: knobs.error }, 400);

    const requested = body.model || DEFAULT_MODEL;
    const candidates = [
      requested,
      "@cf/deepseek-ai/deepseek-v4-pro-0813",
      "@cf/deepseek-ai/deepseek-v4-flash-0731",
      "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
    ];
    let lastErr = null;
    for (const model of candidates) {
      try {
        const res = await env.WORKERS_AI.run(
          model,
          {
            messages: body.messages || [{ role: "user", content: body.prompt || "Hello" }],
            max_completion_tokens: knobs.maxCompletionTokens,
            reasoning_effort: knobs.effort,
            temperature: body.temperature ?? 0.2,
          },
          { gateway: { id: "cloudflareos-ai", skipCache: body.skip_cache === true } },
        );
        const c = extractCompletion(res);
        // ok means "the upstream call succeeded". An empty answer is still ok:true with
        // response:"" and the finish_reason, so clients decide (length => retry/fail loudly).
        return json({
          ok: true,
          provider: "cloudflare-workers-ai",
          gateway: "cloudflareos-ai",
          model,
          requested_model: requested,
          response: c.content,
          finish_reason: c.finishReason,
          usage: c.usage,
          reasoning_effort: knobs.effort,
          max_completion_tokens: knobs.maxCompletionTokens,
          reasoning_chars: c.reasoningChars,
          empty_content: c.content.trim() === "",
        });
      } catch (e) {
        lastErr = String(e);
      }
    }
    return json({ ok: false, error: lastErr }, 502);
  },
};
