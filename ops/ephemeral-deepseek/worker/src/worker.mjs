export default {
  async fetch(request, env) {
    const auth = request.headers.get("Authorization") || "";
    if (!env.AUTH_SECRET || auth !== `Bearer ${env.AUTH_SECRET}`) {
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
    }
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ ok: true, engine: "cloudflare-workers-ai", default_model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017" }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    const body = await request.json();
    const candidates = [
      body.model || "@cf/deepseek-ai/deepseek-v4.1-flash-1017",
      "@cf/deepseek-ai/deepseek-v4-pro-0813",
      "@cf/deepseek-ai/deepseek-v4-flash-0731",
      "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b"
    ];
    let lastErr = null;
    for (const model of candidates) {
      try {
        const res = await env.WORKERS_AI.run(
          model,
          {
            messages: body.messages || [{ role: "user", content: body.prompt || "Hello" }],
            max_tokens: body.max_tokens || 2048,
            temperature: body.temperature ?? 0.2
          },
          { gateway: { id: "cloudflareos-ai", skipCache: false } }
        );
        const text = res?.response || res?.choices?.[0]?.message?.content || JSON.stringify(res);
        return new Response(JSON.stringify({ ok: true, provider: "cloudflare-workers-ai", gateway: "cloudflareos-ai", model, response: text }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      } catch (e) {
        lastErr = String(e);
      }
    }
    return new Response(JSON.stringify({ ok: false, error: lastErr }), { status: 502, headers: { "Content-Type": "application/json" } });
  }
};
