import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.mjs";
import { normalizeRequest, extractCompletion } from "../src/lib.mjs";

const mkEnv = (impl) => ({ AUTH_SECRET: "test-secret", WORKERS_AI: { calls: [], async run(model, input, opts) { this.calls.push({ model, input, opts }); return impl(model, input); } } });
const post = (env, body) => worker.fetch(new Request("https://x/", { method: "POST", headers: { Authorization: "Bearer test-secret" }, body: JSON.stringify(body) }), env);
const chat = (content, finish, extra = {}) => ({ choices: [{ message: { role: "assistant", content, ...extra }, finish_reason: finish }], usage: { prompt_tokens: 10, completion_tokens: 5 } });

test("defaults: reasoning_effort low, max_completion_tokens (not max_tokens)", async () => {
  const env = mkEnv(() => chat("{\"a\":1}", "stop"));
  const r = await (await post(env, { messages: [{ role: "user", content: "hi" }] })).json();
  const sent = env.WORKERS_AI.calls[0].input;
  assert.equal(sent.reasoning_effort, "low");
  assert.equal(sent.max_completion_tokens, 16384);
  assert.equal("max_tokens" in sent, false);
  assert.equal(r.response, "{\"a\":1}");
  assert.equal(r.finish_reason, "stop");
  assert.deepEqual(r.usage, { prompt_tokens: 10, completion_tokens: 5 });
  assert.equal(r.empty_content, false);
});

test("per-request override incl. none; legacy max_tokens still honoured", async () => {
  const env = mkEnv(() => chat("ok", "stop"));
  await post(env, { reasoning_effort: "none", max_tokens: 100, messages: [] });
  assert.equal(env.WORKERS_AI.calls[0].input.reasoning_effort, "none");
  assert.equal(env.WORKERS_AI.calls[0].input.max_completion_tokens, 100);
  await post(env, { max_completion_tokens: 200, max_tokens: 100, messages: [] });
  assert.equal(env.WORKERS_AI.calls[1].input.max_completion_tokens, 200);
});

test("empty content + length is surfaced, never JSON.stringify(res)", async () => {
  const env = mkEnv(() => chat("", "length", { reasoning: "x".repeat(50) }));
  const r = await (await post(env, { messages: [] })).json();
  assert.equal(r.ok, true);
  assert.equal(r.response, "");
  assert.equal(r.finish_reason, "length");
  assert.equal(r.empty_content, true);
  assert.equal(r.reasoning_chars, 50);
});

test("validation and auth", async () => {
  assert.equal(normalizeRequest({ reasoning_effort: "medium" }).ok, false);
  assert.equal(normalizeRequest({ max_completion_tokens: 0 }).ok, false);
  assert.equal(normalizeRequest({ max_completion_tokens: 10 ** 9 }).maxCompletionTokens, 65536);
  const env = mkEnv(() => chat("x", "stop"));
  const bad = await worker.fetch(new Request("https://x/", { method: "POST", body: "{}" }), env);
  assert.equal(bad.status, 401);
  assert.equal((await post(env, { reasoning_effort: "bogus" })).status, 400);
  assert.equal(env.WORKERS_AI.calls.length, 0);
});

test("legacy {response} shape and array content", () => {
  assert.equal(extractCompletion({ response: "old" }).content, "old");
  assert.equal(extractCompletion(chat([{ type: "text", text: "a" }, { type: "text", text: "b" }], "stop")).content, "ab");
});

test("upstream error falls through to 502 with error", async () => {
  const env = mkEnv(() => { throw new Error("boom"); });
  const res = await post(env, { messages: [] });
  assert.equal(res.status, 502);
});
