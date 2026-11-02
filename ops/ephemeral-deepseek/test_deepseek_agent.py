import importlib.machinery
import importlib.util
import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

HELPER = Path(__file__).parent / "bin" / "deepseek-agent"
loader = importlib.machinery.SourceFileLoader("deepseek_agent", str(HELPER))
spec = importlib.util.spec_from_loader("deepseek_agent", loader)
da = importlib.util.module_from_spec(spec)
loader.exec_module(da)


class Resp:
    def __init__(self, obj):
        self.raw = json.dumps(obj).encode()

    def read(self):
        return self.raw

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def worker(text, finish="stop", usage=None, ok=True):
    return {"ok": ok, "response": text, "finish_reason": finish, "usage": usage or {"completion_tokens": 7}}


ENV = {"INTAKE_INTERNAL_API_BEARER_TOKEN": "x" * 30}


def run(responses, env=None, argv=None):
    """Run main() with scripted urlopen results; returns (rc, stdout, stderr, sent_bodies)."""
    sent = []
    queue = list(responses)

    def fake_urlopen(req, timeout=None):
        sent.append(json.loads(req.data))
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return Resp(item)

    e = dict(ENV)
    e.update(env or {})
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, e, clear=True), mock.patch.object(da.urllib.request, "urlopen", fake_urlopen), \
            mock.patch("sys.argv", ["deepseek-agent", "run", "do it"]), redirect_stdout(out), redirect_stderr(err):
        rc = da.main()
    return rc, out.getvalue(), err.getvalue(), sent


class HelperTests(unittest.TestCase):
    def test_success_sends_effort_and_budget(self):
        rc, out, err, sent = run([worker('{"a":1}')])
        self.assertEqual((rc, out.strip(), err), (0, '{"a":1}', ""))
        b = sent[0]
        self.assertEqual(b["reasoning_effort"], "low")
        self.assertEqual(b["max_completion_tokens"], 32768)
        self.assertIn("Keep your reasoning brief", b["messages"][0]["content"])
        self.assertIn("Rust only", b["messages"][0]["content"])

    def test_qa_seat_defaults_to_none_and_env_override(self):
        self.assertEqual(run([worker("ok")], {"EPHEMERAL_SEAT": "QA-3"})[3][0]["reasoning_effort"], "none")
        self.assertEqual(run([worker("ok")], {"EPHEMERAL_SEAT": "qa-3", "EPHEMERAL_DEEPSEEK_REASONING": "high"})[3][0]["reasoning_effort"], "high")
        self.assertEqual(run([worker("ok")], {"EPHEMERAL_SEAT": "DEV-1"})[3][0]["reasoning_effort"], "low")

    def test_invalid_env_effort_warns_and_falls_back(self):
        rc, _, err, sent = run([worker("ok")], {"EPHEMERAL_DEEPSEEK_REASONING": "turbo"})
        self.assertEqual(rc, 0)
        self.assertIn("invalid EPHEMERAL_DEEPSEEK_REASONING", err)
        self.assertEqual(sent[0]["reasoning_effort"], "low")

    def test_length_retries_once_at_lower_effort_then_succeeds(self):
        rc, out, err, sent = run([worker("", "length", {"completion_tokens": 32768}), worker("done")])
        self.assertEqual((rc, out.strip()), (0, "done"))
        self.assertEqual([s["reasoning_effort"] for s in sent], ["low", "none"])
        self.assertIn("retrying once at reasoning_effort=none", err)

    def test_length_twice_fails_loudly_no_partial_stdout(self):
        rc, out, err, sent = run([worker("partial", "length"), worker("partial", "length")])
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertEqual(len(sent), 2)
        self.assertIn("finish_reason=length", err)

    def test_length_at_none_cannot_retry(self):
        rc, out, err, sent = run([worker("", "length")], {"EPHEMERAL_SEAT": "QA-1"})
        self.assertEqual((rc, out, len(sent)), (1, "", 1))
        self.assertIn("empty content", err)

    def test_retry_disabled(self):
        rc, _, _, sent = run([worker("", "length")], {"EPHEMERAL_DEEPSEEK_RETRY": "0"})
        self.assertEqual((rc, len(sent)), (1, 1))

    def test_empty_stop_fails(self):
        rc, out, err, _ = run([worker("", "stop")])
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("empty content", err)

    def test_old_worker_stringified_envelope_is_detected(self):
        env = {"choices": [{"message": {"role": "assistant", "content": "", "reasoning": "thinking"}, "finish_reason": "length"}],
               "usage": {"completion_tokens": 2048}}
        rc, out, err, sent = run([{"ok": True, "response": json.dumps(env)}, {"ok": True, "response": json.dumps(env)}])
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("finish_reason=length", err)
        self.assertIn("completion_tokens=2048", err)

    def test_json_answer_mentioning_choices_is_kept(self):
        answer = '{"findings": [], "note": "choices were considered"}'
        rc, out, _, _ = run([worker(answer)])
        self.assertEqual((rc, out.strip()), (0, answer))

    def test_http_error_is_logged_not_swallowed(self):
        err_http = da.urllib.error.HTTPError("https://w/", 502, "bad", {}, io.BytesIO(b'{"error":"upstream"}'))
        rc, out, err, _ = run([err_http])
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("HTTP 502", err)
        self.assertIn("no result from any DeepSeek 4.1 endpoint", err)
        self.assertNotIn("x" * 30, err)

    def test_transport_error_is_logged(self):
        rc, _, err, _ = run([da.urllib.error.URLError("timed out")])
        self.assertEqual(rc, 1)
        self.assertIn("transport error", err)

    def test_missing_credential_is_explained(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": "/nonexistent"}, clear=True), mock.patch("sys.argv", ["d", "run", "p"]), \
                redirect_stdout(out), redirect_stderr(err):
            rc = da.main()
        self.assertEqual(rc, 1)
        self.assertIn("no Worker credential", err.getvalue())


if __name__ == "__main__":
    unittest.main()
