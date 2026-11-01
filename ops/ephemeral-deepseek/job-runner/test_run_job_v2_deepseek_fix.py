"""Tests for the 2026-11-01 empty-content fix: new Worker response shape, payload keys, explicit failure outcome."""
import json
import tempfile
import unittest
from pathlib import Path
import urllib.request

from run_job_v2 import (ArtifactStore, AttemptGate, BoundaryError, CapturedResponse, ENDPOINT, MODEL, finish_output)
from test_run_job_v2 import FakeResponse, receipt


def request(extra=None):
    body = {"model": MODEL, "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "Pinned fixture packet"}],
            "temperature": 0.2, "reasoning_effort": "low", "max_completion_tokens": 32768, "max_tokens": 32768}
    body.update(extra or {})
    return urllib.request.Request(ENDPOINT, method="POST", data=json.dumps(body).encode())


def worker_shape(text, finish, usage=None):
    return json.dumps({"ok": True, "model": MODEL, "requested_model": MODEL, "response": text, "finish_reason": finish,
                       "usage": usage or {"completion_tokens": 123}, "reasoning_effort": "low", "empty_content": not text.strip()}).encode()


class FixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / "operation"
        self.root.mkdir(mode=0o700)

    def tearDown(self):
        self.temp.cleanup()

    def run_one(self, raw, req=None):
        with ArtifactStore(self.root, "DEV-1") as store:
            value = receipt()
            store.claim({"schema": "chinwag-ephemeral-consumed/v1", "seat": "DEV-1", "input_SHA256": "a" * 64})
            store.record(value)
            gate = AttemptGate(store, value, "Pinned fixture packet")
            seen = {}

            def opener(r, timeout):
                seen["body"] = json.loads(r.data)
                return FakeResponse(raw)
            captured = CapturedResponse(gate.open(req or request(), opener), store, value)
            try:
                captured.read()
            except BoundaryError:
                pass
            code = finish_output(store, value, 0, captured.final)
            return code, value, seen["body"], (self.root / "DEV-1.output.txt").read_bytes()

    def test_new_worker_success_is_completed_and_logs_usage(self):
        code, value, body, out = self.run_one(worker_shape("Final answer", "stop"))
        self.assertEqual((code, value["status"], value["outcome"], out), (0, "completed", "completed", b"Final answer"))
        self.assertEqual(value["reported_finish_reasons"], ["stop"])
        self.assertEqual(value["usage"], {"completion_tokens": 123})
        self.assertEqual((body["max_completion_tokens"], body["max_tokens"], body["reasoning_effort"]), (32768, 32768, "low"))
        self.assertEqual(value["reasoning_effort_requested"], "low")

    def test_length_with_empty_content_is_failed_with_reason(self):
        code, value, _, out = self.run_one(worker_shape("", "length", {"completion_tokens": 32768}))
        self.assertEqual((code, out), (1, b""))
        self.assertEqual((value["status"], value["outcome"], value["failure_reason"], value["finish_reason"], value["completion_tokens"]),
                         ("truncated", "failed", "length_truncated", "length", 32768))

    def test_empty_content_with_stop_is_failed(self):
        code, value, _, out = self.run_one(worker_shape("", "stop"))
        self.assertEqual((code, out, value["outcome"], value["failure_reason"]), (1, b"", "failed", "empty_content"))

    def test_partial_text_with_length_is_failed_and_not_saved(self):
        code, value, _, out = self.run_one(worker_shape("half an ans", "length"))
        self.assertEqual((code, out, value["outcome"], value["failure_reason"]), (1, b"", "failed", "length_truncated"))

    def test_pre_fix_worker_stringified_envelope_is_failed(self):
        env = {"choices": [{"message": {"role": "assistant", "content": "", "reasoning": "x"}, "finish_reason": "length"}]}
        raw = json.dumps({"ok": True, "model": MODEL, "response": json.dumps(env)}).encode()
        code, value, _, out = self.run_one(raw)
        self.assertEqual((code, out, value["status"], value["outcome"]), (1, b"", "truncated", "failed"))

    def test_gate_rejects_unknown_keys_and_bad_effort(self):
        for extra in ({"stream": True}, {"reasoning_effort": "turbo"}):
            with self.subTest(extra=extra):
                with tempfile.TemporaryDirectory() as t:
                    op = Path(t).resolve() / "op"
                    op.mkdir(mode=0o700)
                    with ArtifactStore(op, "DEV-1") as store:
                        value = receipt()
                        gate = AttemptGate(store, value, "Pinned fixture packet")
                        with self.assertRaises(BoundaryError):
                            gate.open(request(extra), lambda *a, **k: self.fail("must not open"))


if __name__ == "__main__":
    unittest.main()
