"""Offline infrastructure boundaries: no real helper, model or network calls."""
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import urllib.request

from run_job_v2 import (ArtifactStore, AttemptGate, BoundaryError, CapturedResponse,
                        ENDPOINT, MODEL, finish_output)


def receipt():
    return {"seat": "DEV-1", "attempts": 0, "status": "not_started", "provider_outcome": "not_attempted"}


def request(prompt="Pinned fixture packet", endpoint=ENDPOINT, model=MODEL):
    return urllib.request.Request(endpoint, method="POST", data=json.dumps({"model": model,
        "messages": [{"role": "system", "content": "Fixed synthetic instruction"},
                     {"role": "user", "content": prompt}]}).encode())


def response(text="Final fixture answer", finish="stop", model=MODEL):
    value = {"choices": [{"message": {"role": "assistant", "content": text}}]}
    if finish is not None:
        value["choices"][0]["finish_reason"] = finish
    if model is not None:
        value["model"] = model
    return json.dumps(value).encode()


class FakeResponse(io.BytesIO):
    status = 200


class OfflineRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.parent = Path(self.temp.name).resolve()
        self.root = self.parent / "operation"
        self.root.mkdir(mode=0o700)
        self.calls = 0
        self.patches = [mock.patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")),
                        mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network forbidden")),
                        mock.patch("pathlib.Path.home", side_effect=AssertionError("real helper forbidden"))]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def claimed(self, store, value):
        store.claim({"schema": "chinwag-ephemeral-consumed/v1", "seat": "DEV-1", "input_SHA256": "a" * 64})
        store.record(value)

    def fake(self, raw, before=None, failure=None):
        def opener(req, timeout):
            self.assertEqual(req.full_url, ENDPOINT)
            self.assertEqual(timeout, 600)
            self.calls += 1
            if before:
                before()
            if failure:
                raise failure
            return FakeResponse(raw)
        return opener

    def run_response(self, store, value, raw):
        gate = AttemptGate(store, value, "Pinned fixture packet")
        captured = CapturedResponse(gate.open(request(), self.fake(raw)), store, value)
        try:
            with captured:
                captured.read()
            code = 0
        except BoundaryError:
            code = 1
        return finish_output(store, value, code, captured.final)

    def test_guard_and_unknown_attempt_are_synced_before_exactly_one_fake_call(self):
        events = []
        def synced(fd):
            info = os.fstat(fd)
            events.append(("file" if stat.S_ISREG(info.st_mode) else "dir", info.st_ino,
                           os.pread(fd, info.st_size, 0) if stat.S_ISREG(info.st_mode) else b""))
            os.fsync(fd)
        with ArtifactStore(self.root, "DEV-1", sync=synced) as store:
            value = receipt()
            self.claimed(store, value)
            def before():
                files = [event for event in events if event[0] == "file"]
                self.assertIn(b'"schema": "chinwag-ephemeral-consumed/v1"', files[0][2])
                last = json.loads(files[-1][2].splitlines()[-1])
                self.assertEqual((last["attempts"], last["status"]), (1, "provider_outcome_unknown"))
                self.assertEqual([event[0] for event in events[-3:]], ["file", "dir", "dir"])
                self.assertNotEqual(events[-2][1], events[-1][1])
            gate = AttemptGate(store, value, "Pinned fixture packet")
            with CapturedResponse(gate.open(request(), self.fake(response(), before)), store, value) as captured:
                captured.read()
                self.assertEqual(finish_output(store, value, 0, captured.final), 0)
            with self.assertRaises(BoundaryError):
                gate.open(request(), self.fake(response()))
            self.assertEqual(self.calls, 1)
            self.assertEqual((self.root / "DEV-1.output.txt").read_text(), "Final fixture answer")
            saved = json.loads((self.root / "DEV-1.receipt.json").read_bytes())
            self.assertEqual(saved["status"], "completed")
            log = list(map(json.loads, (self.root / "DEV-1.receipt.pending").read_bytes().splitlines()))
            self.assertEqual([item["attempts"] for item in log], [0, 1, 1, 1])
            self.assertIn(b'"status": "completed"', [event for event in events if event[0] == "file"][-1][2])

    def test_unverified_or_truncated_evidence_never_produces_completed_or_answer_output(self):
        cases = [(response(finish=None), "unverified_finish"), (response(model=None), "unverified_model"),
                 (response(finish="content_filter"), "unverified_finish"),
                 (response(finish="length"), "truncated"), (response(model="other"), "invalid_response")]
        for n, (raw, expected) in enumerate(cases):
            with self.subTest(expected=expected):
                operation = self.root / str(n)
                operation.mkdir(mode=0o700)
                with ArtifactStore(operation, "DEV-1") as store:
                    value = receipt()
                    self.claimed(store, value)
                    self.assertEqual(self.run_response(store, value, raw), 1)
                    self.assertEqual(value["status"], expected)
                    self.assertEqual((operation / "DEV-1.output.txt").read_bytes(), b"")
                    self.assertEqual(json.loads((operation / "DEV-1.receipt.json").read_bytes())["status"], expected)
                    self.assertEqual((operation / "DEV-1.provider-response.json").read_bytes(), raw)

    def test_malformed_nested_reasoning_is_preserved_raw_and_never_output(self):
        raw = json.dumps({"model": MODEL, "response": '{"choices":[{"message":{"reasoning_content":"synthetic hidden"}'}).encode()
        with ArtifactStore(self.root, "DEV-1") as store:
            value = receipt()
            self.claimed(store, value)
            self.assertEqual(self.run_response(store, value, raw), 1)
            self.assertEqual(value["status"], "invalid_response")
            self.assertEqual((self.root / "DEV-1.output.txt").read_bytes(), b"")
            self.assertEqual((self.root / "DEV-1.provider-response.json").read_bytes(), raw)

    def test_every_guard_initial_receipt_and_attempt_fsync_failure_prevents_provider(self):
        # Each stage syncs held file, directory and its parent, before opener.
        for fail_at in range(1, 10):
            with self.subTest(fail_at=fail_at):
                operation = self.root / str(fail_at)
                operation.mkdir(mode=0o700)
                count = 0
                def synced(fd):
                    nonlocal count
                    count += 1
                    if count == fail_at:
                        raise OSError("synthetic fsync failure")
                    os.fsync(fd)
                with ArtifactStore(operation, "DEV-1", sync=synced) as store:
                    value = receipt()
                    with self.assertRaises(OSError):
                        self.claimed(store, value)
                        AttemptGate(store, value, "Pinned fixture packet").open(request(), self.fake(response()))
                self.assertTrue((operation / "DEV-1.guard").exists())
                with ArtifactStore(operation, "DEV-1") as reopened:
                    with self.assertRaises(BoundaryError):
                        reopened.claim({"replay": False})
        self.assertEqual(self.calls, 0)

    def test_unknown_transport_outcome_stays_consumed_and_cannot_retry(self):
        with ArtifactStore(self.root, "DEV-1") as store:
            value = receipt()
            self.claimed(store, value)
            gate = AttemptGate(store, value, "Pinned fixture packet")
            with self.assertRaises(TimeoutError):
                gate.open(request(), self.fake(b"", failure=TimeoutError("synthetic")))
            self.assertEqual(value["status"], "provider_outcome_unknown")
            self.assertEqual(finish_output(store, value, 1, ""), 1)
            with self.assertRaises(BoundaryError):
                gate.open(request(), self.fake(response()))
        with ArtifactStore(self.root, "DEV-1") as reopened:
            with self.assertRaises(BoundaryError):
                reopened.claim({"replay": False})
        self.assertEqual(self.calls, 1)

    def test_dangling_or_late_foreign_reserved_files_are_never_followed_or_clobbered(self):
        outside = self.parent / "outside"
        outside.write_bytes(b"preserve owner bytes")
        for kind in ["dangling-guard", "pending-symlink", "pending-file", "receipt-file"]:
            with self.subTest(kind=kind):
                operation = self.root / kind
                operation.mkdir(mode=0o700)
                with ArtifactStore(operation, "DEV-1") as store:
                    value = receipt()
                    if kind == "dangling-guard":
                        (operation / "DEV-1.guard").symlink_to(self.parent / "never-created")
                        with self.assertRaises(BoundaryError):
                            self.claimed(store, value)
                        continue
                    store.claim({"consumed": True})
                    path = operation / ("DEV-1.receipt.json" if kind == "receipt-file" else "DEV-1.receipt.pending")
                    if kind == "pending-symlink":
                        path.symlink_to(outside)
                    else:
                        path.write_bytes(b"foreign receipt bytes")
                    with self.assertRaises(BoundaryError):
                        store.record(value)
                        AttemptGate(store, value, "Pinned fixture packet").open(request(), self.fake(response()))
                    self.assertEqual(path.read_bytes(), outside.read_bytes() if kind == "pending-symlink" else b"foreign receipt bytes")
        self.assertEqual(outside.read_bytes(), b"preserve owner bytes")
        self.assertFalse((self.parent / "never-created").exists())
        self.assertEqual(self.calls, 0)

    def test_owned_pending_replacement_is_detected_before_append_or_dispatch(self):
        with ArtifactStore(self.root, "DEV-1") as store:
            value = receipt()
            self.claimed(store, value)
            pending = self.root / "DEV-1.receipt.pending"
            old = self.root / "retained-original"
            pending.rename(old)
            before = old.read_bytes()
            pending.write_bytes(b"foreign replacement")
            with self.assertRaises(BoundaryError):
                AttemptGate(store, value, "Pinned fixture packet").open(request(), self.fake(response()))
            self.assertEqual(pending.read_bytes(), b"foreign replacement")
            self.assertEqual(old.read_bytes(), before)
            self.assertEqual(self.calls, 0)

    def test_late_foreign_output_cannot_publish_success_or_overwrite_bytes(self):
        with ArtifactStore(self.root, "DEV-1") as store:
            value = receipt()
            self.claimed(store, value)
            captured = CapturedResponse(AttemptGate(store, value, "Pinned fixture packet").open(request(), self.fake(response())), store, value)
            with captured:
                captured.read()
            output = self.root / "DEV-1.output.txt"
            output.write_bytes(b"foreign output")
            with self.assertRaises(BoundaryError):
                finish_output(store, value, 0, captured.final)
            self.assertEqual(output.read_bytes(), b"foreign output")
            self.assertFalse((self.root / "DEV-1.receipt.json").exists())
            self.assertEqual(self.calls, 1)

    def test_post_response_output_sync_failure_never_returns_completed(self):
        with ArtifactStore(self.root, "DEV-1") as store:
            value = receipt()
            self.claimed(store, value)
            captured = CapturedResponse(AttemptGate(store, value, "Pinned fixture packet").open(request(), self.fake(response())), store, value)
            with captured:
                captured.read()
            store.sync = mock.Mock(side_effect=OSError("synthetic output sync failure"))
            with self.assertRaises(OSError):
                finish_output(store, value, 0, captured.final)
            self.assertNotEqual(value["status"], "completed")
            self.assertFalse((self.root / "DEV-1.receipt.json").exists())
        self.assertTrue((self.root / "DEV-1.guard").exists())

    def test_final_receipt_sync_failure_cannot_publish_completed_in_memory(self):
        with ArtifactStore(self.root, "DEV-1") as store:
            value = receipt()
            self.claimed(store, value)
            captured = CapturedResponse(AttemptGate(store, value, "Pinned fixture packet").open(request(), self.fake(response())), store, value)
            with captured:
                captured.read()
            def synced(fd):
                final = self.root / "DEV-1.receipt.json"
                if final.exists() and os.fstat(fd).st_ino == final.stat().st_ino:
                    raise OSError("synthetic final receipt sync failure")
                os.fsync(fd)
            store.sync = synced
            with self.assertRaises(OSError):
                finish_output(store, value, 0, captured.final)
            self.assertNotEqual(value["status"], "completed")
            self.assertEqual(self.calls, 1)
        # Bytes can exist after a failed sync; no rollback, repair or replay is
        # claimed. The invocation remains consumed and needs owner adjudication.
        with ArtifactStore(self.root, "DEV-1") as reopened:
            with self.assertRaises(BoundaryError):
                reopened.claim({"replay": False})

    def test_partial_attempt_append_preserves_original_prefix_and_never_opens_provider(self):
        with ArtifactStore(self.root, "DEV-1") as store:
            value = receipt()
            self.claimed(store, value)
            path = self.root / "DEV-1.receipt.pending"
            original = path.read_bytes()
            real_write = os.pwrite
            calls = 0
            def partial(fd, data, offset):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return real_write(fd, data[:5], offset)
                raise OSError("synthetic partial append failure")
            with mock.patch("os.pwrite", side_effect=partial):
                with self.assertRaises(OSError):
                    AttemptGate(store, value, "Pinned fixture packet").open(request(), self.fake(response()))
            self.assertTrue(path.read_bytes().startswith(original))
            self.assertGreater(path.stat().st_size, len(original))
            self.assertEqual(self.calls, 0)
        with ArtifactStore(self.root, "DEV-1") as reopened:
            with self.assertRaises(BoundaryError):
                reopened.claim({"replay": False})

    def test_fifo_packet_is_rejected_without_blocking_or_consuming_a_job(self):
        os.mkfifo(self.root / "fifo.txt", 0o600)
        with ArtifactStore(self.root, "DEV-1") as store:
            with self.assertRaises(BoundaryError):
                store.read_input("fifo.txt")
        self.assertTrue(stat.S_ISFIFO((self.root / "fifo.txt").stat().st_mode))
        self.assertFalse((self.root / "DEV-1.guard").exists())
        self.assertEqual(self.calls, 0)

    def test_directory_swap_nonprivate_and_symlink_root_reject_without_dispatch(self):
        with ArtifactStore(self.root, "DEV-1") as store:
            value = receipt()
            self.claimed(store, value)
            retained = self.parent / "retained"
            self.root.rename(retained)
            self.root.mkdir(mode=0o700)
            with self.assertRaises(BoundaryError):
                AttemptGate(store, value, "Pinned fixture packet").open(request(), self.fake(response()))
            self.assertTrue((retained / "DEV-1.guard").exists())
            self.assertFalse((self.root / "DEV-1.guard").exists())
        os.chmod(self.root, 0o755)
        with self.assertRaises(BoundaryError):
            ArtifactStore(self.root, "DEV-1")
        alias = self.parent / "alias"
        alias.symlink_to(retained, target_is_directory=True)
        with self.assertRaises(OSError):
            ArtifactStore(alias, "DEV-1")
        self.assertEqual(self.calls, 0)

    def test_nonselected_endpoint_model_or_prompt_rejects_before_attempt(self):
        with ArtifactStore(self.root, "DEV-1") as store:
            value = receipt()
            self.claimed(store, value)
            gate = AttemptGate(store, value, "Pinned fixture packet")
            for req in [request(endpoint="https://invalid.example/"), request(model="fallback-model"), request(prompt="foreign packet")]:
                with self.assertRaises(BoundaryError):
                    gate.open(req, self.fake(response()))
            self.assertEqual(value["attempts"], 0)
            self.assertEqual(self.calls, 0)

    def test_input_symlink_and_oversized_file_are_not_operation_packets(self):
        outside = self.parent / "outside"
        outside.write_bytes(b"not an operation packet")
        (self.root / "packet.txt").symlink_to(outside)
        (self.root / "big.txt").write_bytes(b"x" * 20)
        with ArtifactStore(self.root, "DEV-1") as store:
            with self.assertRaises(OSError):
                store.read_input("packet.txt")
            with self.assertRaises(BoundaryError):
                store.read_input("big.txt", limit=10)
        self.assertEqual(outside.read_bytes(), b"not an operation packet")


if __name__ == "__main__":
    unittest.main()
