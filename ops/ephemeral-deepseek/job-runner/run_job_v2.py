"""Future-only infrastructure runner. Never replay a consumed operation.

No run is authorized by this file. Root must allocate a new private operation,
review its exact source pins and approve the jobs separately. Offline tests use
only the pure parser/artifact/call boundary, never the real public helper.
"""
import contextlib
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import types
import urllib.error
import urllib.request
from response_evidence_v2 import completion_evidence, strict_json_loads, ResponseEvidenceError

MODEL = "@cf/deepseek-ai/deepseek-v4.1-flash-1017"
ENDPOINT = "https://chinwag-deepseek-v41.brianspector.workers.dev"
HELPER_SHA256 = "146a15694c13394589ac8ab250e2e5cf755c3a8587f63563d1995516c612febd"  # ops/ephemeral-deepseek/bin/deepseek-agent (pre-fix pin: 5b04c825...36b)
PRIMARY_NAMES = ["INTAKE_INTERNAL_API_BEARER_TOKEN", "WORKER_AUTH_SECRET"]
EFFORTS = ("none", "low", "high", "max")
COMPLETION_BUDGET = 32768
RESPONSE_LIMIT = 1048576
RECEIPT_LINE_LIMIT = 32768
RECEIPT_LOG_LIMIT = 262144
SUFFIXES = (".guard", ".receipt.json", ".receipt.pending", ".receipt.jsonl", ".provider-response.json", ".output.txt")


class BoundaryError(Exception):
    pass


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def completion_status(evidence):
    """Request identity, returned text and verified completion are separate."""
    metadata = evidence["metadata"]
    if metadata["reported_truncated"]:
        return "truncated"
    if not metadata["final_content_present"]:
        return "invalid_response"
    models = metadata["response_reported_models"]
    if not models:
        return "unverified_model"
    if any(model != MODEL for model in models):
        return "invalid_response"
    if not metadata["successful_finish_reported"]:
        return "unverified_finish"
    return "completion_evidence_verified"


def _name(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is None:
        raise BoundaryError("one operation-local filename required")
    return value


def _directory(path):
    """Open every component NOFOLLOW; retain the exact parent and directory."""
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw.startswith("/") or raw == "/" or len(raw) > 4096 or os.path.normpath(raw) != raw:
        raise BoundaryError("normalized absolute operation directory required")
    parts = raw.split("/")[1:]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open("/", flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        directory = os.open(parts[-1], flags, dir_fd=parent)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise BoundaryError("owned private operation directory required")
        except BaseException:
            os.close(directory)
            raise
        return directory, parent
    except BaseException:
        os.close(parent)
        raise


def _identity(info):
    return info.st_dev, info.st_ino


def _regular(info, private):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or (stat.S_IMODE(info.st_mode) != 0o600 if private else info.st_mode & 0o022)):
        raise BoundaryError("owned regular operation file required")


class ArtifactStore:
    """One consumed operation: held files, exclusive creation, append-only log.

    There is deliberately no receipt replacement, deletion or resume/replay API.
    A failed sync may leave bytes in place; that outcome stays consumed/uncertain.
    The private operation directory is the local owner trust boundary, not a
    defense against a hostile process with the same user's filesystem authority.
    """
    def __init__(self, base, seat, sync=os.fsync):
        if re.fullmatch(r"(?:DEV|QA)-[1-5]", seat) is None:
            raise BoundaryError("declared seat required")
        self.base = os.fspath(base)
        self.seat = seat
        self.sync = sync
        self.owned = {}
        self.faulted = False
        self.directory, self.parent = _directory(self.base)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        for file, _expected in self.owned.values():
            os.close(file)
        os.close(self.directory)
        os.close(self.parent)

    def _verify_directory(self):
        current, parent = _directory(self.base)
        try:
            if (_identity(os.fstat(current)) != _identity(os.fstat(self.directory))
                    or _identity(os.fstat(parent)) != _identity(os.fstat(self.parent))):
                raise BoundaryError("operation directory identity changed")
        finally:
            os.close(current)
            os.close(parent)

    def _verify_file(self, name, file, expected):
        before = os.fstat(file)
        _regular(before, True)
        if before.st_size != len(expected) or os.pread(file, len(expected) + 1, 0) != expected:
            raise BoundaryError("owned artifact bytes changed")
        named = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=self.directory)
        try:
            info = os.fstat(named)
            _regular(info, True)
            if _identity(info) != _identity(before):
                raise BoundaryError("owned artifact identity changed")
        finally:
            os.close(named)
        after = os.fstat(file)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (before.st_size, before.st_mtime_ns, before.st_ctime_ns):
            raise BoundaryError("artifact changed during verification")

    def verify(self):
        if self.faulted:
            raise BoundaryError("operation artifact persistence failed")
        self._verify_directory()
        for name, (file, expected) in self.owned.items():
            self._verify_file(name, file, expected)
        for suffix in SUFFIXES:
            name = self.seat + suffix
            if name in self.owned:
                continue
            try:
                os.stat(name, dir_fd=self.directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise BoundaryError("unexpected reserved artifact; never overwritten or adopted")

    def read_input(self, name, limit=RESPONSE_LIMIT):
        self.verify()
        name = _name(name)
        file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=self.directory)
        try:
            before = os.fstat(file)
            _regular(before, False)
            if before.st_size > limit:
                raise BoundaryError("operation input bound exceeded")
            raw = os.pread(file, limit + 1, 0)
            after = os.fstat(file)
            named = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
            if (len(raw) != before.st_size or len(raw) > limit or _identity(named) != _identity(before)
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise BoundaryError("operation input changed")
            self._verify_directory()
            return raw
        finally:
            os.close(file)

    def _existing(self, directory):
        for suffix in SUFFIXES:
            try:
                os.stat(self.seat + suffix, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise BoundaryError("consumed or unknown seat artifact exists; never replayed")

    def claim(self, metadata):
        self.verify()
        self._existing(self.directory)
        try:
            results = os.open("results", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.directory)
        except FileNotFoundError:
            results = None
        if results is not None:
            try:
                self._existing(results)
            finally:
                os.close(results)
        self.write_new(".guard", json_bytes(metadata))

    def _write_all(self, file, data, offset):
        written = 0
        while written < len(data):
            count = os.pwrite(file, data[written:], offset + written)
            if count <= 0:
                raise BoundaryError("artifact write failed")
            written += count

    def write_new(self, suffix, data):
        name = _name(self.seat + suffix)
        if len(data) > RESPONSE_LIMIT:
            raise BoundaryError("artifact byte bound exceeded")
        self.verify()
        try:
            file = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=self.directory)
            self.owned[name] = (file, data)
            os.fchmod(file, 0o600)
            _regular(os.fstat(file), True)
            self._write_all(file, data, 0)
            self.sync(file)
            self.sync(self.directory)
            self.sync(self.parent)
            self.verify()
        except BaseException:
            self.faulted = True
            raise

    def record(self, receipt):
        if self.seat + ".guard" not in self.owned:
            raise BoundaryError("durable consumed guard required")
        data = json_bytes(receipt)
        if len(data) > RECEIPT_LINE_LIMIT:
            raise BoundaryError("receipt line bound exceeded")
        name = self.seat + ".receipt.pending"
        if name not in self.owned:
            self.write_new(".receipt.pending", data)
            return
        self.verify()
        file, previous = self.owned[name]
        if len(previous) + len(data) > RECEIPT_LOG_LIMIT:
            raise BoundaryError("receipt log bound exceeded")
        try:
            self._write_all(file, data, len(previous))
            self.sync(file)
            self.sync(self.directory)
            self.sync(self.parent)
            self.owned[name] = (file, previous + data)
            self.verify()
        except BaseException:
            self.faulted = True
            raise

    def finalize(self, receipt):
        self.record(receipt)
        self.write_new(".receipt.json", json_bytes(receipt))
        self.verify()


class AttemptGate:
    """One process-local attempt; synced consumed+unknown records before opener."""
    def __init__(self, store, receipt, prompt):
        self.store, self.receipt, self.prompt = store, receipt, prompt

    def open(self, request, opener):
        if request.full_url != ENDPOINT or request.get_method() != "POST":
            raise BoundaryError("non-selected provider refused")
        payload = strict_json_loads(request.data)
        if not isinstance(payload, dict) or payload.get("model") != MODEL:
            raise BoundaryError("request model mismatch")
        messages = payload.get("messages")
        if (not isinstance(messages, list) or len(messages) != 2 or not isinstance(messages[0], dict)
                or messages[0].get("role") != "system" or not isinstance(messages[0].get("content"), str)
                or messages[1] != {"role": "user", "content": self.prompt}
                or set(payload) - {"model", "messages", "temperature", "max_tokens", "max_completion_tokens",
                                   "reasoning_effort"}
                or payload.get("reasoning_effort", "low") not in EFFORTS):
            raise BoundaryError("request does not match fixed packet contract")
        # max_tokens is the pre-fix Worker's name for the budget; both carry the same pinned value.
        payload["max_tokens"] = COMPLETION_BUDGET
        payload["max_completion_tokens"] = COMPLETION_BUDGET
        payload["temperature"] = 0.2
        self.receipt["reasoning_effort_requested"] = payload.get("reasoning_effort")
        request.data = json.dumps(payload, allow_nan=False).encode("utf-8")
        if self.receipt["attempts"] != 0:
            raise BoundaryError("duplicate provider attempt refused")
        self.receipt.update(attempts=1, status="provider_outcome_unknown", provider_outcome="unknown_after_attempt")
        self.store.record(self.receipt)
        self.store.verify()
        return opener(request, timeout=600)


class CapturedResponse:
    def __init__(self, response, store, receipt):
        self.response, self.store, self.receipt = response, store, receipt
        self.final = ""
        self.read_once = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.response.close()

    def read(self, *_args):
        if self.read_once:
            raise BoundaryError("duplicate response read refused")
        self.read_once = True
        raw = self.response.read(RESPONSE_LIMIT + 1)
        self.receipt.update(provider_outcome="response_received", HTTP_status=self.response.status,
                            response_bytes=len(raw), response_SHA256=hashlib.sha256(raw).hexdigest())
        if len(raw) > RESPONSE_LIMIT or self.response.status != 200:
            self.receipt["status"] = "invalid_response"
            raise BoundaryError("provider status or response bound rejected")
        self.store.write_new(".provider-response.json", raw)
        try:
            payload = strict_json_loads(raw)
            evidence = completion_evidence(payload)
        except ResponseEvidenceError:
            self.receipt["status"] = "invalid_response"
            raise BoundaryError("invalid or ambiguous provider response") from None
        self.receipt.update(evidence["metadata"])
        self.receipt["response_reported_model"] = payload.get("model")
        self.receipt["provider_ok"] = payload.get("ok")
        self.receipt["usage"] = payload.get("usage")
        self.receipt["status"] = completion_status(evidence)
        self.store.record(self.receipt)
        if self.receipt["status"] != "completion_evidence_verified":
            raise BoundaryError("completion evidence missing or unsuccessful")
        self.final = evidence["text"]
        return raw


def finish_output(store, receipt, code, text):
    """Publish success only after output and final receipt persistence succeeds."""
    valid = type(code) is int and code == 0 and receipt["status"] == "completion_evidence_verified" and bool(text.strip())
    output = text.encode("utf-8") if valid else b""
    store.write_new(".output.txt", output)
    published = dict(receipt)
    # Explicit failure semantics: anything but verified, non-empty completion is a failed run, and the
    # reason (finish_reason, token usage, helper stderr) is recorded so an empty output.txt is never a mystery.
    published["outcome"] = "completed" if valid else "failed"
    if not valid:
        reasons = receipt.get("reported_finish_reasons") or []
        published["failure_reason"] = (
            "length_truncated" if receipt.get("reported_truncated") else
            "empty_content" if receipt.get("final_content_present") is False else
            "unverified_completion" if receipt.get("status") in ("unverified_finish", "unverified_model", "invalid_response") else
            "no_provider_response")
        published["finish_reason"] = reasons[-1] if reasons else None
        usage = receipt.get("usage")
        if isinstance(usage, dict):
            published["completion_tokens"] = usage.get("completion_tokens")
    published.update(exit_code=code, output_bytes=len(output), output_SHA256=hashlib.sha256(output).hexdigest(),
                     saved_output_content_present=bool(output.strip()), finished_at=now())
    if valid:
        published["status"] = "completed"
    elif receipt["status"] == "completion_evidence_verified":
        published["status"] = "failed_helper_exit"
    elif receipt["status"] == "not_started":
        published["status"] = "failed_before_provider_attempt"
    store.finalize(published)
    # Publication can fail after bytes were written. Never publish completed in
    # memory/stdout on that error; preserve the consumed files for adjudication.
    receipt.update(published)
    return 0 if valid else 1


def run():
    base = Path(__file__).absolute().parent
    if len(sys.argv) != 2 or re.fullmatch(r"(?:DEV|QA)-[1-5]", sys.argv[1]) is None:
        raise BoundaryError("one declared seat argument required")
    seat = sys.argv[1]
    with ArtifactStore(base, seat) as store:
        jobs = strict_json_loads(store.read_input("jobs.json"))
        if not isinstance(jobs, list) or len(jobs) > 10 or any(not isinstance(job, dict) for job in jobs):
            raise BoundaryError("bounded job list required")
        matching = [job for job in jobs if job.get("seat") == seat]
        if len(matching) != 1:
            raise BoundaryError("seat must occur exactly once in jobs.json")
        job = matching[0]
        if (job.get("requested_model") != MODEL or job.get("provider") != "cloudflare-workers-ai"
                or job.get("automatic_retry") is not False or job.get("fallback_allowed") is not False
                or job.get("completion_budget") != 32768 or job.get("request_timeout_seconds") != 600):
            raise BoundaryError("job provider/model/budget/retry contract mismatch")
        packet = store.read_input(_name(job.get("input")))
        if hashlib.sha256(packet).hexdigest() != job.get("input_SHA256"):
            raise BoundaryError("input packet hash mismatch")
        prompt = packet.decode("utf-8")
        if not prompt.strip():
            raise BoundaryError("empty input packet")
        store.claim({"schema": "chinwag-ephemeral-consumed/v1", "pid": os.getpid(), "seat": seat,
                     "at": now(), "input_SHA256": job["input_SHA256"]})
        receipt = {"seat": seat, "title": job.get("title"), "started_at": now(),
                   "input_SHA256": job["input_SHA256"], "source_refs": job.get("source_refs", []),
                   "model_requested": MODEL, "provider": "cloudflare-workers-ai", "endpoint": ENDPOINT,
                   "helper_SHA256": HELPER_SHA256, "fallback_allowed": False, "automatic_retry": False,
                   "private_persona_or_signer_loaded": False, "attempts": 0,
                   "status": "not_started", "provider_outcome": "not_attempted"}
        store.record(receipt)
        captured = None
        code = 1
        try:
            helper = Path.home() / ".local/bin/deepseek-agent"
            helper_bytes = helper.read_bytes()
            if hashlib.sha256(helper_bytes).hexdigest() != HELPER_SHA256:
                raise BoundaryError("declared public helper source changed; not invoked")
            module = types.ModuleType("public_deepseek_helper")
            module.__file__ = str(helper)
            exec(compile(helper_bytes, str(helper), "exec"), module.__dict__)
            original_load = module.load_env_key
            module.load_env_key = lambda names: original_load(names) if names == PRIMARY_NAMES else ""

            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *_args, **_kwargs):
                    raise BoundaryError("provider redirect refused")

            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            gate = AttemptGate(store, receipt, prompt)

            def primary_only(request, timeout=None):
                nonlocal captured
                try:
                    response = gate.open(request, opener.open)
                except urllib.error.HTTPError as error:
                    receipt.update(HTTP_status=error.code, provider_outcome="http_error_received", status="failed_http")
                    error.close()
                    raise BoundaryError("provider HTTP error") from None
                except Exception as error:
                    receipt["transport_error_type"] = type(error).__name__
                    raise
                captured = CapturedResponse(response, store, receipt)
                return captured

            module.urllib.request.urlopen = primary_only
            # The helper's one-shot retry-at-lower-effort would be a second provider attempt, which this
            # runner forbids (AttemptGate). Seat selects the default reasoning effort (QA -> none).
            os.environ["EPHEMERAL_DEEPSEEK_RETRY"] = "0"
            os.environ["EPHEMERAL_SEAT"] = seat
            sys.argv = [str(helper), "run", "--model", MODEL]
            sys.stdin = io.StringIO(prompt)
            helper_err = io.StringIO()
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(helper_err):
                    code = module.main()
            finally:
                # Helper stderr lines are written to be secret-free; bound and keep only the tail.
                receipt["helper_stderr_tail"] = helper_err.getvalue()[-500:]
        except Exception as error:
            receipt["local_error_type"] = type(error).__name__
            if isinstance(error, BoundaryError):
                receipt["boundary_error"] = str(error)
            if receipt["attempts"] == 0:
                receipt["status"] = "failed_before_provider_attempt"
        result = finish_output(store, receipt, code, captured.final if captured else "")
        print(json.dumps({key: receipt.get(key) for key in (
            "seat", "status", "outcome", "failure_reason", "attempts", "HTTP_status", "response_reported_model",
            "reported_finish_reasons", "completion_tokens", "completeness", "provider_outcome")}))
        return result


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (BoundaryError, OSError, ValueError):
        # A consumed guard is never cleared. This message makes no claim that an
        # attempted provider request was cancelled, completed or safe to replay.
        print(json.dumps({"status": "local_boundary_or_persistence_failure", "automatic_retry": False}))
        raise SystemExit(2)
