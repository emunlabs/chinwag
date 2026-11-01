"""Bounded provider evidence parsing. No credentials, requests or helper imports."""
import hashlib
import json

LIMIT = 1048576
MAX_DEPTH = 8
MAX_NODES = 128
TRUNCATED = {"length", "max_tokens", "max_completion_tokens", "max_length", "model_length"}


class ResponseEvidenceError(ValueError):
    pass


def strict_json_loads(raw):
    """Reject duplicate keys/non-JSON constants at every parsed object depth."""
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ResponseEvidenceError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise ResponseEvidenceError("non-JSON numeric constant")

    try:
        return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, ResponseEvidenceError):
            raise
        raise ResponseEvidenceError("malformed JSON") from None


def completion_evidence(payload):
    """Extract one literal final candidate; evidence absence never means success.

    Typed outer worker response/result objects are supported. Serialized strings
    unwrap only strongly identified completion envelopes (choices). Ordinary JSON
    answer objects/arrays stay byte-for-byte text; malformed/ambiguous provider
    shapes fail closed. Terminal message.content is always literal answer data.
    """
    reasons, models = [], []
    state = {"nodes": 0, "decoded_bytes": 0, "decoded_layers": 0, "reasoning_present": False}

    def encoded(text):
        try:
            raw = text.encode("utf-8")
        except UnicodeError:
            raise ResponseEvidenceError("invalid UTF-8 text") from None
        if len(raw) > LIMIT:
            raise ResponseEvidenceError("response text bound exceeded")
        return raw

    def metadata(value):
        if "ok" in value and not isinstance(value["ok"], bool):
            raise ResponseEvidenceError("invalid provider status metadata")
        if value.get("ok") is False:
            raise ResponseEvidenceError("provider reported failure")
        reason = value.get("finish_reason")
        if reason is not None:
            if (not isinstance(reason, str) or not reason or reason != reason.strip()
                    or len(reason) > 64 or any(ord(c) < 32 for c in reason)):
                raise ResponseEvidenceError("invalid finish metadata")
            reasons.append(reason)
        model = value.get("model")
        if model is not None:
            if (not isinstance(model, str) or not model or model != model.strip()
                    or len(model) > 256 or any(ord(c) < 32 for c in model)):
                raise ResponseEvidenceError("invalid model metadata")
            models.append(model)

    def count(depth):
        state["nodes"] += 1
        if depth > MAX_DEPTH or state["nodes"] > MAX_NODES:
            raise ResponseEvidenceError("response envelope nesting bound exceeded")

    def suspicious_data(value, depth=0):
        """Unknown serialized reasoning/protocol data cannot be final prose."""
        count(depth)
        if isinstance(value, dict):
            if (any(key in value for key in ("reasoning", "reasoning_content", "choices"))
                    or value.get("type") in ("reasoning", "reasoning_content")):
                return True
            if (any(key in value for key in ("response", "result"))
                    and any(key in value for key in ("model", "ok", "finish_reason"))):
                return True
            return any(suspicious_data(child, depth + 1) for child in value.values())
        if isinstance(value, list):
            return any(suspicious_data(child, depth + 1) for child in value)
        return False

    def string_candidate(text, depth, finish):
        encoded(text)
        original = text
        decoded = 0
        while text.lstrip().startswith(("{", "[", '"')):
            count(depth + decoded)
            raw = encoded(text)
            state["decoded_bytes"] += len(raw)
            if state["decoded_bytes"] > 4 * LIMIT:
                raise ResponseEvidenceError("nested JSON byte bound exceeded")
            parsed = strict_json_loads(text)
            decoded += 1
            if isinstance(parsed, str):
                text = parsed
                continue
            if isinstance(parsed, dict) and "choices" in parsed:
                state["decoded_layers"] += decoded
                return visit(parsed, depth + decoded)
            if suspicious_data(parsed, depth + decoded):
                raise ResponseEvidenceError("ambiguous serialized provider envelope")
            return original, finish
        # Only a recognized completion envelope consumes JSON string layers.
        return original, finish

    def content_text(value):
        if value is None:
            return ""
        if isinstance(value, str):
            encoded(value)
            return value
        if isinstance(value, list) and len(value) <= 32:
            parts = []
            for part in value:
                if (not isinstance(part, dict) or part.get("type") != "text"
                        or not isinstance(part.get("text"), str)):
                    raise ResponseEvidenceError("unsupported content part")
                parts.append(part["text"])
            text = "".join(parts)
            encoded(text)
            return text
        raise ResponseEvidenceError("unsupported content type")

    def visit(value, depth):
        count(depth)
        if not isinstance(value, dict):
            raise ResponseEvidenceError("unsupported response envelope")
        metadata(value)
        branches = [key for key in ("choices", "response", "result") if key in value]
        if len(branches) != 1:
            raise ResponseEvidenceError("one unambiguous response branch required")
        if branches[0] == "choices":
            choices = value["choices"]
            if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
                raise ResponseEvidenceError("one unambiguous completion choice required")
            choice = choices[0]
            metadata(choice)
            if any(key in choice for key in ("response", "result", "choices")):
                raise ResponseEvidenceError("ambiguous completion choice")
            message = choice.get("message")
            if not isinstance(message, dict) or message.get("role", "assistant") != "assistant":
                raise ResponseEvidenceError("assistant completion message required")
            state["reasoning_present"] |= bool(message.get("reasoning_content") or message.get("reasoning"))
            return content_text(message.get("content")), choice.get("finish_reason")
        child = value[branches[0]]
        if isinstance(child, str):
            return string_candidate(child, depth + 1, value.get("finish_reason"))
        if isinstance(child, dict):
            return visit(child, depth + 1)
        raise ResponseEvidenceError("unsupported response envelope child")

    if not isinstance(payload, dict):
        raise ResponseEvidenceError("response must be an object")
    text, leaf_reason = visit(payload, 0)
    raw = encoded(text)
    truncated = any(reason.lower() in TRUNCATED for reason in reasons)
    successful_finish = leaf_reason == "stop" and all(reason == "stop" for reason in reasons)
    completeness = ("reported_truncated" if truncated else
                    "successful_finish_reported" if successful_finish else
                    "unsupported_finish_reason" if leaf_reason is not None else "unreported")
    return {"text": text, "metadata": {
        "final_content_present": bool(text.strip()),
        "final_content_bytes": len(raw),
        "final_content_SHA256": hashlib.sha256(raw).hexdigest(),
        "reported_finish_reasons": reasons,
        "leaf_finish_reason": leaf_reason,
        "successful_finish_reported": successful_finish,
        "response_reported_models": models,
        "truncation_metadata_reported": bool(reasons),
        "reported_truncated": truncated,
        "completeness": completeness,
        "json_string_layers_decoded": state["decoded_layers"],
        "reasoning_present": state["reasoning_present"],
    }}
