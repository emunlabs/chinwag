"""Synthetic parser fixtures. No helper import, model or network execution."""
import json
import unittest
from response_evidence_v2 import completion_evidence, strict_json_loads, ResponseEvidenceError
from run_job_v2 import completion_status, MODEL


def completion(text="Final answer", finish="stop", model=MODEL):
    result = {"choices": [{"message": {"role": "assistant", "content": text}}]}
    if finish is not None:
        result["choices"][0]["finish_reason"] = finish
    if model is not None:
        result["model"] = model
    return result


class ResponseEvidenceTests(unittest.TestCase):
    def test_plain_text_missing_finish_is_explicitly_unverified(self):
        result = completion_evidence({"model": MODEL, "response": "Answer"})
        self.assertEqual(result["text"], "Answer")
        self.assertEqual(result["metadata"]["completeness"], "unreported")
        self.assertEqual(completion_status(result), "unverified_finish")

    def test_success_requires_actual_leaf_stop_and_reported_exact_model(self):
        self.assertEqual(completion_status(completion_evidence(completion())), "completion_evidence_verified")
        for finish in [None, "error", "content_filter", "future_unknown"]:
            self.assertNotEqual(completion_status(completion_evidence(completion(finish=finish))), "completion_evidence_verified")
        for reason in ["", " stop", "length ", 5, []]:
            with self.assertRaises(ResponseEvidenceError):
                completion_evidence(completion(finish=reason))
        self.assertEqual(completion_status(completion_evidence(completion(model=None))), "unverified_model")
        self.assertEqual(completion_status(completion_evidence(completion(model="other"))), "invalid_response")
        inner = completion(finish=None)
        result = completion_evidence({"model": MODEL, "finish_reason": "stop", "result": inner})
        self.assertEqual(completion_status(result), "unverified_finish", "outer stop cannot complete an unfinished leaf")

    def test_actual_nested_reasoning_only_shape_is_not_final(self):
        nested = completion(text="", finish="length")
        nested["choices"][0]["message"]["reasoning_content"] = "synthetic hidden reasoning"
        result = completion_evidence({"model": MODEL, "response": json.dumps(nested)})
        self.assertEqual(result["text"], "")
        self.assertTrue(result["metadata"]["reported_truncated"])
        self.assertEqual(completion_status(result), "truncated")
        self.assertNotIn("synthetic hidden reasoning", json.dumps(result))

    def test_multiple_serialized_completion_layers_keep_metadata_not_reasoning(self):
        nested = completion()
        nested["choices"][0]["message"]["reasoning"] = "synthetic private reasoning"
        result = completion_evidence({"result": {"response": json.dumps(json.dumps(nested))}})
        self.assertEqual(result["text"], "Final answer")
        self.assertEqual(result["metadata"]["json_string_layers_decoded"], 2)
        self.assertEqual(completion_status(result), "completion_evidence_verified")
        self.assertNotIn("synthetic private reasoning", json.dumps(result))

    def test_nonempty_partial_and_outer_truncation_never_complete(self):
        for finish in ["length", "max_tokens", "max_completion_tokens", "max_length", "model_length"]:
            result = completion_evidence(completion(text="Partial", finish=finish))
            self.assertEqual(completion_status(result), "truncated")
        result = completion_evidence({"model": MODEL, "finish_reason": "length", "response": completion()})
        self.assertEqual(completion_status(result), "truncated")

    def test_json_answer_data_remains_literal_including_provider_named_keys(self):
        for text in ['{"passed": true, "findings": []}', '{"result":"pass"}', '[1,2,3]', '"quoted answer"']:
            result = completion_evidence({"model": MODEL, "finish_reason": "stop", "response": text})
            self.assertEqual(result["text"], text)
            self.assertEqual(completion_status(result), "completion_evidence_verified")
        # Once the actual completion leaf is established its content is data,
        # including keys that would otherwise resemble a provider wrapper.
        text = '{"choices": [], "response": "answer", "result": "data", "reasoning": "audit field"}'
        self.assertEqual(completion_evidence(completion(text=text))["text"], text)

    def test_malformed_or_unrecognized_serialized_reasoning_never_becomes_text(self):
        for text in ['{"choices":[{"message":{"reasoning_content":"hidden"}',
                     '{"reasoning_content":"hidden"}',
                     '[{"type":"reasoning","text":"hidden"}]',
                     '{"model":"fixed","response":"ambiguous"}',
                     '{"result":']:
            with self.assertRaises(ResponseEvidenceError):
                completion_evidence({"model": MODEL, "response": text})

    def test_mixed_sibling_branches_reject_before_either_can_win(self):
        mixed = completion()
        mixed["result"] = completion(text="", finish="length")
        for payload in [mixed, {"response": "one", "result": "two"},
                        {"response": json.dumps(mixed)}]:
            with self.assertRaises(ResponseEvidenceError):
                completion_evidence(payload)

    def test_duplicate_keys_and_non_json_constants_fail_at_every_layer(self):
        raw = '{"model":"' + MODEL + '","choices":[{"finish_reason":"length","finish_reason":"stop","message":{"content":"partial"}}]}'
        with self.assertRaises(ResponseEvidenceError):
            strict_json_loads(raw)
        with self.assertRaises(ResponseEvidenceError):
            completion_evidence({"response": raw})
        for raw in ['{"x":NaN}', '{"x":Infinity}', '{"result":1,"result":2}']:
            with self.assertRaises(ResponseEvidenceError):
                strict_json_loads(raw)

    def test_nested_model_mismatch_and_provider_failure_are_not_completions(self):
        nested = completion(model="other")
        result = completion_evidence({"model": MODEL, "response": json.dumps(nested)})
        self.assertEqual(completion_status(result), "invalid_response")
        for payload in [{"ok": False, "response": completion()},
                        {"response": {"ok": False, **completion()}},
                        {"response": {"ok": "true", **completion()}}]:
            with self.assertRaises(ResponseEvidenceError):
                completion_evidence(payload)

    def test_empty_unsupported_or_nonassistant_content_is_not_final(self):
        self.assertEqual(completion_status(completion_evidence(completion(text=" "))), "invalid_response")
        for payload in [{"choices": []}, {"choices": [{"message": {"role": "user", "content": "x"}}]},
                        completion(text=[{"type": "reasoning", "text": "hidden"}]),
                        {"response": ["unsupported typed envelope"]}]:
            with self.assertRaises(ResponseEvidenceError):
                completion_evidence(payload)

    def test_nested_byte_depth_and_content_bounds_fail_closed(self):
        value = completion()
        for _ in range(10):
            value = {"result": value}
        with self.assertRaises(ResponseEvidenceError):
            completion_evidence(value)
        with self.assertRaises(ResponseEvidenceError):
            completion_evidence(completion(text="x" * 1048577))
        with self.assertRaises(ResponseEvidenceError):
            completion_evidence({"response": json.dumps({"items": list(range(130))})})


if __name__ == "__main__":
    unittest.main()
