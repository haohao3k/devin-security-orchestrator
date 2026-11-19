import copy
import json
import unittest

import httpx

from devin_guard.devin import (
    ANALYSIS_RESULT_SCHEMA, DevinAPIError, DevinClient, DispatchUnknown,
    InvalidAnalysisResult, normalize_session_status, validate_analysis_result,
)


def analysis(verdict="candidate"):
    return {
        "verdict": verdict, "summary": "A scoped hypothesis requiring independent verification.",
        "locations": [{"path": "src/api.py", "line": 42, "reason": "Boundary checked here."}],
        "evidence": [{"kind": "static_trace", "detail": "Input is passed to the named sink."}],
        "unresolved_paths": [],
    }


class DevinClientTests(unittest.TestCase):
    def make_client(self, handler):
        client = DevinClient("org-test", "cog_test_only", transport=httpx.MockTransport(handler))
        self.addCleanup(client.close)
        return client

    def test_create_uses_documented_schema_budget_and_stable_job_tag(self):
        requests = []

        def handle(request):
            requests.append(request)
            return httpx.Response(200, json={"session_id": "devin-one", "status": "new"})

        client = self.make_client(handle)
        result = client.create_session("Investigate one path", 4, ["owner/repo"], "inv-123")
        self.assertEqual(result["session_id"], "devin-one")
        self.assertEqual(len(requests), 1)
        request = requests[0]
        self.assertEqual(str(request.url), "https://api.devin.ai/v3/organizations/org-test/sessions")
        self.assertEqual(request.headers["authorization"], "Bearer cog_test_only")
        body = json.loads(request.content)
        self.assertEqual(body["max_acu_limit"], 4)
        self.assertEqual(body["tags"], ["devin-guard", "job:inv-123"])
        self.assertEqual(body["structured_output_schema"], ANALYSIS_RESULT_SCHEMA)
        self.assertTrue(body["structured_output_required"])
        self.assertFalse(body["memory_enabled"])
        self.assertNotIn("bypass_approval", body)

    def test_create_timeout_is_unknown_and_is_never_automatically_retried(self):
        calls = []

        def handle(request):
            calls.append(request)
            raise httpx.ReadTimeout("provider may have accepted request", request=request)

        client = self.make_client(handle)
        with self.assertRaises(DispatchUnknown):
            client.create_session("Investigate", 1, ["owner/repo"], "inv-123")
        self.assertEqual(len(calls), 1)

    def test_create_server_error_and_malformed_success_are_unknown(self):
        for response in (
            httpx.Response(500, text="do not log cog_test_only"),
            httpx.Response(408),
            httpx.Response(200, text="not json"),
            httpx.Response(200, json={"status": "running"}),
            httpx.Response(200, json={"session_id": "devin-one", "status": []}),
        ):
            with self.subTest(response=response):
                calls = []

                def handle(request):
                    calls.append(request)
                    return response

                client = self.make_client(handle)
                with self.assertRaises(DispatchUnknown) as caught:
                    client.create_session("Investigate", 1, ["owner/repo"], "inv-123")
                self.assertEqual(len(calls), 1)
                self.assertNotIn("cog_test_only", str(caught.exception))

    def test_create_known_rejections_are_not_retried(self):
        for status in (400, 401, 403, 404, 409, 422, 429):
            with self.subTest(status=status):
                client = self.make_client(lambda request: httpx.Response(status))
                with self.assertRaises(DevinAPIError) as caught:
                    client.create_session("Investigate", 1, ["owner/repo"], "inv-123")
                self.assertFalse(caught.exception.retryable)
                self.assertEqual(caught.exception.status_code, status)

    def test_redirect_cannot_forward_credentials(self):
        calls = []

        def handle(request):
            calls.append(request)
            return httpx.Response(307, headers={"Location": "https://attacker.invalid/collect"})

        client = self.make_client(handle)
        with self.assertRaises(DispatchUnknown):
            client.create_session("Investigate", 1, ["owner/repo"], "inv-123")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].url.host, "api.devin.ai")

    def test_identifiers_cannot_change_credential_destination(self):
        with self.assertRaises(ValueError):
            DevinClient("org-../evil", "cog_test_only")
        calls = []
        client = self.make_client(lambda request: calls.append(request))
        for sid in ("https://evil.invalid", "../sessions", "devin-x?url=evil", "devin-x/../../"):
            with self.subTest(sid=sid), self.assertRaises(ValueError):
                client.get_session(sid)
        self.assertEqual(calls, [])

    def test_get_checks_session_identity_and_classifies_retryable_errors(self):
        client = self.make_client(lambda request: httpx.Response(200, json={
            "session_id": "devin-other", "status": "running", "status_detail": "finished",
        }))
        with self.assertRaises(DevinAPIError) as caught:
            client.get_session("devin-one")
        self.assertFalse(caught.exception.retryable)
        limited = self.make_client(lambda request: httpx.Response(429))
        with self.assertRaises(DevinAPIError) as caught:
            limited.get_session("devin-one")
        self.assertTrue(caught.exception.retryable)

    def test_cancel_uses_documented_delete_endpoint(self):
        calls = []

        def handle(request):
            calls.append(request)
            return httpx.Response(200, json={"session_id": "devin-one", "status": "exit"})

        self.make_client(handle).cancel_session("devin-one")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].method, "DELETE")
        self.assertEqual(calls[0].url.path, "/v3/organizations/org-test/sessions/devin-one")

    def test_running_finished_is_complete_but_suspension_is_never_clean(self):
        cases = [
            ("running", "finished", "completed"),
            ("running", "working", "active"),
            ("running", "waiting_for_approval", "blocked"),
            ("suspended", "usage_limit_exceeded", "incomplete"),
            ("suspended", "out_of_credits", "incomplete"),
            ("suspended", "finished", "incomplete"),
            ("exit", None, "incomplete"),
            ("error", "finished", "incomplete"),
        ]
        for status, detail, expected in cases:
            with self.subTest(status=status, detail=detail):
                self.assertEqual(normalize_session_status({"status": status, "status_detail": detail}), expected)

    def test_result_schema_requires_evidence_and_does_not_accept_verification_flags(self):
        good = analysis()
        self.assertEqual(validate_analysis_result(good), good)
        bad_values = [None, {**good, "verified": True}, {**good, "evidence": []}]
        for value in bad_values:
            with self.subTest(value=value), self.assertRaises(InvalidAnalysisResult):
                validate_analysis_result(value)
        for path in ("/etc/passwd", "../secret", "src/../../secret", "C:\\secret", "src/\nsecret"):
            value = copy.deepcopy(good)
            value["locations"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(InvalidAnalysisResult):
                validate_analysis_result(value)


if __name__ == "__main__":
    unittest.main()
