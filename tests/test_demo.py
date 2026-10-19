import base64
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from mcp.types import CallToolResult, TextContent

import github_mcp_demo as demo


ENDPOINTS = demo.OAuthEndpoints(
    "https://github.com/login/oauth/authorize",
    "https://github.com/login/oauth/access_token",
    demo.GITHUB_ISSUER,
    True,
)
RESOURCE_METADATA = "https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/x/all/readonly"
AUTH_METADATA = "https://github.com/.well-known/oauth-authorization-server/login/oauth"


class CallbackTests(unittest.TestCase):
    def test_rejects_bad_callbacks_then_accepts_valid_code(self):
        with demo.callback_listener(0, "expected-state", ENDPOINTS) as (port, results):
            url = f"http://127.0.0.1:{port}/callback"
            with httpx.Client(trust_env=False) as client:
                for query in [
                    {"state": "wrong", "code": "hidden"},
                    {"state": "é", "code": "hidden"},
                    {"state": "expected-state", "code": "hidden"},  # missing issuer
                    {"state": "expected-state", "iss": "https://evil.example", "code": "hidden"},
                    {"state": "expected-state", "iss": demo.GITHUB_ISSUER},  # missing code
                ]:
                    self.assertEqual(client.get(url, params=query).status_code, 400)
                    self.assertTrue(results.empty())
                duplicate = urlencode([("state", "expected-state"), ("state", "other"),
                                       ("iss", demo.GITHUB_ISSUER), ("code", "hidden")])
                self.assertEqual(client.get(url + "?" + duplicate).status_code, 400)
                response = client.get(url, params={
                    "state": "expected-state", "iss": demo.GITHUB_ISSUER, "code": "one-use-code",
                })
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertNotIn("one-use-code", response.text)
                self.assertEqual(results.get_nowait(), "one-use-code")

    def test_denial_is_returned_as_an_error_without_echoing_remote_text(self):
        with demo.callback_listener(0, "expected-state", ENDPOINTS) as (port, results):
            with httpx.Client(trust_env=False) as client:
                response = client.get(f"http://127.0.0.1:{port}/callback", params={
                    "state": "expected-state", "iss": demo.GITHUB_ISSUER,
                    "error": "access_denied", "error_description": "untrusted-secret",
                })
            self.assertEqual(response.status_code, 200)
            error = results.get_nowait()
            self.assertIsInstance(error, demo.DemoError)
            self.assertNotIn("untrusted-secret", str(error))


class FlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_browser_oauth_and_mcp_flow_with_real_sdk(self):
        await self.exercise_full_flow()

    async def test_explicit_repo_scope_reaches_browser_and_token_exchange(self):
        text = await self.exercise_full_flow(scopes="read:user repo")
        self.assertIn("including private repositories and writes", text)

    async def test_custom_limit_and_text_json_output_use_one_tool_call(self):
        text = await self.exercise_full_flow(limit=7, text_only=True, show_json=True)
        self.assertIn("Showing 7 of 250", text)

    async def test_reset_revokes_old_grant_and_uses_only_new_token_for_mcp(self):
        text = await self.exercise_full_flow(reset_auth=True)
        self.assertIn("Grant revoked", text)
        self.assertEqual(text.count("Callback received; OAuth state and issuer validated"), 2)

    async def test_failed_reset_stops_before_second_login_and_mcp(self):
        calls = []
        def network(request):
            calls.append(request)
            return httpx.Response(422)
        with contextlib.redirect_stdout(io.StringIO()):
            async with httpx.AsyncClient(transport=httpx.MockTransport(network)) as client:
                with self.assertRaisesRegex(demo.DemoError, "reset failed.*422"):
                    await demo.reset_authorization(client, "fake-token", "id", "secret", "demo-user", demo.Trace())
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].method, "DELETE")

    async def test_mcp_403_preserves_scope_challenge_and_redacts_streamed_error_body(self):
        text = await self.exercise_full_flow(call_error=True)
        self.assertIn("MCP HTTP 403", text)
        self.assertIn("OAuth error: insufficient_scope", text)
        self.assertIn("OAuth scope: repo", text)
        self.assertIn("--scopes", text)
        self.assertIn("Server response:", text)
        self.assertIn("GitHub request ID: test-request-id", text)

    async def exercise_full_flow(self, scopes="read:user repo", call_error=False,
                                 limit=20, text_only=False, show_json=False, reset_auth=False):
        """Only the network/browser are simulated; OAuth and MCP code run normally."""
        calls = []
        login = {}
        token = "fake-access-token-never-print"
        secret = "fake-client-secret-never-print"
        authorization_code = "fake-authorization-code-never-print"
        token_exchanges = 0
        browser_visits = []
        revoked = False

        def browser(url):
            browser_visits.append(url)
            login.update({key: values[0] for key, values in parse_qs(urlsplit(url).query).items()})
            callback = login["redirect_uri"] + "?" + urlencode({
                "state": login["state"], "iss": demo.GITHUB_ISSUER, "code": authorization_code,
            })
            with httpx.Client(trust_env=False) as client:
                self.assertEqual(client.get(callback).status_code, 200)
            return True

        def network(request):
            nonlocal token_exchanges, revoked
            calls.append(request)
            url = str(request.url)
            if url == RESOURCE_METADATA:
                return httpx.Response(200, json={
                    "resource": demo.MCP_URL, "authorization_servers": [demo.GITHUB_ISSUER],
                })
            if url == AUTH_METADATA:
                return httpx.Response(200, json={
                    "issuer": demo.GITHUB_ISSUER, "authorization_endpoint": ENDPOINTS.authorization,
                    "token_endpoint": ENDPOINTS.token, "code_challenge_methods_supported": ["S256"],
                    "authorization_response_iss_parameter_supported": True,
                })
            if url == ENDPOINTS.token:
                token_exchanges += 1
                body = parse_qs(request.content.decode())
                self.assertEqual(body["client_secret"], [secret])
                self.assertEqual(body["code"], [authorization_code])
                self.assertEqual(body["redirect_uri"], [login["redirect_uri"]])
                self.assertEqual(body["resource"], [demo.MCP_URL])
                challenge = base64.urlsafe_b64encode(hashlib.sha256(body["code_verifier"][0].encode()).digest()).rstrip(b"=").decode()
                self.assertEqual(challenge, login["code_challenge"])
                return httpx.Response(200, json={
                    "access_token": token if token_exchanges == 1 else token + "-new", "token_type": "bearer", "scope": scopes,
                    "refresh_token": "fake-refresh-token-never-print", "expires_in": 28800,
                })
            if url == "https://api.github.com/user":
                expected_token = token if token_exchanges == 1 else token + "-new"
                self.assertEqual(request.headers["Authorization"], f"Bearer {expected_token}")
                return httpx.Response(200, json={"login": "demo-user"})
            if url == "https://api.github.com/applications/test-client-id/grant":
                self.assertTrue(reset_auth)
                self.assertEqual(token_exchanges, 1)
                self.assertEqual(request.method, "DELETE")
                self.assertEqual(json.loads(request.content), {"access_token": token})
                self.assertEqual(request.headers["Authorization"], "Basic " + base64.b64encode(f"test-client-id:{secret}".encode()).decode())
                revoked = True
                return httpx.Response(204)
            self.assertEqual(url, demo.MCP_URL)
            if "Authorization" not in request.headers:
                return httpx.Response(401, headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{RESOURCE_METADATA}"',
                })
            expected_token = token + "-new" if reset_auth else token
            self.assertEqual(request.headers["Authorization"], f"Bearer {expected_token}")
            if reset_auth:
                self.assertTrue(revoked)
                self.assertEqual(token_exchanges, 2)
            self.assertEqual(request.headers["X-MCP-Readonly"], "true")
            if request.method != "POST":
                return httpx.Response(405)
            message = json.loads(request.content)
            method = message["method"]
            if method == "initialize":
                result = {"protocolVersion": message["params"]["protocolVersion"],
                          "capabilities": {"tools": {}}, "serverInfo": {"name": "mock-github", "version": "1"}}
            elif method == "notifications/initialized":
                return httpx.Response(202)
            elif method == "tools/list":
                if not message.get("params", {}).get("cursor"):
                    result = {"tools": [{"name": "get_file_contents", "inputSchema": {"type": "object"}}], "nextCursor": "second-page"}
                else:
                    result = {"tools": [{"name": "search_repositories", "inputSchema": {
                        "type": "object", "properties": {
                            "query": {"type": "string"}, "perPage": {"type": "integer"},
                            "page": {"type": "integer"}, "sort": {"type": "string"},
                            "order": {"type": "string"}, "minimal_output": {"type": "boolean"},
                        }, "required": ["query"],
                    }}]}
            elif method == "tools/call":
                self.assertEqual(message["params"]["name"], "search_repositories")
                self.assertEqual(message["params"]["arguments"], {
                    "query": "user:demo-user fork:true", "perPage": limit, "page": 1,
                    "sort": "updated", "order": "desc", "minimal_output": True,
                })
                if call_error:
                    return httpx.Response(403, headers={
                        "WWW-Authenticate": 'Bearer error="insufficient_scope", scope="repo"',
                        "X-GitHub-Request-Id": "test-request-id",
                    }, stream=httpx.ByteStream(f'{{"message":"Missing repo scope {token}"}}'.encode()))
                payload = {"total_count": 250, "incomplete_results": False, "items": [
                    {"full_name": f"demo-user/project-{i}", "private": i % 2 == 1,
                     "description": token} for i in range(limit)
                ]}
                result = {"content": [{"type": "text", "text": json.dumps(payload)}], "isError": False}
                if not text_only:
                    result["structuredContent"] = payload
            else:
                self.fail(f"Unexpected MCP method: {method}")
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})

        real_async_client = httpx.AsyncClient
        def client_factory(**kwargs):
            return real_async_client(**{**kwargs, "transport": httpx.MockTransport(network)})

        arguments = ["--scopes", scopes, "--limit", str(limit)]
        if show_json:
            arguments.append("--show-json")
        if reset_auth:
            arguments.append("--reset-auth")
        args = demo.parse_args(arguments)
        args.port = 0  # Use an OS-selected free port in tests only.
        output = io.StringIO()
        trace = demo.Trace()
        failure = None
        with patch.dict("os.environ", {"GITHUB_CLIENT_ID": "test-client-id", "GITHUB_CLIENT_SECRET": secret}), \
             patch.object(demo.httpx, "AsyncClient", side_effect=client_factory), \
             patch.object(demo.webbrowser, "open", side_effect=browser), \
             contextlib.redirect_stdout(output):
            try:
                await demo.run(args, trace)
            except Exception as error:
                if not call_error:
                    raise
                failure = error
        text = output.getvalue()
        if call_error:
            self.assertIsNotNone(failure)
            text += trace.safe(demo.error_messages(failure))
        for value in [secret, token, authorization_code, "fake-refresh-token-never-print"]:
            self.assertNotIn(value, text)
        self.assertEqual(login["scope"], scopes)
        self.assertEqual(login["code_challenge_method"], "S256")
        self.assertEqual(login["resource"], demo.MCP_URL)
        if not call_error:
            self.assertIn("PUBLIC", text)
            self.assertIn("PRIVATE", text)
            self.assertIn(f"Showing {limit} of 250", text)
            self.assertIn("Done", text)
        self.assertIn("protocol:", text)
        self.assertIn("tools/list", text)
        self.assertIn("tools/call", text)
        self.assertGreater(len(calls), 8)
        tool_calls = [request for request in calls if request.method == "POST"
                      and str(request.url) == demo.MCP_URL
                      and json.loads(request.content).get("method") == "tools/call"]
        self.assertEqual(len(tool_calls), 1)
        self.assertEqual(len(browser_visits), 2 if reset_auth else 1)
        if reset_auth:
            states = [parse_qs(urlsplit(url).query)["state"][0] for url in browser_visits]
            self.assertNotEqual(states[0], states[1])
        return text

    async def test_discovery_rejects_untrusted_metadata_before_fetching_it(self):
        requests = []
        def network(request):
            requests.append(request)
            return httpx.Response(401, headers={
                "WWW-Authenticate": 'Bearer resource_metadata="https://evil.example/metadata"',
            })
        with contextlib.redirect_stdout(io.StringIO()):
            async with httpx.AsyncClient(transport=httpx.MockTransport(network)) as client:
                with self.assertRaises(demo.DemoError):
                    await demo.discover(client, demo.Trace())
        self.assertEqual(len(requests), 1)

    async def test_token_rejection_does_not_echo_response_secrets(self):
        def browser(url):
            params = parse_qs(urlsplit(url).query)
            with httpx.Client(trust_env=False) as client:
                client.get(params["redirect_uri"][0], params={
                    "state": params["state"][0], "iss": demo.GITHUB_ISSUER, "code": "test-code",
                })
            return True
        args = demo.parse_args([])
        args.port = 0
        with patch.object(demo.webbrowser, "open", side_effect=browser), contextlib.redirect_stdout(io.StringIO()):
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(
                200, json={"error": "bad_verification_code", "error_description": "secret-from-response"},
            ))) as client:
                with self.assertRaisesRegex(demo.DemoError, "GitHub rejected the token exchange") as error:
                    await demo.authorize(client, ENDPOINTS, "id", "secret", args, demo.Trace())
        self.assertNotIn("secret-from-response", str(error.exception))

    async def test_callback_timeout_closes_listener(self):
        args = demo.parse_args(["--no-browser", "--timeout", "0.01"])
        args.port = 0
        with contextlib.redirect_stdout(io.StringIO()):
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: self.fail("No token request expected"))) as client:
                with self.assertRaisesRegex(demo.DemoError, "timed out"):
                    await demo.authorize(client, ENDPOINTS, "id", "secret", args, demo.Trace())


class UtilityTests(unittest.TestCase):
    def test_limit_validation_and_default(self):
        self.assertEqual(demo.parse_args([]).limit, 20)
        self.assertEqual(demo.parse_args(["--limit", "100"]).limit, 100)
        for limit in ("0", "-1", "101", "many"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                demo.parse_args(["--limit", limit])

    def test_repository_labels_empty_results_and_missing_visibility(self):
        trace = demo.Trace()
        output = io.StringIO()
        payload = {"items": [
            {"full_name": "u/public", "private": False},
            {"full_name": "u/private", "private": True},
            {"full_name": "u/unknown"},
            {"full_name": "u/extra", "private": False},
        ], "total_count": 4, "incomplete_results": True}
        with contextlib.redirect_stdout(output):
            demo.display_repositories(payload, "u", 3, trace)
            demo.display_repositories({"items": [], "total_count": 0}, "u", 20, trace)
        text = output.getvalue()
        for label in ("PUBLIC", "PRIVATE", "UNKNOWN", "incomplete", "No matching"):
            self.assertIn(label, text)
        self.assertNotIn("u/extra", text)

    def test_rejects_unrecognized_repository_result(self):
        with self.assertRaises(demo.DemoError):
            demo.repository_payload(CallToolResult(content=[TextContent(type="text", text="not JSON")]))

    def test_non_scope_403_reports_policy_error_without_suggesting_broader_scopes(self):
        response = httpx.Response(403, request=httpx.Request("POST", demo.MCP_URL),
                                  json={"message": "OAuth application blocked by organization policy"})
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            text = demo.error_messages(error)
        self.assertIn("blocked by organization policy", text)
        self.assertNotIn("--scopes", text)

    def test_pkce_matches_rfc7636(self):
        verifier, challenge = demo.pkce_pair()
        self.assertTrue(43 <= len(verifier) <= 128)
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        self.assertEqual(challenge, expected)
        self.assertEqual(len(challenge), 43)

    def test_trace_redacts_credentials_and_removes_terminal_escape(self):
        trace = demo.Trace()
        trace.hide("hidden-value")
        self.assertEqual(trace.safe("hidden-value\x1b[31m"), "[REDACTED][31m")

    def test_missing_credentials_produces_useful_exit_without_network(self):
        output = io.StringIO()
        with patch.dict("os.environ", {}, clear=True), patch.object(demo, "load_dotenv", return_value=False), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(output):
            self.assertEqual(demo.main([]), 1)
        self.assertIn("GITHUB_CLIENT_ID", output.getvalue())

    def test_startup_loads_dotenv_preserving_shell_values_and_literal_secrets(self):
        observed = {}
        async def fake_run(args, trace):
            observed.update({key: os.environ.get(key) for key in ("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET")})

        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("GITHUB_CLIENT_ID=file-id\nGITHUB_CLIENT_SECRET=file-secret-${LITERAL}\n")
            output = io.StringIO()
            with patch.dict("os.environ", {"GITHUB_CLIENT_ID": "shell-id"}, clear=True), \
                 patch.object(demo, "ENV_FILE", env_file), \
                 patch.object(demo, "run", side_effect=fake_run), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(demo.main([]), 0)
            self.assertEqual(observed, {"GITHUB_CLIENT_ID": "shell-id", "GITHUB_CLIENT_SECRET": "file-secret-${LITERAL}"})
            self.assertIn("Loaded .env", output.getvalue())
            self.assertNotIn("file-secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()
