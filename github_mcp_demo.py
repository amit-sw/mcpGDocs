#!/usr/bin/env python3
"""A browser OAuth login, MCP tool discovery, and one repository search."""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import queue
import re
import secrets
import sys
import threading
import webbrowser
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import httpx
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Implementation, LATEST_PROTOCOL_VERSION


MCP_URL = "https://api.githubcopilot.com/mcp/x/all/readonly"
GITHUB_ISSUER = "https://github.com/login/oauth"
HTTP_TIMEOUT = httpx.Timeout(60.0, connect=15.0)
ENV_FILE = Path(__file__).with_name(".env")


class DemoError(Exception):
    """An expected failure with a useful, credential-free explanation."""


class Trace:
    def __init__(self):
        self.number = 0
        self._secrets = []

    def hide(self, value):
        if value:
            self._secrets.append(value)

    def safe(self, value):
        text = str(value)
        for secret in sorted(self._secrets, key=len, reverse=True):
            text = text.replace(secret, "[REDACTED]")
        # Repository text is untrusted: don't execute terminal control sequences.
        return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", text)

    def say(self, message):
        print(self.safe(message), flush=True)

    def step(self, message):
        self.number += 1
        self.say(f"\n[{self.number:02d}] {message}")


@dataclass(frozen=True)
class OAuthEndpoints:
    authorization: str
    token: str
    issuer: str
    require_issuer: bool = False


def pkce_pair():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


def require_url(url, host, path=None):
    """Keep this GitHub-only demo from sending credentials to another origin."""
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != host or parsed.query
            or parsed.fragment or (path is not None and parsed.path != path)):
        raise DemoError("Discovery returned an unexpected URL; refusing to continue.")
    return url


def json_response(response, operation):
    if response.is_error or response.is_redirect:
        hint = ""
        if response.status_code == 401:
            hint = " Authorization failed or the token needs additional scopes."
        elif response.status_code == 403:
            hint = " Check account/organization access policies and rate limits."
        raise DemoError(f"{operation}: HTTP {response.status_code}.{hint}")
    try:
        data = response.json()
    except ValueError:
        raise DemoError(f"{operation}: expected a JSON response.") from None
    if not isinstance(data, dict):
        raise DemoError(f"{operation}: expected a JSON object.")
    return data


async def discover(client, trace):
    trace.step("Contact GitHub MCP without a token → expect HTTP 401")
    response = await client.post(MCP_URL, headers={
        "Accept": "application/json, text/event-stream",
    }, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {},
                   "clientInfo": {"name": "python-oauth-demo", "version": "0.1.0"}},
    })
    if response.status_code != 401:
        raise DemoError(f"Expected an OAuth challenge, received HTTP {response.status_code}.")
    challenge = response.headers.get("www-authenticate", "")
    match = re.search(r'\bresource_metadata="([^"\s]+)"', challenge, re.IGNORECASE)
    if not match:
        raise DemoError("The MCP challenge has no protected-resource metadata URL.")
    metadata_url = require_url(match[1], "api.githubcopilot.com")
    trace.say("  ← HTTP 401, WWW-Authenticate: Bearer resource_metadata=…")

    trace.step("Discover the OAuth authorization and token endpoints")
    trace.say(f"  → GET {metadata_url}")
    resource = json_response(await client.get(metadata_url), "Resource discovery")
    if resource.get("resource", "").rstrip("/") != MCP_URL.rstrip("/"):
        raise DemoError("Protected-resource metadata does not identify this MCP endpoint.")
    if GITHUB_ISSUER not in resource.get("authorization_servers", []):
        raise DemoError("The MCP server did not advertise GitHub's OAuth issuer.")
    # RFC 8414: insert the well-known path before the issuer's /login/oauth path.
    issuer = urlsplit(GITHUB_ISSUER)
    metadata_url = f"https://{issuer.netloc}/.well-known/oauth-authorization-server{issuer.path}"
    trace.say(f"  → GET {metadata_url}")
    metadata = json_response(await client.get(metadata_url), "OAuth discovery")
    if metadata.get("issuer") != GITHUB_ISSUER:
        raise DemoError("OAuth metadata issuer mismatch.")
    if "S256" not in metadata.get("code_challenge_methods_supported", []):
        raise DemoError("GitHub did not advertise the required S256 PKCE support.")
    endpoints = OAuthEndpoints(
        require_url(metadata.get("authorization_endpoint", ""), "github.com", "/login/oauth/authorize"),
        require_url(metadata.get("token_endpoint", ""), "github.com", "/login/oauth/access_token"),
        GITHUB_ISSUER,
        metadata.get("authorization_response_iss_parameter_supported") is True,
    )
    trace.say(f"  Authorization endpoint: {endpoints.authorization}")
    trace.say(f"  Token endpoint:         {endpoints.token}")
    trace.say("  Using your registered OAuth App (no dynamic client registration).")
    return endpoints


@contextmanager
def callback_listener(port, state, endpoints):
    """Capture one valid callback without logging its authorization code."""
    results = queue.Queue(maxsize=1)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_args):
            pass  # The default access log would expose ?code=…

        def reply(self, status, message):
            body = message.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path != "/callback":
                self.reply(404, "Not found.")
                return
            values = parse_qs(parsed.query, keep_blank_values=True)
            if (any(len(v) != 1 for v in values.values())
                    or not secrets.compare_digest(
                        values.get("state", [""])[0].encode(), state.encode())):
                self.reply(400, "Invalid OAuth state. Return to the original login attempt.")
                return
            returned_issuer = values.get("iss", [None])[0]
            if ((returned_issuer is not None and returned_issuer != endpoints.issuer)
                    or (endpoints.require_issuer and returned_issuer is None)):
                self.reply(400, "Invalid OAuth issuer.")
                return
            if "error" in values:
                result = DemoError("GitHub authorization was denied or failed. Run the demo again to retry.")
            elif values.get("code", [""])[0]:
                result = values["code"][0]
            else:
                self.reply(400, "Missing authorization code.")
                return
            try:
                results.put_nowait(result)
            except queue.Full:
                self.reply(409, "This login callback has already been received.")
                return
            self.reply(200, "GitHub authorization callback received. Return to the terminal to see the token exchange and MCP calls.")

    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError:
        raise DemoError(f"Cannot listen on 127.0.0.1:{port}. Close the other listener or use --port and update the OAuth callback URL.") from None
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    worker.start()
    try:
        yield server.server_port, results
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


async def authorize(client, endpoints, client_id, client_secret, args, trace):
    state = secrets.token_urlsafe(32)
    verifier, challenge = pkce_pair()
    trace.hide(verifier)
    trace.step("Create OAuth state + PKCE; start the localhost callback listener")
    with callback_listener(args.port, state, endpoints) as (port, results):
        redirect_uri = f"http://127.0.0.1:{port}/callback"
        trace.say(f"  Callback: {redirect_uri}")
        trace.say(f"  Requested scopes: {args.scopes}")
        if "repo" in args.scopes.split():
            trace.say("  The repo OAuth scope grants broad repository access, including private repositories and writes.")
            trace.say("  This CLI calls only the read-only MCP endpoint; review GitHub's consent screen.")
        url = endpoints.authorization + "?" + urlencode({
            "client_id": client_id, "redirect_uri": redirect_uri,
            "response_type": "code", "scope": args.scopes, "state": state,
            "code_challenge": challenge, "code_challenge_method": "S256",
            "resource": MCP_URL,
        })
        trace.step("Open GitHub in your browser; sign in and authorize the demo")
        trace.say(f"  Authorization URL (also works if browser opening fails):\n  {url}")
        if not args.no_browser:
            try:
                webbrowser.open(url)
            except webbrowser.Error:
                trace.say("  Open the URL above manually.")
        trace.say(f"  Waiting up to {args.timeout:g} seconds for the callback…")
        try:
            async with asyncio.timeout(args.timeout):
                while results.empty():
                    await asyncio.sleep(0.1)
                code = results.get_nowait()
        except TimeoutError:
            raise DemoError("OAuth callback timed out. Check the registered callback URL, then retry.") from None
    if isinstance(code, DemoError):
        raise code
    trace.hide(code)
    trace.step("Callback received; OAuth state and issuer validated")
    trace.say("  Authorization code captured (hidden). The PKCE verifier stays in this process.")

    trace.step("Exchange the authorization code + PKCE verifier for an access token")
    trace.say(f"  → POST {endpoints.token} (code, verifier, and client secret hidden)")
    response = await client.post(endpoints.token, headers={"Accept": "application/json"}, data={
        "client_id": client_id, "client_secret": client_secret, "code": code,
        "redirect_uri": redirect_uri, "code_verifier": verifier,
        "grant_type": "authorization_code", "resource": MCP_URL,
    })
    data = json_response(response, "Token exchange")
    for key in ("access_token", "refresh_token"):
        trace.hide(data.get(key))
    if data.get("error") or not isinstance(data.get("access_token"), str) or not data["access_token"]:
        raise DemoError("GitHub rejected the token exchange. Check the client ID/secret and callback URL, then retry.")
    if str(data.get("token_type", "")).lower() != "bearer":
        raise DemoError("GitHub returned an unsupported token type.")
    trace.say("  ← Access token obtained (hidden; kept in memory only).")
    trace.say(f"  Granted scopes: {data.get('scope') or '(none reported)'}")
    if "expires_in" in data:
        trace.say(f"  Token lifetime: {data['expires_in']} seconds. This short demo does not refresh tokens.")
    return data["access_token"]


async def github_identity(client, token, trace):
    trace.step("Validate the signed-in GitHub identity (one direct REST request)")
    user = json_response(await client.get("https://api.github.com/user", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
    }), "Identity check")
    username = user.get("login")
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9-]+", username):
        raise DemoError("GitHub's identity response did not include a valid user login.")
    trace.say(f"  ← Signed in as {username}")
    return username


async def reset_authorization(client, token, client_id, client_secret, username, trace):
    trace.step(f"Reset OAuth authorization for {username} and this OAuth App")
    trace.say("  Revoking the grant and all tokens issued by this app for this user.")
    url = f"https://api.github.com/applications/{quote(client_id, safe='')}/grant"
    trace.say(f"  → DELETE {url} (app credentials and access token hidden)")
    trace.hide(base64.b64encode(f"{client_id}:{client_secret}".encode()).decode())
    response = await client.request("DELETE", url,
        auth=httpx.BasicAuth(client_id, client_secret),
        headers={"Accept": "application/vnd.github+json"}, json={"access_token": token})
    if response.status_code != 204:
        raise DemoError(f"Authorization reset failed (HTTP {response.status_code}); fresh authorization was not started.")
    trace.say("  ← HTTP 204. Grant revoked; requesting fresh browser consent next.")


def repository_payload(result):
    """Support both structured MCP output and the older JSON-in-text format."""
    if isinstance(result.structuredContent, dict) and isinstance(result.structuredContent.get("items"), list):
        return result.structuredContent
    for block in result.content:
        if block.type == "text":
            try:
                payload = json.loads(block.text)
            except ValueError:
                continue
            if isinstance(payload, dict) and isinstance(payload.get("items"), list):
                return payload
    raise DemoError("Repository search returned an unexpected format: no repository items list.")


def display_repositories(payload, username, limit, trace):
    items = payload["items"][:limit]
    trace.say(f"\nRepositories owned by {username} (forks included; most recently updated first)")
    trace.say(f"Showing {len(items)} of {payload.get('total_count', '(unknown)')} matches accessible to this token; requested up to {limit}.")
    if payload.get("incomplete_results"):
        trace.say("  GitHub reported an incomplete search result.")
    if not items:
        trace.say("  No matching repositories were returned.")
        return
    trace.say(f"\n{'#':>3}  {'VISIBILITY':<10}  REPOSITORY")
    trace.say("-" * 72)
    for index, repo in enumerate(items, 1):
        if not isinstance(repo, dict):
            raise DemoError("Repository search returned an invalid repository entry.")
        visibility = repo.get("visibility")
        if visibility in ("public", "private", "internal"):
            visibility = visibility.upper()
        elif repo.get("private") is True:
            visibility = "PRIVATE"
        elif repo.get("private") is False:
            visibility = "PUBLIC"
        else:
            visibility = "UNKNOWN"  # Never assume a missing private flag means public.
        name = repo.get("full_name") or repo.get("name") or "(unnamed)"
        trace.say(f"{index:>3}  {visibility:<10}  {name}")


async def run_mcp(token, username, args, trace, transport=None):
    # The SDK raises for HTTP errors before reading streamed response bodies.
    # Preserve those bodies so the top-level error can explain scope challenges.
    async def read_error_body(response):
        if response.is_error:
            await response.aread()

    trace.step("Connect to GitHub MCP using Streamable HTTP + Bearer authorization")
    trace.say(f"  MCP endpoint: {MCP_URL}")
    trace.say("  Authorization: Bearer [REDACTED]")
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}", "X-MCP-Readonly": "true"},
        timeout=HTTP_TIMEOUT, transport=transport, follow_redirects=False,
        event_hooks={"response": [read_error_body]},
    ) as client:
        async with streamable_http_client(MCP_URL, http_client=client) as (read, write, _):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=60),
                                     client_info=Implementation(name="python-oauth-demo", version="0.1.0")) as session:
                trace.step("MCP → initialize; then notifications/initialized")
                info = await session.initialize()
                trace.say(f"  ← Server: {info.serverInfo.name}; protocol: {info.protocolVersion}")
                trace.step("MCP → tools/list (discover tool names and input schemas)")
                tools = []
                cursor = None
                while True:
                    page = await session.list_tools(cursor=cursor)
                    tools.extend(page.tools)
                    if not page.nextCursor:
                        break
                    cursor = page.nextCursor
                for tool in tools:
                    trace.say(f"  • {tool.name}")
                trace.say(f"  Discovered {len(tools)} available read-only tools.")
                selected = next((tool for tool in tools if tool.name == "search_repositories"), None)
                if selected is None:
                    raise DemoError("GitHub did not advertise search_repositories in this toolset.")
                trace.say("\n  Discovered input schema for search_repositories:")
                trace.say(json.dumps(selected.inputSchema, indent=2))
                arguments = {"query": f"user:{username} fork:true", "perPage": args.limit,
                             "page": 1, "sort": "updated", "order": "desc", "minimal_output": True}
                trace.step("MCP → tools/call: search_repositories (one tool call)")
                trace.say(json.dumps({"name": selected.name, "arguments": arguments}, indent=2))
                result = await session.call_tool(selected.name, arguments=arguments)
                trace.say(f"  ← tools/call result: isError={result.isError}")
                if result.isError or args.show_json:
                    output = trace.safe(json.dumps(result.model_dump(mode="json", exclude_none=True), indent=2, ensure_ascii=False))
                    trace.say(output[:args.max_chars])
                    if len(output) > args.max_chars:
                        trace.say(f"  … JSON output truncated ({len(output)} characters total; use --max-chars to show more).")
                if result.isError:
                    raise DemoError("The MCP repository search reported an error. Check the printed result and OAuth permissions.")
                display_repositories(repository_payload(result), username, args.limit, trace)


async def run(args, trace):
    client_id = os.environ.get("GITHUB_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GITHUB_CLIENT_SECRET", "").strip()
    trace.hide(client_secret)
    if not args.discover_only and (not client_id or not client_secret):
        raise DemoError("Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in .env or your environment. See README.md for OAuth App setup.")
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=False) as client:
        endpoints = await discover(client, trace)
        if args.discover_only:
            trace.step("Discovery complete; no login or credentials needed")
            return
        token = await authorize(client, endpoints, client_id, client_secret, args, trace)
        username = await github_identity(client, token, trace)
        if args.reset_auth:
            await reset_authorization(client, token, client_id, client_secret, username, trace)
            token = await authorize(client, endpoints, client_id, client_secret, args, trace)
            username = await github_identity(client, token, trace)
    await run_mcp(token, username, args, trace)
    trace.step("Done — MCP connection closed; no tokens saved to disk")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=20, help="maximum repositories in the single tool call, 1–100 (default: 20)")
    parser.add_argument("--scopes", default="read:user repo", help="space-separated OAuth scopes (default: 'read:user repo', including private repository access)")
    parser.add_argument("--port", type=int, default=8765, help="localhost callback port (default: 8765)")
    parser.add_argument("--timeout", type=float, default=180, help="seconds to wait for authorization (default: 180)")
    parser.add_argument("--no-browser", action="store_true", help="print the login URL without opening a browser")
    parser.add_argument("--discover-only", action="store_true", help="verify public MCP/OAuth metadata without credentials or login")
    parser.add_argument("--reset-auth", action="store_true", help="revoke this user's grant and all tokens for this OAuth App, then request fresh consent (two browser flows)")
    parser.add_argument("--show-json", action="store_true", help="also print the raw MCP tool result")
    parser.add_argument("--max-chars", type=int, default=6000, help="maximum JSON result characters to print (default: 6000; does not truncate repository table)")
    args = parser.parse_args(argv)
    if args.reset_auth and args.discover_only:
        parser.error("--reset-auth cannot be combined with --discover-only")
    if not args.scopes.split() or any(not re.fullmatch(r"[A-Za-z0-9_:.-]+", scope) for scope in args.scopes.split()):
        parser.error("--scopes must be a space-separated list of OAuth scope names")
    args.scopes = " ".join(dict.fromkeys(args.scopes.split()))
    if not 1 <= args.limit <= 100:
        parser.error("--limit must be between 1 and 100 (one repository-search page)")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not 0 < args.timeout <= 600:
        parser.error("--timeout must be between 0 and 600 seconds")
    if args.max_chars < 1:
        parser.error("--max-chars must be positive")
    return args


def error_messages(error):
    if isinstance(error, BaseExceptionGroup):
        return "; ".join(dict.fromkeys(error_messages(child) for child in error.exceptions))
    if isinstance(error, httpx.HTTPStatusError):
        response = error.response
        parts = [f"MCP HTTP {response.status_code}."]
        challenge = response.headers.get("www-authenticate", "")
        parameters = dict(re.findall(r'([a-z_]+)="([^"\r\n]*)"', challenge, re.IGNORECASE))
        for key in ("error", "error_description", "scope"):
            if key in parameters:
                parts.append(f"OAuth {key}: {parameters[key]}")
        if parameters.get("error") == "insufficient_scope":
            parts.append("GitHub requires additional authorization for this tool. Rerun with --scopes including the scope above and approve the new GitHub consent request.")
        try:
            body = response.text.strip()
        except httpx.ResponseNotRead:
            body = ""
        if body:
            parts.append(f"Server response: {body}")
        request_id = response.headers.get("x-github-request-id")
        if request_id:
            parts.append(f"GitHub request ID: {request_id}")
        if not challenge and not body:
            parts.append("Check authorization, scopes, organization policies, and repository access.")
        return "\n".join(parts)
    if isinstance(error, httpx.RequestError):
        return "Network request failed. Check your connection and retry."
    return str(error) or type(error).__name__


def main(argv=None):
    args = parse_args(argv)
    # Library debug/access logs may contain callback URLs or transport data.
    logging.basicConfig(level=logging.CRITICAL)
    trace = Trace()
    trace.say("GitHub OAuth + MCP demo — no LLM required")
    try:
        if load_dotenv(ENV_FILE, override=False, interpolate=False):
            trace.say("  Loaded .env beside the script; existing environment variables take precedence.")
        asyncio.run(run(args, trace))
    except KeyboardInterrupt:
        trace.say("\nCancelled. No tokens saved to disk.")
        return 130
    except Exception as error:
        print(trace.safe(f"\nError: {error_messages(error)}"), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
