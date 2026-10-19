# GitHub OAuth + MCP in a Python CLI

A small, local teaching demo. It opens GitHub login in your browser, receives an
OAuth callback, exchanges the code for a token, and uses the **official MCP Python
SDK** to discover tools and list your repositories with public/private labels. No LLM, web UI, or
deployed server is needed.

## 1. Register a GitHub OAuth App

Open [GitHub → Settings → Developer settings → OAuth Apps → New OAuth App](https://github.com/settings/applications/new).

| Field | Value |
| --- | --- |
| Application name | Python MCP OAuth Demo |
| Homepage URL | `http://127.0.0.1:8765` |
| Authorization callback URL | `http://127.0.0.1:8765/callback` |

Register the application, copy its **Client ID**, and generate a **Client Secret**.
Choose an **OAuth App**, rather than a GitHub App, for these instructions.
Device Flow does not need to be enabled. There is no Marketplace publication step.

## 2. Install

Requires Python 3.11 or later. From this directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 3. Set credentials and run

Create a `.env` file beside `github_mcp_demo.py` (or copy `.env.example`) with:

```dotenv
GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret
```

The CLI loads this file at startup, even when launched from another directory.
Existing shell environment variables take precedence over `.env` values. Values
are loaded literally, without `${...}` variable interpolation. `.env` is ignored
by Git; its contents are never printed by the demo. You can also supply the same
variables through your shell instead of using a file.

```sh
python github_mcp_demo.py
```

Sign in and approve the OAuth request in your browser. The terminal then shows
all available read-only MCP tools, the input schema for `search_repositories`,
the call arguments, and a table of up to **20 repositories owned by your account**.
Each row explicitly says **PUBLIC** or **PRIVATE** based on GitHub's metadata.
Forks are included. Results are sorted by most recently updated first.

Configure the maximum count at invocation time:

```sh
python github_mcp_demo.py --limit 20
python github_mcp_demo.py --limit 50
```

`--limit` accepts 1–100 (default: 20), matching GitHub's maximum search page size.
The demo makes exactly **one `tools/call`** after completing tool discovery.
It may return fewer repositories if fewer match or are accessible. The search
uses `user:YOUR_LOGIN fork:true`: it lists repositories you own, rather than
all organization or collaborator repositories you can access. GitHub search
indexing and token access determine which repositories appear.

Example output (illustrative names):

```text
  #  VISIBILITY  REPOSITORY
------------------------------------------------------------------------
  1  PRIVATE     your-login/internal-tool
  2  PUBLIC      your-login/mcp-demo
```

Other useful commands:

```sh
# Check GitHub's public discovery endpoints without credentials or a login.
python github_mcp_demo.py --discover-only

# Print the browser URL without automatically opening it.
python github_mcp_demo.py --no-browser

# Revoke the existing app grant and obtain fresh browser consent.
python github_mcp_demo.py --limit 20 --reset-auth

# Also display the raw MCP result JSON after the tool call.
python github_mcp_demo.py --show-json

# Change the callback port; also update the registered callback URL to match.
python github_mcp_demo.py --port 8766

python github_mcp_demo.py --help
```

## What each step demonstrates

1. **Unauthenticated MCP request:** the server returns HTTP 401 and a
   `WWW-Authenticate` header pointing to protected-resource metadata.
2. **Discovery:** read that metadata, then GitHub's OAuth metadata to find the
   authorization and token endpoints. This demo accepts GitHub.com endpoints only.
3. **OAuth preparation:** generate unpredictable `state` and an S256 PKCE
   challenge; start a temporary callback listener bound to `127.0.0.1`.
4. **Browser authorization:** GitHub authenticates you and obtains consent.
5. **Callback:** validate `state` and the issuer, and capture the code. Invalid
   callbacks are rejected without consuming the pending login attempt.
6. **Token exchange:** send the code, client secret, and PKCE verifier to GitHub.
7. **Identity check:** one direct GitHub REST request verifies which account
   signed in. This request is separate from MCP and labeled in the trace.
8. **MCP connection:** attach the token as `Authorization: Bearer …` over HTTPS.
9. **MCP initialization:** negotiate the protocol and send the initialized notification.
10. **`tools/list`:** discover tool names and input schemas, including pagination.
11. **One `tools/call`:** invoke `search_repositories` with `perPage` set to
    `--limit`, then print a table with explicit visibility labels. Both structured
    MCP responses and older JSON-in-text responses are supported. Missing
    visibility is labeled `UNKNOWN`, rather than assumed public.

OAuth grants access. MCP defines how the client discovers and invokes tools.
The SDK handles JSON-RPC IDs, initialization, and Streamable HTTP; the trace
explains the operations without dumping raw headers or credentials.

## Scope and token lifetime

The demo defaults to **`read:user repo`**: profile reading for the identity check,
and repository access so the search can include private repositories. GitHub can
advertise repository tools successfully but reject their invocation if `repo`
has not been granted. You can override scopes at invocation time:

```sh
python github_mcp_demo.py --scopes 'read:user'
```

Omitting `repo` can produce a scope challenge or exclude private repositories.
Review the requested permission in GitHub. The `repo` OAuth scope
includes broad read/write access to public and private repositories; GitHub's
OAuth Apps do not offer an equivalent read-only `repo` scope. The CLI still uses
only read-only MCP tools. A fresh OAuth App is useful for teaching:
GitHub may retain scopes previously granted to an existing
app. The trace reports the scopes returned by the token exchange.

The MCP connection uses GitHub's all-toolsets, read-only endpoint:
`https://api.githubcopilot.com/mcp/x/all/readonly`. Read-only mode restricts
exposed MCP tools; it does not change the underlying OAuth token's permissions.

Client secrets, authorization codes, PKCE verifiers, and tokens are hidden from
the normal trace. Tokens stay in process memory and are never saved by the demo.
Every run performs authorization again; GitHub may remember consent. This short
demo does not implement token refresh. Exiting does not revoke the grant: revoke
it under [GitHub → Settings → Applications](https://github.com/settings/applications)
when finished if desired. Each person running a copy should use their own OAuth
App credentials.

## Reset authorization for a demonstration

```sh
python github_mcp_demo.py --reset-auth --limit 20
```

The CLI already performs OAuth on every run because it saves no tokens. GitHub
can remember your app grant and skip showing consent again. `--reset-auth`
removes that remembered grant using GitHub's **Delete an app authorization** API.
This revokes **all tokens issued by this OAuth App for the selected account**,
including tokens from other runs or programs using this same app and account.
It does not delete your `.env` credentials, unregister the app, or sign you out
of GitHub.

Because no old token is stored, reset mode has two browser authorization flows:

1. Obtain a token and identify the account whose grant will be reset. An existing
   grant may let GitHub complete this first authorization without another consent screen.
2. Revoke the grant with app credentials and that token, then run OAuth again
   with fresh state and PKCE to show consent. Only the new token is used for MCP.

If revocation fails, the demo stops. After a successful reset and reauthorization,
the new grant remains valid; use `--reset-auth` again when you want another fresh
consent demonstration. Reset mode cannot be combined with `--discover-only`.

## Troubleshooting

- **Missing credentials:** set both variables in `.env` beside the script or
  export them in your shell. Unset old shell variables to use the `.env` values.
- **Callback mismatch or timeout:** use exactly `http://127.0.0.1:8765/callback`
  in the OAuth App settings; `localhost` is a different hostname. The browser
  must run on the same machine as the CLI. Run again to retry after denial.
- **Port already in use:** stop the other listener, or change `--port` and the
  registered callback URL together.
- **HTTP 403 with `insufficient_scope`:** tool discovery does not guarantee
  permission to invoke a tool. The CLI prints GitHub's requested scope. For
  `search_repositories`, GitHub lists `repo` as its challenge scope; rerun with
  `--scopes 'read:user repo'` and approve the additional grant in your browser.
  Permissions are never automatically broadened.
- **Other HTTP 401/403:** inspect the printed server response and request ID.
  Check credentials, account/organization policies, and rate limits.
- **Missing private repositories:** approve the `repo` scope. Only repositories
  owned by the signed-in user and visible to the token are searched; organization
  policies and search indexing may also affect results.
- **Truncated JSON:** increase `--max-chars` (default: 6000). This affects raw JSON
  displayed with `--show-json`; the repository table is not truncated.

## Tests

```sh
python -m unittest discover -s tests -v
```

Tests use fake credentials, a local callback listener, and mocked HTTP responses.
They exercise the actual MCP SDK's initialization, tool discovery, and tool call,
plus OAuth discovery, PKCE, state/issuer rejection, denial, token exchange,
grant reset, repository visibility labels, and configurable count limits.
They do not contact GitHub or open a browser. A live login still requires your
registered OAuth App credentials and browser consent.

## References

- [GitHub MCP host integration and OAuth discovery](https://github.com/github/github-mcp-server/blob/main/docs/host-integration.md)
- [GitHub OAuth authorization code flow and PKCE](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
- [GitHub MCP public repository access and scope challenges](https://github.com/github/github-mcp-server/blob/main/docs/scope-filtering.md)
- [GitHub MCP repository search](https://github.com/github/github-mcp-server/blob/main/pkg/github/search.go)
- [GitHub Delete an app authorization API](https://docs.github.com/en/rest/apps/oauth-applications#delete-an-app-authorization)
- [Official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk/tree/v1.x)
