# credproxy

A small local proxy for macOS that holds API keys in memory and adds them to allowed requests, so the
programs (and AI agents) making those requests never see the keys. Keys stay sealed with
[age](https://github.com/FiloSottile/age) on disk; the first request unlocks (e.g. one Touch ID with
[age-plugin-se](https://github.com/remko/age-plugin-se)) and the key serves every call until it idles out or you
lock it.

Clients get a fixed URL and a **token** that they send as if it were the API key:

```bash
export RUNPOD_API_URL=http://127.0.0.1:7777/runpod/v1 RUNPOD_API_KEY=<token>
```

credproxy checks the token, checks the call against the service's allowlist, swaps the token for the real key,
forwards over HTTPS and returns the reply with the key scrubbed out. The token is useless anywhere but this proxy.

## Why

- An agent that runs a tool which needs an API key would otherwise get the key in its env, argv or a file, and
  from there into logs and transcripts.
- Decrypting on every call means a Touch ID prompt on every call.
- Existing credential-injecting proxies (OneCLI, Infisical Agent Vault) keep keys in their own vault or database and
  run as Docker or server stacks; agent-airlock reads keys from plaintext JSON. None decrypts through an
  age plugin.

## Design

| Piece | How |
|---|---|
| Daemon | LaunchAgent (`credproxy install`): starts at login, locked; restarted if it exits. |
| URL | `http://<listen>/<service>/<route prefix>/…`, `listen` fixed (default `127.0.0.1:7777`, loopback only). |
| Token | Per service, 256-bit random, in `<state_dir>/tokens/<service>` (0600, dir 0700); stable until `credproxy rotate`. The client sends it in the service's own auth header (e.g. `Authorization: Bearer <token>`); compared in constant time. Missing or wrong → 401. |
| Client env | Per service `[env]` templates (`{base}`, `{token}`); `credproxy env` prints them as `export` lines. Set them only where they're used (shell profile, a tool's own config), not globally: crash and telemetry reports of unrelated apps can include environment variables. |
| Unlock | On the first allowed request for a locked service (or `credproxy unlock`): `age -d -i <identity> <secrets_dir>/<secret>.age`, plaintext read from a pipe into memory (zeroed on lock). One line of printable ASCII. A failed unlock (Touch ID denied) blocks new prompts from requests for 30 s. |
| Order | Token → allowlist → key. A request that would be refused never triggers an unlock. |
| Lock | After `idle_lock` without use (default 12 h), on `credproxy lock [service]`, and when the daemon exits. |
| Allowlist | Per route: `METHOD /path/{param}` rules (`{param}` = one segment of `[A-Za-z0-9._-]`, never `.`/`..`), or a GraphQL endpoint where only one `query` operation whose top-level fields are all listed passes (no mutations, subscriptions or fragments). Anything else → 403, never sent upstream. |
| Upstream | HTTPS only (plain HTTP only to 127.0.0.1, for tests), no redirects followed, own `User-Agent: credproxy/<version>`, 60 s timeout. Only `Content-Type` and `Accept` are forwarded from the client; its auth header, cookies and other headers are dropped. Request body ≤ 1 MiB, response ≤ 16 MiB. |
| Reply | Status, `Content-Type` and body, with every verbatim copy of the key replaced by `[REDACTED]`. |
| Control | Unix socket `ctl.sock` (0600) in a 0700 runtime dir, peer uid checked: status, unlock, lock, rotate, stop. |
| Log | `~/Library/Logs/credproxy.log` (0600): time, service, method, path, status, ms. No token, no query string, no key. |
| Hardening | Core dumps off; on macOS the daemon requests `PT_DENY_ATTACH` (not tested by the test suite). |

## Limits (read these)

- **The token is in the environment of the shells and tools you give it to**, and in the token file. Anything
  running as you can read the file and use the proxy within the allowlist — like ssh-agent. It cannot get the key through
  credproxy.
- **Using a locked service raises a Touch ID prompt** (with age-plugin-se). Deny prompts you didn't expect.
- **Root, or a process able to read the daemon's memory, can read the key.** Copies of it also pass through the
  HTTP client's buffers while a request is built; those are not zeroed.
- **Other local users can reach the port**, but need the token (0600 file, your processes' env).
- **Scrubbing catches the key verbatim only**, not encoded forms (base64, URL-encoded).
- **The allowlist covers method and path.** Query strings and REST request bodies are passed through unchecked, so
  an allowed `POST /pods` can create any pod the API allows.

## Install

```bash
brew install --cask nhz-io/tap/credproxy
```

Apple Silicon. Needs `age` (and `age-plugin-se` for a Secure Enclave identity): `brew install age age-plugin-se`.
Write the config (below), then:

```bash
credproxy install
```

Shell profile (`~/.zshrc`), for terminals and tools started from them:

```zsh
(( $+commands[credproxy] )) && eval "$(credproxy env)"
```

### Build from source

```bash
cargo test
```

```bash
cargo install --locked --path .
```

The tests need `age` and `age-keygen`; they use a throwaway identity, a fake key and a free port, and never touch
launchd.

## Config

`~/.config/credproxy/config.toml` (or `$CREDPROXY_CONFIG`). Full example: [examples/runpod.toml](examples/runpod.toml).

```toml
idle_lock = "12h"                                  # s, m or h
listen = "127.0.0.1:7777"
# age = "age"                                      # defaults shown
# identity = "~/.config/age/se-identity.txt"
# secrets_dir = "~/.secrets"
# state_dir = "~/Library/Application Support/credproxy"
# runtime_dir = "~/Library/Caches/credproxy"
# log = "~/Library/Logs/credproxy.log"

[services.runpod]
secret = "runpod/api-key"                          # ~/.secrets/runpod/api-key.age
# auth = { header = "Authorization", format = "Bearer {key}" }   # also how clients send the token

[services.runpod.env]
RUNPOD_API_URL = "{base}/v1"                       # {base} = http://127.0.0.1:7777/runpod
RUNPOD_API_KEY = "{token}"

[[services.runpod.routes]]
prefix = "/v1"                                     # longest prefix wins
upstream = "https://rest.runpod.io/v1"
allow = ["GET /pods", "POST /pods", "GET /pods/{id}", "DELETE /pods/{id}", "GET /billing/pods"]
```

The daemon reads the config at start; after changing it, `credproxy stop` (launchd starts it again).

## Use

| Command | What |
|---|---|
| `credproxy status` | Running? Which services are unlocked, and for how long |
| `credproxy unlock <service>` | Unlock now (e.g. before a long job), instead of on the first request |
| `credproxy lock [<service>]` | Forget the key(s) now |
| `credproxy rotate <service>` | New token; the old one stops working. New shells and apps get it |
| `credproxy env` | Client variables as `export` lines (for `eval` in a shell profile) |
| `credproxy install` / `uninstall` | LaunchAgent on/off |
| `credproxy stop` | Stop the daemon (locks everything; launchd starts a fresh one) |

## License

MIT
