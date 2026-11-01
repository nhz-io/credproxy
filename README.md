# credproxy

A small local proxy for macOS that holds API keys in memory and adds them to allowed requests, so the
programs (and AI agents) making those requests never see the keys. Keys stay sealed with
[age](https://github.com/FiloSottile/age) on disk; the first request unlocks (e.g. one Touch ID with
[age-plugin-se](https://github.com/remko/age-plugin-se)) and the key serves every call until it idles out or you
lock it.

Clients get a fixed URL and send a **token** where the API key would go:

```bash
curl -H "Authorization: Bearer $(credproxy token runpod)" http://127.0.0.1:7777/runpod/v1/pods
```

credproxy checks that the request comes from this machine and carries the token, checks it against the service's
allowlist, swaps the token for the real key, forwards over HTTPS and returns the reply with the key scrubbed out.

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
| Daemon | LaunchAgent (`credproxy install`): starts at login, locked. If port is busy it retries for 30 s. launchd restarts it after a crash (any panic ends the process, so it never runs half-broken), not after a clean exit: `stop`, or a startup error such as a bad config, which goes to `credproxy.err.log` and shows a notification. |
| URL | `http://<listen>/<service>/<route prefix>/…`, `listen` fixed (default `127.0.0.1:7777`, loopback only). |
| Host check | Every request must say `Host: 127.0.0.1:<port>` (or `localhost:<port>`), else 403. A DNS-rebinding web page reaches 127.0.0.1 under its own domain name, which the browser puts in `Host`. |
| Token | Per service, random (256 bits) at every daemon start, **in memory only**: never written to disk. Clients get it with `credproxy token <service>` (control socket below) and send it in the service's own auth header (e.g. `Authorization: Bearer <token>`); compared in constant time. Missing or wrong → 401. After a daemon restart the old token gets 401: fetch the token at the start of a run, and again on a 401. |
| Unlock | On the first allowed request for a locked service (or `credproxy unlock`), one unlock job per service runs `age -d -i <identity> <secrets_dir>/<secret>.age` in its own process group; every request that needs the key waits for that job. A client that gives up doesn't cancel it. The plaintext is read from a pipe into a preallocated buffer (zeroed on lock). One line of printable ASCII. A failed unlock (Touch ID denied, 2-minute timeout) blocks new prompts from requests for 30 s. |
| Order | Host → token → allowlist → key. A request that would be refused never triggers an unlock. |
| Lock | After `idle_lock` without use (default 12 h), on `credproxy lock [service]`, and when the daemon exits. A lock during a pending unlock aborts it: age and its plugin are killed, which closes the prompt. Like pressing Cancel, that pauses new prompts from requests for 30 s. |
| Allowlist | Per route: `METHOD /path/{param}` rules (`{param}` = one segment of `[A-Za-z0-9._-]`, never `.`/`..`), or a GraphQL endpoint where only one `query` operation whose top-level fields are all listed passes (no mutations, subscriptions or fragments). Anything else → 403, never sent upstream. For GraphQL only the checked request is sent: `{query, variables, operationName}` re-serialised as JSON, `Content-Type: application/json`, no query string — so the upstream can't read anything that wasn't checked. |
| Upstream | HTTPS only (plain HTTP only to 127.0.0.1, for tests), no redirects followed, own `User-Agent: credproxy/<version>`, `Accept-Encoding: identity` (a compressed reply is refused: the key couldn't be scrubbed from it), 60 s timeout. Only `Content-Type` and `Accept` are forwarded from the client; its auth header, cookies and other headers are dropped. Request body ≤ 1 MiB, response ≤ 16 MiB. |
| Reply | Status, `Content-Type` and body, with every verbatim copy of the key replaced by `[REDACTED]`. |
| Control | Unix socket `ctl.sock` (0600) in a 0700 runtime dir, peer uid checked: token, status, unlock, lock, stop. |
| Log | `~/Library/Logs/credproxy.log` (0600): time, service, method, path, status, ms; unlocks and locks. No token, no query string, no key. Rotates at 1 MiB into one `.1` file; reopened if deleted. |
| Limits | At most 64 client connections at once (logged when reached), one request per connection, headers within 10 s, 5 minutes per connection. Unknown services get the same 401, with the same text, as a wrong token. |
| Hardening | Core dumps off; on macOS the daemon requests `PT_DENY_ATTACH` (not tested by the test suite). |

## Limits (read these)

- **Anything running as you can use an unlocked service**, within its allowlist — like ssh-agent. It cannot get the
  key through credproxy.
- **Other user accounts on the Mac** can reach the port, but can't get the token (it is only handed out over the
  control socket, to your user).
- **Using a locked service raises a Touch ID prompt** (with age-plugin-se). Deny prompts you didn't expect.
- **Root, or a process able to read the daemon's memory, can read the key.** Copies of it also pass through the
  HTTP client's buffers while a request is built; those are not zeroed.
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
# runtime_dir = "~/Library/Caches/credproxy"
# log = "~/Library/Logs/credproxy.log"

[services.runpod]
secret = "runpod/api-key"                          # ~/.secrets/runpod/api-key.age
# auth = { header = "Authorization", format = "Bearer {key}" }   # also how clients send the token

[[services.runpod.routes]]
prefix = "/v1"                                     # longest prefix wins
upstream = "https://rest.runpod.io/v1"
allow = ["GET /pods", "POST /pods", "GET /pods/{id}", "DELETE /pods/{id}", "GET /billing/pods"]
```

The daemon reads the config at start; after changing it, `credproxy restart`.

## Use

| Command | What |
|---|---|
| `credproxy status` | Running? Each service: locked, unlocking (waiting for Touch ID), or unlocked and for how long |
| `credproxy unlock <service>` | Unlock now (e.g. before a long job), instead of on the first request |
| `credproxy lock [<service>]` | Forget the key(s) now |
| `credproxy token <service>` | Print the current token (changes at every daemon start) |
| `credproxy install` / `uninstall` | LaunchAgent on/off |
| `credproxy restart` | Restart the daemon: locks everything, reloads the config, new token |
| `credproxy stop` | Stop it until `restart` or the next login |

## License

MIT
