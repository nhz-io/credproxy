# credproxy

A small local proxy for macOS that holds API keys in memory and adds them to allowed requests, so the
programs (and AI agents) making those requests never see the keys. Keys stay sealed with
[age](https://github.com/FiloSottile/age) on disk; one unlock (e.g. one Touch ID with
[age-plugin-se](https://github.com/remko/age-plugin-se)) serves every call until it idles out or you lock it.

```bash
credproxy run runpod -- python launcher.py sweep
```

The launcher gets `RUNPOD_PROXY=http://127.0.0.1:<port>/<token>` and calls `$RUNPOD_PROXY/pods`;
credproxy checks the call against the service's allowlist, adds `Authorization: Bearer <key>`, forwards it over
HTTPS and returns the reply with the key scrubbed out.

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
| Unlock | `credproxy run <service>` starts the daemon if needed and asks it to unlock: it runs `age -d -i <identity> <secrets_dir>/<secret>.age` and reads the plaintext from a pipe into memory (zeroed on lock). The key must be one line of printable ASCII. |
| Token | 256-bit random per unlock, compared in constant time; locking invalidates it. |
| Lock | After `idle_lock` without use (default 12 h), on `credproxy lock [service]`, on `stop`, and when the daemon exits. |
| Transport | Clients: HTTP on `127.0.0.1:<random port>`, path `/<token>/…`. Control: Unix socket `ctl.sock` (0600) in a 0700 runtime dir, peer uid checked. |
| Allowlist | Per route: `METHOD /path/{param}` rules (`{param}` = one segment of `[A-Za-z0-9._-]`, never `.`/`..`), or a GraphQL endpoint where only one `query` operation whose top-level fields are all listed passes (no mutations, subscriptions or fragments). Anything else → 403, never sent upstream. |
| Upstream | HTTPS only (plain HTTP only to 127.0.0.1, for tests), no redirects followed, own `User-Agent: credproxy/<version>`, 60 s timeout. Only `Content-Type` and `Accept` are forwarded from the client; its `Authorization`, cookies and other headers are dropped. Request body ≤ 1 MiB, response ≤ 16 MiB. |
| Reply | Status, `Content-Type` and body, with every verbatim copy of the key replaced by `[REDACTED]`. |
| Log | `~/Library/Logs/credproxy.log` (0600): time, service, method, path, status, ms. No token, no query string, no key. |
| Hardening | Core dumps off; on macOS the daemon requests `PT_DENY_ATTACH` (not tested by the test suite). |

## Limits (read these)

- **Anything running as you can use an unlocked service**, within its allowlist — like ssh-agent. It can connect to
  the control socket and get the URL. It cannot read the key through credproxy.
- **Anything running as you can also trigger an unlock** of a locked service. That shows a Touch ID prompt
  (with age-plugin-se); deny prompts you didn't expect.
- **Root, or a process able to read the daemon's memory, can read the key.** Copies of it also pass through the
  HTTP client's buffers while a request is built; those are not zeroed.
- **Scrubbing catches the key verbatim only**, not encoded forms (base64, URL-encoded).
- **The allowlist covers method and path.** Query strings and REST request bodies are passed through unchecked, so
  an allowed `POST /pods` can create any pod the API allows.

## Install

```bash
brew install --cask nhz-io/tap/credproxy
```

Apple Silicon. Needs `age` (and `age-plugin-se` for a Secure Enclave identity) on `PATH`:
`brew install age age-plugin-se`.

### Build from source

```bash
cargo test
```

```bash
cargo install --locked --path .
```

The tests need `age` and `age-keygen`; they use a throwaway identity and a fake key.

## Config

`~/.config/credproxy/config.toml` (or `$CREDPROXY_CONFIG`). Example: [examples/runpod.toml](examples/runpod.toml).

```toml
idle_lock = "12h"                                  # s, m or h
# age = "age"                                      # defaults shown
# identity = "~/.config/age/se-identity.txt"
# secrets_dir = "~/.secrets"
# runtime_dir = "~/Library/Caches/credproxy"
# log = "~/Library/Logs/credproxy.log"

[services.runpod]
secret = "runpod/api-key"                          # ~/.secrets/runpod/api-key.age
env = "RUNPOD_PROXY"                               # variable the child gets
# auth = { header = "Authorization", format = "Bearer {key}" }

[[services.runpod.routes]]
prefix = "/graphql"                                # longest prefix wins
upstream = "https://api.runpod.io/graphql"
graphql_queries = ["gpuTypes"]

[[services.runpod.routes]]
prefix = "/"
upstream = "https://rest.runpod.io/v1"
allow = ["GET /pods", "POST /pods", "GET /pods/{id}", "DELETE /pods/{id}", "GET /billing/pods"]
```

The daemon reads the config at start; after changing it, `credproxy stop` (the next `run` starts a new one).

## Use

```bash
credproxy run <service> [--] <command> [args...]
```

```bash
credproxy status
```

```bash
credproxy lock [<service>]
```

```bash
credproxy stop
```

A wrapper per tool keeps it short, e.g. `~/.local/bin/runpod`:

```zsh
#!/bin/zsh
exec credproxy run runpod -- python -I ~/src/launcher.py "$@"
```

## License

MIT
