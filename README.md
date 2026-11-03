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

S3-compatible storage (RunPod network volumes, Cloudflare R2, AWS S3) works the same way for the client, but the
secret never leaves credproxy at all: it signs each allowed request with AWS SigV4 instead.

```bash
curl -H "Authorization: Bearer $(credproxy token runpod-s3)" http://127.0.0.1:7777/runpod-s3/eu-ro-1/<volume>/<key>
```

Backblaze B2's native API (buckets and application keys, which its S3 API can't manage): at unlock credproxy trades
the key for a B2 token and forgets the key; calls are allowed by name.

```bash
curl -X POST -H "Authorization: Bearer $(credproxy token b2)" http://127.0.0.1:7777/b2/b2api/v3/b2_list_buckets -d '{}'
```

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
| Daemon | LaunchAgent (`credproxy install`): starts at login, locked. If the port is busy it retries for 30 s. launchd restarts it after a crash (any panic ends the process, so it never runs half-broken), not after a clean exit: `stop`, or a startup error such as a bad config, which goes to `credproxy.err.log` and shows a notification. |
| URL | `http://<listen>/<service>/<route prefix>/…`, `listen` fixed (default `127.0.0.1:7777`, loopback only). |
| Host check | Every request must say `Host: 127.0.0.1:<port>` (or `localhost:<port>`), else 403. A DNS-rebinding web page reaches 127.0.0.1 under its own domain name, which the browser puts in `Host`. |
| Token | Per service, random (256 bits) at every daemon start, **in memory only**: never written to disk. Clients get it with `credproxy token <service>` (control socket below) and send it in the service's own auth header (e.g. `Authorization: Bearer <token>`); compared in constant time. Missing or wrong → 401. After a daemon restart the old token gets 401: fetch the token at the start of a run, and again on a 401. |
| Unlock | On the first allowed request for a locked service (or `credproxy unlock`), one unlock job per service runs `age -d -i <identity> <secrets_dir>/<secret>.age` in its own process group; every request that needs the key waits for that job. A client that gives up doesn't cancel it. The plaintext is read from a pipe into a preallocated buffer (zeroed on lock). One line of printable ASCII, or two for S3 and B2 services. A B2 key is traded for a token at once and zeroed then, not kept until lock (B2 row). A failed unlock (Touch ID denied, 2-minute timeout) blocks new prompts from requests for 30 s. |
| Order | Host → token → allowlist → key. A request that would be refused never triggers an unlock. |
| Lock | After `idle_lock` without use (default 12 h, wall-clock: time asleep counts; checked at every use, not only by the periodic sweep), on `credproxy lock [service]`, and when the daemon exits. A lock during a pending unlock aborts it: age and its plugin are killed, which closes the prompt. Like pressing Cancel, that pauses new prompts from requests for 30 s. |
| Allowlist | Per route: `METHOD /path/{param}` rules (`{param}` = one segment of `[A-Za-z0-9._-]`, never `.`/`..`; a trailing `/` is part of the path, so `GET /instances/` matches `/instances/` only, for APIs that redirect one to the other), or a GraphQL endpoint where only one `query` operation whose top-level fields are all listed passes (no mutations, subscriptions or fragments). Anything else → 403, never sent upstream. For GraphQL only the checked request is sent: `{query, variables, operationName}` re-serialised as JSON, `Content-Type: application/json`, no query string — so the upstream can't read anything that wasn't checked. |
| Upstream | HTTPS only (plain HTTP only to 127.0.0.1, for tests), no redirects followed, own `User-Agent: credproxy/<version>`. Key-in-header routes: `Accept-Encoding: identity` (a compressed reply is refused: the key couldn't be scrubbed from it), 60 s timeout. Only `Content-Type` and `Accept` are forwarded from the client; its auth header, cookies and other headers are dropped. Request body ≤ 1 MiB, response ≤ 16 MiB. |
| Reply | Key-in-header routes: status, `Content-Type`, `Retry-After` and body, with every verbatim copy of the key replaced by `[REDACTED]`. (S3: see below.) |
| S3 (SigV4) | For services with `auth.sigv4`. The sealed file holds two lines: access key id, secret. Path-style only (`/<bucket>/<key>`). The operation is worked out from method + path + query and must be in the route's `ops`: `GetObject`, `HeadObject`, `PutObject`, `DeleteObject`, `HeadBucket`, `ListObjectsV2`, `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListParts`. Nothing else passes (no ListBuckets, bucket admin, ACLs, tagging, versions, DeleteObjects). Keys are percent-decoded and refused if they hold `.`/`..` or empty segments or control characters; list prefixes get the same check; optional `key_prefixes` (directories, ending in `/`) limit keys and list prefixes, and refuse HeadBucket. Path and query are re-encoded canonically, then signed with [`aws-sigv4`](https://crates.io/crates/aws-sigv4). Only these client headers go upstream, all signed: `Content-Type`, `Content-MD5`, `Content-Encoding`, `Content-Disposition`, `Content-Language`, `Cache-Control`, `Expires`, `Range`, `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, `If-Range` (so a resumed download keeps its precondition). Any of them given twice → 400; `Content-Encoding: aws-chunked` → 400. A client `x-amz-*` header other than `x-amz-content-sha256` (and `x-amz-date`, `x-amz-user-agent`, replaced by the signature) refuses the call: copy, metadata, tagging, SSE and checksum headers would otherwise be dropped and change what the call does (a CopyObject would become an empty PutObject). |
| S3 payload | PutObject / UploadPart bodies stream through (≤ 512 MiB each) when the client sends their SHA-256 in `x-amz-content-sha256`; the signature covers it and the server checks the body against it. Other bodies (≤ 1 MiB, e.g. the CompleteMultipartUpload XML) are hashed by credproxy. `UNSIGNED-PAYLOAD` only where the route sets `unsigned_payload = true`; aws-chunked (`STREAMING-…`) is refused. S3 calls have no overall time limit: a transfer runs as long as it keeps moving. One that moves no bytes for `s3_idle` (60 s) in either direction is cut off, including a client that stops reading or an upstream that stops accepting (a per-connection watchdog). Once a request is fully sent, the upstream may take up to `s3_reply_wait` (2 h) to reply to an upload or a CompleteMultipartUpload (the whole completion reply, keep-alive bytes included, must be done within it), and `s3_idle` for anything else (plus `s3_connect_timeout` for small requests, whose clock starts before connecting), else 504; after such a 504 the outcome is unknown (the upload may still complete), so check the object (HEAD, ListParts) before retrying. Cut-offs are logged (`… cut off: no progress for 60s`). A cut-off transfer is an error at both ends, never a short success. S3 goes upstream over HTTP/1.1 only. Header values must be ASCII (else 400, rather than being dropped). |
| S3 reply | Successful replies stream back as they are, with `Content-Type`, `Content-Encoding`, `Content-Disposition`, `Cache-Control`, `Content-Length`, `Content-Range`, `Accept-Ranges`, `ETag`, `Last-Modified` (others, e.g. `x-amz-meta-*`, are dropped): the secret was never sent, so it can't come back in them. Error replies are buffered and scrubbed of the access key id and the secret, keeping `ETag`, `Last-Modified`, `Content-Range` and `Retry-After`. A CompleteMultipartUpload counts as done only when its reply has the result element: an `<Error>` body (S3 sends one after a 200 when the failure comes late), an empty or cut-off reply become a 502. A success reply with neither a length nor chunked framing is refused (502): a connection cut short would look complete. When a state-changing call fails after it was sent, the reply says the outcome is unknown. |
| B2 | For services with `auth.b2`. The sealed file holds two lines: key id, application key. At unlock credproxy decrypts them, calls `b2_authorize_account` itself (HTTP Basic; a connection failure or 5xx is tried again, up to 3 tries within 30 s, while the key is still held) and keeps only the reply's `authorizationToken`, `apiUrl`, `downloadUrl` and `accountId`; credproxy's own buffers holding the key (the decrypted pair, the `key id:key` string, the Basic header string) are zeroed as soon as the reply's headers are in (the header value handed to the HTTP client is not: see Limits). The authorize reply never reaches a client. `apiUrl`/`downloadUrl` must be `https://…backblazeb2.com` without a path, else the unlock fails. API routes (`b2 = { calls = [...] }`, prefix `/b2api/<version>`, the version calls go out with): `POST <prefix>/<call>` for a listed call only, no query string, body a JSON object (≤ 1 MiB; empty = `{}`), sent as `POST <apiUrl>/b2api/<version>/<call>` with the B2 token. For `b2_list_buckets`, `b2_create_bucket`, `b2_update_bucket`, `b2_delete_bucket`, `b2_create_key`, `b2_list_keys` credproxy fills in `accountId`; a body that has one is refused (403) before unlocking. `b2_authorize_account` and calls whose reply is a credential (uploads go through an upload route instead) that works against B2 directly (`b2_get_upload_url`, `b2_get_upload_part_url`, `b2_get_download_authorization`) or that don't go to the apiUrl (`b2_upload_file`, `b2_upload_part`, `b2_download_file_by_id`) can't be allowed (config check). Replies are buffered (≤ 16 MiB) and scrubbed of the B2 token, like key-in-header replies; `b2_create_key`'s new application key is passed on (that's its point) and, like every body, never logged. Download routes (`b2 = { download = true }`): `GET`/`HEAD <prefix>/<bucket>/<file name>`, no query string (B2 takes tokens there), the name checked and re-encoded like an S3 key, `Range` forwarded (no other client header: files stored with SSE-C, whose key B2 wants in `X-Bz-Server-Side-Encryption-Customer-*` headers, can't be downloaded; and nothing that pins the version: B2 serves the newest version of a name, so a client resuming with `Range` must check that `X-Bz-File-Id` is still the one it started with); the reply streams back (watchdog, `s3_idle` and `s3_connect_timeout` as for S3) with `Content-*`, `Accept-Ranges`, `Cache-Control`, `Expires`, `X-Bz-File-Id`, `X-Bz-File-Name`, `X-Bz-Content-Sha1`, `X-Bz-Upload-Timestamp`, `X-Bz-Info-*` and the SSE/retention headers; a header holding the token is dropped. Error replies are buffered and scrubbed. Upload routes (`b2 = { upload = true }`): `PUT <prefix>/<bucket>/<file name>` (name checked and encoded as for downloads, no query string) with `Content-Length` (B2 takes no chunked bodies; no size limit of credproxy's own, B2 has its own) and the body's SHA-1 in `X-Bz-Content-Sha1` (40 hex digits; B2 checks the body against it), optionally `Content-Type` (default `b2/x-auto`) and `X-Bz-Info-src_last_modified_millis`. Any other `X-Bz-*` header (SSE, retention, other file info) and `Content-Encoding`, `Content-Disposition`, `Content-Language`, `Content-Range`, `Expires` refuse the upload (403), as do bad values (400), before unlocking. credproxy looks the bucket's id up once per session (`b2_list_buckets` by name) and gets upload URLs itself (`b2_get_upload_url`; an `https://…backblaze.com` or `…backblazeb2.com` URL, else refused): each upload takes one to itself (B2 refuses a token another upload is using), puts it back after success and drops it after any failure, so parallel uploads get their own. The body streams through (watchdog and `s3_idle`, then up to `s3_reply_wait` for B2's reply), never buffered, so credproxy can't replay a failed upload: when B2 refuses it with 401 (but not `unauthorized`), 408, 429 or 5xx, or it breaks off before the body was sent, nothing was stored and the client gets **503** `upload not stored …: retry` (the retry gets a new upload URL); when it breaks off after the body was sent, **502**/**504** say the outcome is unknown (check with `b2_list_file_names` before uploading again). B2's reply (fileId, fileName, contentLength, contentSha1, …) is passed on scrubbed of the account and upload tokens. A bucket deleted through credproxy (`b2_delete_bucket`), or one B2 no longer knows by its cached id (`bad_bucket_id`: deleted, maybe recreated, elsewhere), is forgotten with its upload URLs and looked up again. Uploads reach any bucket of the account, like the other B2 routes. The body isn't read until the service is unlocked and the upload URL is in: a client uploading to a locked service needs no write timeout (or runs `credproxy unlock b2` first). In paths, a space is `%20` (a `+` is a plus sign, B2's `+`-for-space applies to its own replies only). |
| B2 token end | B2 tokens last at most 24 h, and the key is gone, so a new token needs a new unlock. The service locks `relock_after` (default 23 h, wall-clock: time asleep counts, as it does for B2) after its unlock, or after `idle_lock` without use, whichever comes first; the next request unlocks again (Touch ID) as for any locked service. When B2 answers 401 `expired_auth_token` or `bad_auth_token`, or a 401 without a code (e.g. a `HEAD`'s) to a token that has already worked (a 2xx, or a B2 error about the call; a front end's 5xx doesn't count), the service locks and the client gets **503** `B2 token expired or revoked …: retry`; credproxy doesn't replay the call itself (it may have changed something). A codeless 401 to a token that hasn't worked yet is a 502 instead, so a refusal doesn't make each retry raise Touch ID; B2's `unauthorized` 401 (the token is good but may not do this) is passed on. `credproxy lock` during an unlock also stops an authorize in flight (no further tries; the key is zeroed). The trade-off: one Touch ID per token (at most about once a day), in return for the key never staying in memory. |
| Control | Unix socket `ctl.sock` (0600) in a 0700 runtime dir, peer uid checked: token, status, unlock, lock, stop. |
| Log | `~/Library/Logs/credproxy.log` (0600): time, service, method, path, status, ms; unlocks and locks. No token, no query string, no key. Rotates at 1 MiB into one `.1` file; reopened if deleted. |
| Limits | At most 64 client connections at once (logged when reached), one request per connection, headers within 10 s, a small request body within 60 s, 5 minutes per connection (S3 calls: as long as they make progress, see above). Unknown services get the same 401, with the same text, as a wrong token. |
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
  an allowed `POST /pods` can create any pod the API allows. (S3 routes do check the query.)
- **B2 download bodies are not scrubbed** (they stream): a file whose content is the B2 token would pass. Every
  other B2 reply is.
- **A B2 API route passes request bodies unchecked**, like other routes: an allowed `b2_create_key` can create a
  key with any capabilities the master key has, an allowed `b2_delete_bucket` can delete any bucket B2 lets it.
- **The B2 token isn't zeroed everywhere**: credproxy's copy is (when the session ends), but the JSON parser and the
  HTTP client may leave copies of it in freed memory, as they do with keys (above). Likewise the application key:
  credproxy's own buffers are zeroed once the authorize reply's headers are in, but the Basic header value handed to
  the HTTP client (and its internal buffers) is freed without zeroing.
- **A resumed B2 download can join two versions** if the name was uploaded again in between: check `X-Bz-File-Id`
  on every part.
- **The last bytes of an upload are in flight unseen**: once the whole body is handed to the upstream connection,
  silence counts as the upstream working (up to `s3_reply_wait`), so an upstream that stops reading in that last
  stretch is only noticed then.
- **Many clients, services and endpoints at once** are fine (up to 64 connections in all). A service has one key
  and one token shared by all its clients, so the log can't tell clients apart; a second account is a second
  service. For an S3 service the token header can't be one credproxy forwards upstream (config check).
- **An S3 route reaches every bucket the key can**, unless `key_prefixes` narrows it: an allowed `DeleteObject`
  can delete any object there.

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
launchd. The S3 tests run an S3 server in process ([s3s-fs](https://crates.io/crates/s3s-fs)) that checks every
signature and body hash, plus a scripted upstream for faults. They check that bytes arrive exactly (every size
around the 1 MiB and part boundaries, random data, parallel multipart parts, ranges across part boundaries, what the
upstream itself receives), that failures are errors and never short files (truncated or stalled downloads, a client
hanging up mid-upload), Expect: 100-continue, and 60 random keys with awkward characters through PUT, GET and a
paginated listing. The B2 tests run a fake B2 (authorize, calls, downloads): one authorize per unlock, the token
going up and scrubbed coming back, `accountId` filled in, refused calls and paths never unlocking, expiry by time and
by a 401 locking and the retry unlocking again (B2's `unauthorized` passing through), authorize retries, a download
waiting through a slow unlock under a 1 s `s3_idle`, ranges and header filtering on downloads, bad authorize replies
failing the unlock, `credproxy lock` stopping an authorize in flight, a codeless 401 locking only a token that has
worked (a front end's 5xx doesn't count), a slow download error body under a 1 s `s3_idle`, `version = "v4"` going
out as v4, uploads (20 MiB byte-exact with its SHA-1, the bucket id and upload URL reused, parallel uploads on their
own URLs, refusals before unlocking, B2's refusals as retry or pass-through with the URL dropped, an ended account
token locking), and no key or token in the log. Signing is also checked against AWS's published examples. Also covered: refused calls never
unlock, lock or stop during an upload (finishes intact / never completes), 304/416/404/307 replies, more parallel
parts than the connection limit, the log never showing queries, and (simulated time) the idle cut-off and connection
lifetimes. `CREDPROXY_TEST_PYTHON=<python with boto3> cargo test` adds a real boto3 run through the proxy. `cargo test --release --test s3 -- --ignored --nocapture` also runs the slow ones: 600 MB up and
down with the daemon's memory printed (7 MiB idle, 11–12 MiB peak on an M-series Mac), a slow reader (memory stays flat), and a stalled
download and upload each cut off after 60 s.

## Config

`~/.config/credproxy/config.toml` (or `$CREDPROXY_CONFIG`). Full example: [examples/runpod.toml](examples/runpod.toml).

```toml
idle_lock = "12h"                                  # s, m or h
# s3_idle = "60s"                                  # S3 and B2 downloads: cut a transfer after this long without bytes moving (≤ 24h)
# s3_reply_wait = "2h"                             # S3: how long the upstream may take to reply once sent (≤ 168h)
# s3_connect_timeout = "30s"                       # S3 and B2 downloads: connecting to the upstream (DNS, TCP, TLS) (≤ 5m)
listen = "127.0.0.1:7777"
# age = "age"                                      # defaults shown
# identity = "~/.config/age/se-identity.txt"
# secrets_dir = "~/.secrets"
# runtime_dir = "~/Library/Caches/credproxy"
# log = "~/Library/Logs/credproxy.log"

[services.runpod]
secret = "runpod/api-key"                          # ~/.secrets/runpod/api-key.age
# auth = { header = "Authorization", format = "Bearer {key}" }   # also how clients send the token
# auth = { header = "api_key", format = "{key}" }   # any HTTP header name, except ones credproxy sets or forwards
#   (Content-Type, Accept, Accept-Encoding, User-Agent) and connection headers (Host, Content-Length, …)

[[services.runpod.routes]]
prefix = "/v1"                                     # longest prefix wins
upstream = "https://rest.runpod.io/v1"
allow = ["GET /pods", "POST /pods", "GET /pods/{id}", "DELETE /pods/{id}", "GET /billing/pods",
         "GET /networkvolumes", "POST /networkvolumes", "GET /networkvolumes/{id}", "DELETE /networkvolumes/{id}"]
```

An S3-compatible service (here RunPod network volumes; one route per datacenter):

```toml
[services.runpod-s3]
secret = "runpod/s3-key"                           # two lines: access key id (user_…), secret (rps_…)
auth = { sigv4 = { service = "s3" } }              # clients still send "Authorization: Bearer <token>"

[[services.runpod-s3.routes]]
prefix = "/eu-ro-1"
upstream = "https://s3api-eu-ro-1.runpod.io"
s3 = { region = "EU-RO-1", ops = ["GetObject", "HeadObject", "PutObject", "DeleteObject", "ListObjectsV2",
       "CreateMultipartUpload", "UploadPart", "CompleteMultipartUpload", "AbortMultipartUpload"] }
# key_prefixes = ["runs/"]                         # optional
# unsigned_payload = true                          # optional: let clients skip the body hash
```

Cloudflare R2: `upstream = "https://<account id>.r2.cloudflarestorage.com"`, `region = "auto"`.

Clients send `Authorization: Bearer <token>` instead of signing, so stock SDK defaults need adjusting. boto3
(tested: [tests/boto3_client.py](tests/boto3_client.py), incl. multipart `upload_file`/`download_file`):

```python
def credproxy_auth(request, **_):                  # the token instead of a signature, plus the body's SHA-256
    body = request.body or b""
    if hasattr(body, "read"):
        pos = body.tell(); data = body.read(); body.seek(pos)
    else:
        data = body.encode() if isinstance(body, str) else bytes(body)
    request.headers["x-amz-content-sha256"] = hashlib.sha256(data).hexdigest()
    request.headers["Authorization"] = f"Bearer {token}"

s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:7777/runpod-s3/eu-ro-1", region_name="EU-RO-1",
                  config=Config(signature_version=botocore.UNSIGNED, s3={"addressing_style": "path"},
                                request_checksum_calculation="when_required",
                                response_checksum_validation="when_required"))
s3.meta.events.register("request-created.s3", credproxy_auth)
```

Without those settings boto3 and the AWS CLI send checksum headers or aws-chunked bodies, which credproxy refuses
(403/400). SDKs that add `?x-id=…` to the query (AWS JS v3, Rust) are refused too. Plain HTTP clients (curl,
requests) work as is.

Backblaze B2's native API:

```toml
[services.b2]
secret = "backblaze/master"                        # two lines: key id, application key
auth = { b2 = {} }                                 # optional: version = "v3" (or "v4"), relock_after = "23h" (≤ 24h)

[[services.b2.routes]]
prefix = "/b2api/v3"                               # "/b2api/<version>"; clients: POST /b2/b2api/v3/<call>
b2 = { calls = ["b2_list_buckets", "b2_create_bucket", "b2_update_bucket", "b2_delete_bucket", "b2_create_key",
                "b2_list_keys", "b2_delete_key", "b2_list_file_names", "b2_delete_file_version"] }

[[services.b2.routes]]
prefix = "/file"                                   # clients: GET /b2/file/<bucket>/<file name>
b2 = { download = true }

[[services.b2.routes]]
prefix = "/upload"                                 # clients: PUT /b2/upload/<bucket>/<file name>
b2 = { upload = true }
```

B2 routes have no `upstream`: it comes from the authorize reply. (`auth.b2.authorize_url` replaces the default
`https://api.backblazeb2.com/b2api/<version>/b2_authorize_account`, for fakes on this machine; then the returned
URLs must be on this machine too.)

Seal two lines without the clipboard (zsh; the secret isn't echoed):

```bash
{ read -r "id?Access key id: "; read -rs "sec?Secret: "; echo >&2; printf '%s\n%s\n' "$id" "$sec"; } | age -R <recipients> -o ~/.secrets/runpod/s3-key.age
```

The daemon reads the config at start; after changing it, `credproxy restart`.

## Use

| Command | What |
|---|---|
| `credproxy status` | Running? Each service: locked (or paused for 30 s after a refused or failed unlock), unlocking (waiting for Touch ID; for B2 then authorizing), or unlocked and for how long |
| `credproxy unlock <service>` | Unlock now (e.g. before a long job), instead of on the first request |
| `credproxy lock [<service>]` | Forget the key(s) now |
| `credproxy token <service>` | Print the current token (changes at every daemon start) |
| `credproxy install` / `uninstall` | LaunchAgent on/off |
| `credproxy restart` | Restart the daemon: locks everything, reloads the config, new token |
| `credproxy stop` | Stop it until `restart` or the next login |

## License

MIT
