# redis-rest-api

A self-hosted HTTP facade implementing the
[Upstash Redis REST API](https://upstash.com/docs/redis/features/restapi) over
Redis or Valkey.

It provides Upstash-compatible transport, not Upstash's managed platform.
Replication, persistence, quotas, billing, and supported modules belong to the
backing server.

## Run

```sh
docker compose up --build
```

The development tokens are `development-token` and
`development-read-token`.

```sh
curl http://localhost:8081/set/foo/bar \
  -H 'Authorization: Bearer development-token'

curl http://localhost:8081/get/foo \
  -H 'Authorization: Bearer development-token'
```

## API

Path command:

```text
GET /COMMAND/ARGUMENT/...
```

JSON command:

```text
POST /
["SET", "foo", "bar", "EX", 60]
```

Body value with ordered query options:

```text
POST /set/foo?EX=60

binary body
```

Batch endpoints:

```text
POST /pipeline
POST /multi-exec

[["SET", "foo", "bar"], ["GET", "foo"]]
```

Authentication uses `Authorization: Bearer TOKEN`. URL credentials are disabled
by default; enable `_token=TOKEN` compatibility with `-allow-query-token`.
Responses default to JSON. `Upstash-Encoding: base64` encodes strings.
`Upstash-Response-Format: resp2` returns RESP2, except for transactions.

Streaming endpoints require `Accept: text/event-stream`:

```text
POST /subscribe/channel
POST /psubscribe/pattern
POST /monitor
```

Health endpoints are unauthenticated:

```text
GET /livez
GET /readyz
```

Enable Prometheus metrics with `-metrics`; scrape `GET /metrics`.

## Configuration

| Environment | Default |
|---|---|
| `REDIS_URL` | `redis://127.0.0.1:6379` |
| `REDIS_REST_ADDR` | `:8081` |
| `REDIS_REST_TOKEN` | unset |
| `REDIS_REST_READ_ONLY_TOKEN` | unset |
| `REDIS_REST_TOKEN_FILE` | `redis-users.json` when tokens are unset |
| `REDIS_REST_TLS_CERT` | unset |
| `REDIS_REST_TLS_KEY` | unset |
| `REDIS_REST_LOG_LEVEL` | `info` |
| `REDIS_REST_REDIS_INSECURE_SKIP_VERIFY` | `false` |
| `REDIS_REST_ALLOW_QUERY_TOKEN` | `false` |

Use `redis-rest-api -h` for timeouts and request limits.

Key limits default to:

| Flag | Default |
|---|---:|
| `-max-body-bytes` | 1 MiB |
| `-max-response-bytes` | 16 MiB |
| `-max-header-bytes` | 32 KiB |
| `-max-in-flight` | 256 |
| `-max-subscriptions` | 128 |
| `-max-monitors` | 1 |
| `-ready-cache-ttl` | 1s |
| `-write-timeout` | 10s |

The Redis pool defaults to ten connections per `GOMAXPROCS`, capped at 1024.
Use `-redis-pool-size`, `-redis-min-idle`, and the pipeline buffer flags to
tune measured workloads.

`REDIS_URL` supports Redis URI credentials, database selection, and `rediss`.
Terminate public TLS at a reverse proxy or provide both HTTP TLS files.

## Tokens

Generate standard and readonly tokens:

```sh
make build
./bin/token-gen
```

The command creates a mode `0600` file and prints each secret once. Existing
files are preserved unless `-force` is given.

The file stores SHA-256 hashes:

```json
{
  "standard": {
    "role": "rw",
    "tokenSHA": "64 hexadecimal characters"
  },
  "readonly": {
    "role": "ro",
    "tokenSHA": "64 hexadecimal characters"
  }
}
```

Readonly tokens cannot write, run blocking commands, or use `KEYS` and `SCAN`.
Standard tokens still cannot issue backend-control, connection, cluster,
blocking, or explicit transaction-control commands. Pipelines and
`/multi-exec` remain supported.

Command metadata is loaded from the backing server at startup. Redis modules
such as JSON work when installed there.

## Design

```text
HTTP adapter -> service/auth policy -> Redis adapter -> Redis/Valkey
                                      |-> Pub/Sub
                                      `-> MONITOR connection
```

Each request carries its cancellation context through every layer. Request
bodies, responses, batch sizes, command arguments, headers, concurrency,
connection pools, stream writes, and shutdown duration are bounded.

## Develop

Requires Go 1.26 or newer.

```sh
make test
make vet
make lint
make bench

TEST_REDIS_URL=redis://127.0.0.1:6379 make integration
```

CI runs race-tested unit and Redis integration tests, vet, lint, and builds.
