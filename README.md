# redis-rest-api

A simple REST proxy for Redis written in Go.

> **Warning**
> This is really is just a proof of concept, and several errors are unhandled.

## Is it any good?

[Yes.](https://news.ycombinator.com/item?id=3067434)

## Is it fast?

Not as fast as a direct Redis TCP connection to Redis, but it is reasonably competitive. See [Benchmarks](#benchmarks) for more.

## Build

```bash
$ make
```

This will create three binaries - `redis-rest-api`, `aclgen` and `commandgen` in the `bin/` directory.

## Usage

```shell
$ ./bin/redis-rest-api -h
Usage of ./bin/redis-rest-api:
  -listen-addr string
    	address to listen on (default ":8081")
  -map-file string
    	filepath containing user map (default "redis-users.json")
  -profile
    	Create a CPU profile
  -redis-addr string
    	address of redis server (default "localhost:6379")
  -redis-password string
    	redis user password to AUTH with
  -redis-user string
    	redis user to AUTH as (default "default")
  -tls-cert string
    	TLS certificate file (default "test-cert.pem")
  -tls-key string
    	TLS key file (default "test-key.pem")
  -version
    	print version and exit
```

`redis-rest-api` expects to connect to a localhost Redis over plaintext, with optional `AUTH`. This is primarily to reduce latency.

First, generate an ACL file using the `aclgen` binary:

```bash
$ ./bin/aclgen
[!] Generating tokens these will not be shown again!
readwrite:[redacted]
readonly:[redacted]
[!] Rendering redis-users.json
```

Take a note of the generated `user:pass` combinations as these will can used to authenticate with the proxy.

### User Map

For a simple auth experience, users are mapped in a file called `redis-users.json` in the following format:

```json
{
  "<user>": {
    "_roledoc": "'rw' and 'ro' are the only valid roles",
    "role": "ro",
    "_tokendoc": "sha256sum of the desired token/password",
    "tokenSHA": "<tokenSHA>"
  }
}
```

TODO:

- [ ] Replace with a better auth lookup/auth backends (e.g. Vault)

### Running

You may create some self-signed certs with:

```
$ make certs
```

This will create `test-cert.pem` and `test-key.pem` using OpenSSL, or [`mkcert`](https://github.com/FiloSottile/mkcert) if available. Certs are required.

Start the proxy:

```bash
$ ./bin/redis-rest-api -h
Usage of ./bin/redis-rest-api:
  -listen-addr string
    	address to listen on (default ":8081")
  -map-file string
    	filepath containing user map (default "redis-users.json")
  -profile
    	Create a CPU profile
  -redis-addr string
    	address of redis server (default "localhost:6379")
  -redis-password string
    	redis user password to AUTH with
  -redis-user string
    	redis user to AUTH as (default "default")
  -tls-cert string
    	TLS certificate file (default "test-cert.pem")
  -tls-key string
    	TLS key file (default "test-key.pem")
  -version
    	print version and exit

$ ./bin/redis-rest-api
```

There is currently minimal unstructured logging.

- [ ] TODO: Implement otel.

## API

This implements the [Upstash Redis REST API](https://docs.upstash.com/redis/features/restapi#api-semantics) for the most part.

### Getting Started

Construct a path mapping to a command and arguments, with a Bearer token for authentication. In this case, we're using executing the `SET` command with the key of `foo` and the value of `1`:

```bash
$ curl -s https://localhost:8081/set/foo/1 -H "Authorization: Bearer [token]" | jq
{
  "result": "OK"
}
```

```bash
$ curl -s https://localhost:8081/get/foo -H "Authorization: Bearer [token]" | jq
{
  "result": "1"
}
```

### Responses

Responses are in JSON. The following status codes are used:

- `200` - OK
- `400` - Bad Request (invalid command etc)
- `401` - Unauthorized (invalid auth)
- `405` - Method Not Allowed (invalid HTTP method, only `GET`, `POST`, `PUT` and `HEAD` are supported)
- `500` - Internal Server Error

For successful commands, a JSON object with the key of `result` is returned:

```json
{ "result": "OK" }
```

For errprs, a JSON object with the key of `error` is returned:

```json
{ "error": "ERR unknown command 'FOO'" }
```

### Path

Build a path to map a command, where all values are strings, for example:

- `GET key` -> `/get/key`
- `SET key value` -> `/set/key/value`
- `SET key value EX 10` -> `/set/key/value/ex/10`

Using `curl`:

```bash
$ curl -s https://localhost:8081/set/key/value/ex/10 -H "Authorization: Bearer [token]" | jq
{
  "result": "OK"
}
```

### JSON

For more complex commands or more control over types, send a `POST` request with a JSON array in the body representing the command and arguments to the root path:

```bash
$ curl -s -X POST https://localhost:8081 \
    -H "Authorization: Bearer [token]" \
    -d '["SET", "key1", "foo"]' | jq
{
  "result": "OK"
}
```

### Pipelining

Pipelining is supported by sending a 2-dimensional JSON array in the body out of a `POST` request to `/pipeline`, returning a JSON array of results:

```bash
$ curl -s -X POST https://localhost:8081/pipeline \
  -H "Authorization: Bearer [token]" \
  -d '[["SET", "key1", "foo"], ["GET", "key1"]]' | jq
[
  {
    "result": "OK"
  },
  {
    "result": "foo"
  }
]
```

Errors in the pipeline will be tolerated and the response will contain the error(s):

```bash
curl -s -X POST https://localhost:8081/pipeline \
    -H "Authorization: Bearer [token]"
    -d '[["SET", "key1", "foo"], ["GET", "key2", "extra"], ["GET", "key1"]]'
[
  {
    "result": "OK"
  },
  {
    "error": "ERR wrong number of arguments for 'get' command"
  },
  {
    "result": "foo"
  }
]
```

### Transactions

Transactions are supported by sending a 2-dimensional JSON array in the body out of a `POST` request to `/multi-exec`, returning a JSON array of results. If we wanted to convert the following to a REST API request, you can send the body to `/multi-exec`:

```bash
MULTI
SET key1 valuex
SETEX key2 13 valuez
INCR key1 # wrong type of operation
ZADD myset 11 item1 22 item2
EXEC
```

```bash
curl -s -X POST https://localhost:8081/multi-exec \
    -H "Authorization: Bearer [token]" \
    -d '
[
    ["DEL", "key1"],
    ["DEL", "key2"],
    ["DEL", "myset"],
    ["SET", "key1", "valuex"],
    ["SETEX", "key2", 13, "valuez"],
    ["INCR", "key1", "key2"],
    ["ZADD", "myset", 11, "item1", 22, "item2"]
]
'
{
  "error": "EXECABORT Transaction discarded because of previous errors."
}
```

A transaction is `DISCARD`ed on `EXECABORT` and `NOPERM` errors.

## Identity

Authentication is done via a Bearer token in the `Authorization` header, with a header to declare which user to authenticate as, `X-Redis-User`.

`aclgen` will generate tokens and roles for two users: `readwrite` and `readonly`. The `readwrite` user does not require the usage of `X-Redis-User`, but all other users do.

Users must be present in the map file, otherwise the request will be rejected.

- [ ] TODO: Better auth backends.

## Capabilities

A list of commands for each role type, `rw` (read-write) and `ro` (read-only) are generated (see `commands.go`) from a Redis 7 instance with:

```
$ make commandgen
```

All API users do not have access to the ACL groups and commands:

```
-@dangerous
-@blocking
-@connection
-@pubsub
-@transaction
-WATCH
-UNWATCH
-DISCARD
```

`ro` users additionally do not have access to the following ACL groups and commands:

```
-@write
-KEYS
-SCAN
```

Some commands are granted explicitly:

```
+PING
+ECHO
```

## Compatibility

This API _should_ be tracking against the [Upstash Redis REST API](https://docs.upstash.com/redis/features/restapi#rest---redis-api-compatibility).

## Benchmarks

A quick `k6` benchmark on my laptop (2020 M1 MacbookAir):

```javascript
import http from "k6/http";

export const options = {
  discardResponseBodies: true,
  scenarios: {
    contacts: {
      executor: "per-vu-iterations",
      vus: 200,
      iterations: 10000,
      maxDuration: "5m",
    },
  },
};

export default function () {
  const payload = '[["SET", "foo", 1], ["GET", "foo"], ["DEL", "foo"]]';
  const pipeline = "https://127.0.0.1:8081/pipeline";
  const params = {
    headers: {
      Authorization: "Bearer [token]",
    },
  };

  http.post(pipeline, payload, params);
}
```

```
     data_received..................: 293 MB  3.7 MB/s
     data_sent......................: 241 MB  3.1 MB/s
     http_req_blocked...............: avg=9.64µs   min=0s      med=0s     max=153.36ms p(90)=1µs     p(95)=1µs
     http_req_connecting............: avg=1.15µs   min=0s      med=0s     max=28.82ms  p(90)=0s      p(95)=0s
     http_req_duration..............: avg=7.81ms   min=0s      med=7.06ms max=76.96ms  p(90)=10.35ms p(95)=13.65ms
       { expected_response:true }...: avg=7.81ms   min=81µs    med=7.06ms max=76.96ms  p(90)=10.35ms p(95)=13.65ms
     http_req_failed................: 0.00%   ✓ 0            ✗ 2000000
     http_req_receiving.............: avg=460.56µs min=0s      med=270µs  max=28.02ms  p(90)=1.09ms  p(95)=1.55ms
     http_req_sending...............: avg=12.98µs  min=0s      med=8µs    max=17.89ms  p(90)=16µs    p(95)=27µs
     http_req_tls_handshaking.......: avg=8.37µs   min=0s      med=0s     max=149.62ms p(90)=0s      p(95)=0s
     http_req_waiting...............: avg=7.34ms   min=0s      med=6.61ms max=76.81ms  p(90)=9.82ms  p(95)=12.99ms
     http_reqs......................: 2000000 25435.229525/s
     iteration_duration.............: avg=7.84ms   min=93.04µs med=7.09ms max=186ms    p(90)=10.38ms p(95)=13.7ms
     iterations.....................: 2000000 25435.229525/s
     vus............................: 200     min=200        max=200
     vus_max........................: 200     min=200        max=200
```

And some `hyperfine` results against raw TCP-over-TLS:

```bash
$ $ hyperfine -w 250 -r 1000 \
    -n raw "printf '\r\nSET foo 1\r\nGET foo\r\nDEL foo\r\n' | redis-cli --tls --insecure -p 6380 --pipe" \
    -n redis-rest-api "curl -s -X POST https://localhost:8081/pipeline -H \"Authorization: Bearer [token]\" -d '[[\"SET\", \"foo\", \"1\"],[\"GET\", \"foo\"],[\"DEL\", \"foo\"]]'"
```

```

Benchmark 1: raw
  Time (mean ± σ):       9.3 ms ±   0.9 ms    [User: 5.5 ms, System: 1.3 ms]
  Range (min … max):     8.2 ms …  28.7 ms    1000 runs

Benchmark 2: redis-rest-api
  Time (mean ± σ):      12.5 ms ±   0.9 ms    [User: 6.0 ms, System: 2.0 ms]
  Range (min … max):    10.9 ms …  23.9 ms    1000 runs

Summary
  'raw' ran
    1.35 ± 0.16 times faster than 'redis-rest-api'
```
