# webperf

An iperf-style throughput tester for HTTP/HTTPS. A single Go binary that is both
the server and the client — useful for measuring real web traffic across NATs,
load balancers, CDNs, or any path where raw iperf can't reach.

## Build

```sh
make         # cross-compiles linux/darwin/windows × amd64/arm64 into dist/
```

## Server

```sh
# HTTP on :8080
./webperf server -listen :8080

# HTTPS on :8443 with an in-memory self-signed cert
./webperf server -listen :8443 -tls

# HTTPS with your own cert/key
./webperf server -listen :8443 -tls -cert server.crt -key server.key
```

Endpoints: `/download?size=N`, `/upload`, `/healthz`.

## Client

```sh
# 200 connections, ramped up over 10s, then held for 30s, ~1MB per request
./webperf client -c 200 -rampup 10s -d 30s -size 1MB http://host:8080

# Upload test over HTTPS (skip cert check for self-signed servers)
./webperf client -c 100 -mode upload -size 4MB -insecure https://host:8443

# Mixed: half the workers upload, half download
./webperf client -c 100 -mode both -insecure https://host:8443

# Fresh TCP (+TLS) handshake per request — measure connection setup cost
./webperf client -c 50 -d 20s -size 64KB http://host:8080

# Reuse one keep-alive connection per worker — measure steady-state throughput
./webperf client -c 50 -d 20s -size 64KB -keepalive http://host:8080

# Web-like heavy-tailed size mix (many small, occasional large)
./webperf client -c 100 -d 30s -size 256KB -dist exp http://host:8080
```

## Client flags

| flag         | default      | meaning                                                      |
|--------------|--------------|--------------------------------------------------------------|
| `-c`         | `10`         | concurrent connections                                       |
| `-rampup`    | `0`          | duration over which connections are gradually added          |
| `-d`         | `10s`        | steady-state duration held after ramp-up                     |
| `-size`      | `1MB`        | mean payload per request (e.g. `64KB`, `1MB`, `4MB`)         |
| `-dist`      | `uniform`    | size distribution: `fixed` \| `uniform` \| `exp`             |
| `-mode`      | `download`   | `download` \| `upload` \| `both`                             |
| `-keepalive` | off          | reuse TCP across requests (default: fresh TCP per request)   |
| `-insecure`  | off          | skip TLS cert verification (self-signed servers)             |
| `-interval`  | `1s`         | live reporting interval                                      |

The client prints per-interval throughput while running and a summary at the end
(transferred bytes, avg request size, Mbit/s, req/s, latency min/avg/max).
