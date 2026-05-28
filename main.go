// webperf - an iperf-style throughput tester for HTTP/HTTPS web traffic.
//
// A single file that is both the server and the client.
//
// Build:
//   go build -o webperf webperf.go
//
// Run a server (HTTP):
//   ./webperf server -listen :8080
//
// Run a server (HTTPS, auto self-signed cert):
//   ./webperf server -listen :8443 -tls
//
// Run a client (download with 200 connections, ramped up over 10s,
// then held at full load for 30s, 1MB per request):
//   ./webperf client -c 200 -rampup 10s -d 30s -size 1MB http://host:8080
//
// Upload test over HTTPS (skip cert verification for self-signed servers):
//   ./webperf client -c 100 -mode upload -size 4MB -insecure https://host:8443
//
// Mixed up+down (half the connections upload, half download):
//   ./webperf client -c 100 -mode both https://host:8443 -insecure
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `webperf - iperf-style HTTP/HTTPS throughput tester

USAGE:
  webperf server [flags]
  webperf client [flags] <target>

SERVER FLAGS:
  -listen    address to listen on (default ":8080")
  -tls       serve HTTPS (auto-generates a self-signed cert if -cert/-key absent)
  -cert      TLS certificate file (optional)
  -key       TLS private key file (optional)
  -interval  live reporting interval (default 1s)

CLIENT FLAGS:
  -c         concurrent connections (default 10)
  -rampup    duration over which connections are gradually added (default 0, all at once)
  -d         steady-state duration held after ramp-up completes (default 10s)
  -size      mean payload size per request, e.g. 64KB, 1MB, 4MB (default "1MB")
  -dist      payload size distribution: fixed|uniform|exp (default "uniform")
             all distributions average to -size; exp is heavy-tailed/web-like
  -mode      download | upload | both (default "download")
  -keepalive reuse TCP connection across requests (default off: fresh TCP per request)
  -insecure  skip TLS certificate verification (for self-signed servers)
  -interval  live reporting interval (default 1s)

  <target>   base URL or host, e.g. http://10.0.0.5:8080 or https://host:8443
             (scheme defaults to http:// if omitted)

EXAMPLES:
  webperf server -listen :8443 -tls
  webperf client -c 200 -rampup 10s -d 30s -size 1MB http://host:8080
  webperf client -c 100 -mode both -insecure https://host:8443
`)
}

// ---------------------------------------------------------------------------
// Shared: byte-pattern generation and helpers
// ---------------------------------------------------------------------------

// patternReader yields exactly n bytes of a cheap repeating pattern without
// allocating the full payload in memory. Used for both server downloads and
// client uploads so arbitrarily large payloads cost almost nothing.
type patternReader struct {
	remaining int64
	buf       []byte
	pos       int
}

func newPatternReader(n int64) *patternReader {
	buf := make([]byte, 64*1024)
	for i := range buf {
		buf[i] = byte('A' + (i % 26))
	}
	return &patternReader{remaining: n, buf: buf}
}

func (r *patternReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	limit := len(p)
	if int64(limit) > r.remaining {
		limit = int(r.remaining)
	}
	written := 0
	for written < limit {
		c := copy(p[written:limit], r.buf[r.pos:])
		written += c
		r.pos += c
		if r.pos >= len(r.buf) {
			r.pos = 0
		}
	}
	r.remaining -= int64(written)
	return written, nil
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	var mult int64 = 1
	switch {
	case strings.HasSuffix(s, "GB"):
		mult, s = 1<<30, strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		mult, s = 1<<20, strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		mult, s = 1<<10, strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "B"):
		mult, s = 1, strings.TrimSuffix(s, "B")
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	return int64(v * float64(mult)), nil
}

// nextSize draws a per-request payload size. The expected value of every
// distribution is mean, so over many requests the realized average converges
// to -size (verify via the "avg req" line in the summary).
//
//	fixed   - always exactly mean (no randomization)
//	uniform - uniform on [0, 2*mean], E = mean (bounded spread)
//	exp     - exponential with mean = mean (heavy-tailed, web-like: many
//	          small objects, occasional large ones)
func nextSize(r *mrand.Rand, mean int64, dist string) int64 {
	if mean <= 0 {
		return 0
	}
	switch dist {
	case "fixed":
		return mean
	case "exp":
		u := r.Float64()
		if u <= 0 {
			u = 1e-12 // guard against log(0)
		}
		return int64(-float64(mean) * math.Log(u))
	default: // uniform
		return r.Int63n(2*mean + 1)
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

type serverStats struct {
	bytesDown  int64 // bytes streamed to clients via /download
	bytesUp    int64 // bytes received from clients via /upload
	reqsDown   int64
	reqsUp     int64
	reqsHealth int64
	errors     int64 // I/O errors mid-transfer (client disconnects, write failures)
	active     int64 // currently in-flight transfer requests
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "listen address")
	useTLS := fs.Bool("tls", false, "serve HTTPS")
	certFile := fs.String("cert", "", "TLS certificate file (optional)")
	keyFile := fs.String("key", "", "TLS private key file (optional)")
	interval := fs.Duration("interval", time.Second, "live reporting interval")
	_ = fs.Parse(args)

	st := &serverStats{}
	mux := http.NewServeMux()

	// /download?size=N  -> server streams N bytes to the client.
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&st.active, 1)
		defer atomic.AddInt64(&st.active, -1)

		size := int64(1 << 20)
		if s := r.URL.Query().Get("size"); s != "" {
			if v, err := parseSize(s); err == nil {
				size = v
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		// io.Copy returns bytes-written even on error, so partial transfers
		// (client disconnects mid-stream) still get counted accurately.
		n, err := io.Copy(w, newPatternReader(size))
		atomic.AddInt64(&st.bytesDown, n)
		atomic.AddInt64(&st.reqsDown, 1)
		if err != nil {
			atomic.AddInt64(&st.errors, 1)
		}
	})

	// /upload  -> server drains the request body and reports the byte count.
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&st.active, 1)
		defer atomic.AddInt64(&st.active, -1)

		n, err := io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		atomic.AddInt64(&st.bytesUp, n)
		atomic.AddInt64(&st.reqsUp, 1)
		if err != nil {
			atomic.AddInt64(&st.errors, 1)
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%d", n)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&st.reqsHealth, 1)
		io.WriteString(w, "ok")
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}

	scheme := "http"
	if *useTLS {
		scheme = "https"
		if *certFile == "" || *keyFile == "" {
			cert, err := generateSelfSigned()
			if err != nil {
				fmt.Fprintln(os.Stderr, "cert generation failed:", err)
				os.Exit(1)
			}
			srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			fmt.Fprintln(os.Stderr, "using in-memory self-signed certificate (clients should pass -insecure)")
		}
	}

	// Graceful shutdown on Ctrl-C. The reporter goroutine watches reportCtx
	// so it stops cleanly before we print the final summary.
	reportCtx, stopReporter := context.WithCancel(context.Background())
	defer stopReporter()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	fmt.Printf("webperf server listening on %s (%s)\n", *listen, scheme)
	fmt.Println("endpoints: /download?size=N  /upload  /healthz")
	fmt.Println()

	start := time.Now()
	go serverReporter(reportCtx, st, *interval, start)

	var err error
	if *useTLS {
		// Empty file args -> server uses srv.TLSConfig.Certificates.
		err = srv.ListenAndServeTLS(*certFile, *keyFile)
	} else {
		err = srv.ListenAndServe()
	}
	stopReporter()
	if err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
	printServerSummary(st, time.Since(start).Seconds())
}

func serverReporter(ctx context.Context, st *serverStats, interval time.Duration, start time.Time) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastDown, lastUp, lastReqsD, lastReqsU int64
	lastTime := start
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			bd := atomic.LoadInt64(&st.bytesDown)
			bu := atomic.LoadInt64(&st.bytesUp)
			rd := atomic.LoadInt64(&st.reqsDown)
			ru := atomic.LoadInt64(&st.reqsUp)
			active := atomic.LoadInt64(&st.active)
			elapsed := now.Sub(lastTime).Seconds()
			if elapsed <= 0 {
				continue
			}
			// Skip purely idle ticks so an unused server doesn't spam zero lines.
			if active == 0 && bd == lastDown && bu == lastUp && rd == lastReqsD && ru == lastReqsU {
				lastTime = now
				continue
			}
			downMbps := float64(bd-lastDown) * 8 / 1e6 / elapsed
			upMbps := float64(bu-lastUp) * 8 / 1e6 / elapsed
			downRps := float64(rd-lastReqsD) / elapsed
			upRps := float64(ru-lastReqsU) / elapsed
			fmt.Printf("[%6.1fs] active=%-3d  down %9.2f Mbit/s %7.1f req/s  up %9.2f Mbit/s %7.1f req/s  errs=%d\n",
				now.Sub(start).Seconds(), active,
				downMbps, downRps, upMbps, upRps, atomic.LoadInt64(&st.errors))
			lastDown, lastUp, lastReqsD, lastReqsU, lastTime = bd, bu, rd, ru, now
		}
	}
}

func printServerSummary(st *serverStats, elapsed float64) {
	bd := atomic.LoadInt64(&st.bytesDown)
	bu := atomic.LoadInt64(&st.bytesUp)
	rd := atomic.LoadInt64(&st.reqsDown)
	ru := atomic.LoadInt64(&st.reqsUp)
	rh := atomic.LoadInt64(&st.reqsHealth)
	errs := atomic.LoadInt64(&st.errors)

	fmt.Println("\n──────────────── server summary ────────────────")
	fmt.Printf("uptime:       %.1fs\n", elapsed)
	if rd > 0 {
		avg := bd / rd
		fmt.Printf("download:     %s in %d req (avg %s/req, %.2f Mbit/s)\n",
			humanBytes(bd), rd, humanBytes(avg), float64(bd)*8/1e6/elapsed)
	} else {
		fmt.Printf("download:     0 req\n")
	}
	if ru > 0 {
		avg := bu / ru
		fmt.Printf("upload:       %s in %d req (avg %s/req, %.2f Mbit/s)\n",
			humanBytes(bu), ru, humanBytes(avg), float64(bu)*8/1e6/elapsed)
	} else {
		fmt.Printf("upload:       0 req\n")
	}
	fmt.Printf("healthz:      %d req\n", rh)
	fmt.Printf("errors:       %d\n", errs)
	fmt.Println("────────────────────────────────────────────────")
}

func generateSelfSigned() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "webperf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

type stats struct {
	bytes      int64
	requests   int64
	errors     int64
	latNanoSum int64
	latCount   int64
	latMin     int64
	latMax     int64
}

func recordLatency(st *stats, lat int64) {
	atomic.AddInt64(&st.latNanoSum, lat)
	atomic.AddInt64(&st.latCount, 1)
	for {
		old := atomic.LoadInt64(&st.latMin)
		if old != 0 && lat >= old {
			break
		}
		if atomic.CompareAndSwapInt64(&st.latMin, old, lat) {
			break
		}
	}
	for {
		old := atomic.LoadInt64(&st.latMax)
		if lat <= old {
			break
		}
		if atomic.CompareAndSwapInt64(&st.latMax, old, lat) {
			break
		}
	}
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	conns := fs.Int("c", 10, "concurrent connections")
	ramp := fs.Duration("rampup", 0, "ramp-up duration")
	dur := fs.Duration("d", 10*time.Second, "steady-state duration after ramp-up")
	sizeStr := fs.String("size", "1MB", "mean payload size per request, e.g. 64KB, 1MB")
	dist := fs.String("dist", "uniform", "payload size distribution: fixed|uniform|exp (all average to -size)")
	mode := fs.String("mode", "download", "download|upload|both")
	keepalive := fs.Bool("keepalive", false, "reuse TCP connection across requests (default: fresh TCP per request)")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	interval := fs.Duration("interval", time.Second, "live reporting interval")
	_ = fs.Parse(args)

	if *conns < 1 {
		fmt.Fprintln(os.Stderr, "-c must be >= 1")
		os.Exit(2)
	}
	switch *mode {
	case "download", "upload", "both":
	default:
		fmt.Fprintln(os.Stderr, "-mode must be download, upload, or both")
		os.Exit(2)
	}
	switch *dist {
	case "fixed", "uniform", "exp":
	default:
		fmt.Fprintln(os.Stderr, "-dist must be fixed, uniform, or exp")
		os.Exit(2)
	}

	target := fs.Arg(0)
	if target == "" {
		fmt.Fprintln(os.Stderr, "missing target (e.g. http://host:8080)")
		os.Exit(2)
	}
	baseURL, err := normalizeTarget(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad target:", err)
		os.Exit(2)
	}
	size, err := parseSize(*sizeStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	total := *ramp + *dur
	ctx, cancel := context.WithTimeout(context.Background(), total)
	defer cancel()

	// Stop early on Ctrl-C and still print a summary.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\ninterrupted, stopping...")
		cancel()
	}()

	fmt.Printf("webperf client -> %s\n", baseURL)
	ka := "off"
	if *keepalive {
		ka = "on"
	}
	fmt.Printf("connections=%d  mode=%s  size~%s (%s)  keepalive=%s  rampup=%s  duration=%s\n\n",
		*conns, *mode, humanBytes(size), *dist, ka, *ramp, *dur)

	st := &stats{}
	var active int64
	start := time.Now()

	go reporter(ctx, st, &active, *interval, start)

	var wg sync.WaitGroup
	for i := 0; i < *conns; i++ {
		// Spread worker starts evenly across the ramp-up window so we never
		// open all connections at once.
		var delay time.Duration
		if *conns > 1 {
			delay = time.Duration(int64(*ramp) * int64(i) / int64(*conns))
		}
		wg.Add(1)
		go func(id int, delay time.Duration) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			atomic.AddInt64(&active, 1)

			wmode := *mode
			if *mode == "both" {
				if id%2 == 0 {
					wmode = "download"
				} else {
					wmode = "upload"
				}
			}
			// Per-worker RNG avoids lock contention on the global source at
			// high connection counts; distinct seeds keep streams independent.
			rng := mrand.New(mrand.NewSource(time.Now().UnixNano() + int64(id)*2654435761))
			worker(ctx, newClient(*insecure, *keepalive), baseURL, wmode, size, *dist, rng, st)
		}(i, delay)
	}

	wg.Wait()
	elapsed := time.Since(start).Seconds()
	printSummary(st, elapsed, *conns)
}

func normalizeTarget(t string) (string, error) {
	if !strings.Contains(t, "://") {
		t = "http://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("could not determine host from %q", t)
	}
	return u.Scheme + "://" + u.Host, nil
}

// newClient returns an http.Client backed by its own Transport pinned to a
// single connection. One worker therefore maps to exactly one live connection,
// which keeps the reported concurrency honest (HTTP/2 multiplexing is disabled
// so requests don't get folded onto one socket). When keepalive is false the
// transport closes the connection after each response, so every request pays
// the cost of a fresh TCP (and TLS) handshake.
func newClient(insecure, keepalive bool) *http.Client {
	tr := &http.Transport{
		MaxConnsPerHost:     1,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   !keepalive,
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return &http.Client{Transport: tr}
}

func worker(ctx context.Context, client *http.Client, baseURL, mode string, mean int64, dist string, rng *mrand.Rand, st *stats) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		reqSize := nextSize(rng, mean, dist)
		start := time.Now()
		var n int64
		var err error
		if mode == "upload" {
			n, err = doUpload(ctx, client, baseURL, reqSize)
		} else {
			n, err = doDownload(ctx, client, baseURL, reqSize)
		}
		lat := time.Since(start).Nanoseconds()

		if err != nil {
			// A cancelled/expired context just means the test ended mid-request;
			// that isn't a real failure, so don't pollute the error count.
			if ctx.Err() != nil {
				return
			}
			atomic.AddInt64(&st.errors, 1)
			// Back off briefly so a refused/closed server doesn't spin a hot loop.
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		atomic.AddInt64(&st.bytes, n)
		atomic.AddInt64(&st.requests, 1)
		recordLatency(st, lat)
	}
}

func doDownload(ctx context.Context, client *http.Client, baseURL string, size int64) (int64, error) {
	u := fmt.Sprintf("%s/download?size=%d", baseURL, size)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.Copy(io.Discard, resp.Body)
}

func doUpload(ctx context.Context, client *http.Client, baseURL string, size int64) (int64, error) {
	u := baseURL + "/upload"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, newPatternReader(size))
	if err != nil {
		return 0, err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	return size, nil
}

func reporter(ctx context.Context, st *stats, active *int64, interval time.Duration, start time.Time) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastBytes, lastReqs int64
	lastTime := start
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			b := atomic.LoadInt64(&st.bytes)
			rq := atomic.LoadInt64(&st.requests)
			elapsed := now.Sub(lastTime).Seconds()
			if elapsed <= 0 {
				continue
			}
			mbps := float64(b-lastBytes) * 8 / 1e6 / elapsed
			rps := float64(rq-lastReqs) / elapsed
			fmt.Printf("[%6.1fs] conns=%-4d %9.2f Mbit/s %8.1f req/s  total=%-11s errs=%d\n",
				now.Sub(start).Seconds(), atomic.LoadInt64(active),
				mbps, rps, humanBytes(b), atomic.LoadInt64(&st.errors))
			lastBytes, lastReqs, lastTime = b, rq, now
		}
	}
}

func printSummary(st *stats, elapsed float64, conns int) {
	b := atomic.LoadInt64(&st.bytes)
	rq := atomic.LoadInt64(&st.requests)
	errs := atomic.LoadInt64(&st.errors)
	latCount := atomic.LoadInt64(&st.latCount)

	avgMbps := 0.0
	if elapsed > 0 {
		avgMbps = float64(b) * 8 / 1e6 / elapsed
	}
	var avgLat, minLat, maxLat float64
	if latCount > 0 {
		avgLat = float64(atomic.LoadInt64(&st.latNanoSum)) / float64(latCount) / 1e6
		minLat = float64(atomic.LoadInt64(&st.latMin)) / 1e6
		maxLat = float64(atomic.LoadInt64(&st.latMax)) / 1e6
	}

	fmt.Println("\n──────────────── summary ────────────────")
	fmt.Printf("duration:     %.1fs over %d connections\n", elapsed, conns)
	fmt.Printf("transferred:  %s\n", humanBytes(b))
	if rq > 0 {
		fmt.Printf("avg req:      %s (target mean of -size)\n", humanBytes(b/rq))
	}
	fmt.Printf("throughput:   %.2f Mbit/s (%.2f MiB/s)\n", avgMbps, float64(b)/1048576/elapsed)
	fmt.Printf("requests:     %d (%.1f/s)\n", rq, float64(rq)/elapsed)
	fmt.Printf("errors:       %d\n", errs)
	if latCount > 0 {
		fmt.Printf("latency:      avg %.1fms  min %.1fms  max %.1fms\n", avgLat, minLat, maxLat)
	}
	fmt.Println("──────────────────────────────────────────")
}
