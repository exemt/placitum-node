/*
 * Потолок архива: тот же PutObject, без nginx и без инспекторов.
 *
 * Замер отвечает на вопрос «сколько объектов S3 выдержит», а не «сколько
 * выдержит контур». Датаграммы, Redis и инспекторы сюда не входят: они только
 * сузят число, которое получится здесь.
 *
 *     go run ./cmd/waf-retain-bench \
 *         -endpoint http://minio:9000 \
 *         -headers 400k -body 4m \
 *         -workers 1,2,4,8,16,32 \
 *         -duration 15s
 */

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/exemt/placitum-node/agent/internal/retain"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "retain-bench: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		endpoint   = flag.String("endpoint", "http://127.0.0.1:9002", "S3 API")
		region     = flag.String("region", "us-east-1", "SigV4 region")
		access     = flag.String("access", "waf", "access key")
		secret     = flag.String("secret", "wafwafwaf", "secret key")
		hdrBucket  = flag.String("headers-bucket", "waf-headers", "")
		bodyBucket = flag.String("body-bucket", "waf-bodies", "")
		hdrSize    = flag.String("headers", "400k", "headers object size")
		bodySize   = flag.String("body", "4m", "body object size")
		mode       = flag.String("mode", "pair", "pair | headers | body")
		workers    = flag.String("workers", "1,2,4,8,16,32", "concurrency steps")
		duration   = flag.Duration("duration", 15*time.Second, "per step")
		warmup     = flag.Duration("warmup", 2*time.Second, "per step")
		timeout    = flag.Duration("timeout", 30*time.Second, "one PUT")
	)
	flag.Parse()

	hdrBytes, err := parseSize(*hdrSize)
	if err != nil {
		return fmt.Errorf("headers: %w", err)
	}
	bodyBytes, err := parseSize(*bodySize)
	if err != nil {
		return fmt.Errorf("body: %w", err)
	}

	steps, err := parseWorkers(*workers)
	if err != nil {
		return err
	}

	stamp := time.Now().UTC().Format("20060102T150405")
	hdrPayload := make([]byte, hdrBytes)
	bodyPayload := make([]byte, bodyBytes)
	for i := range hdrPayload {
		hdrPayload[i] = 'H'
	}
	for i := range bodyPayload {
		bodyPayload[i] = 'B'
	}

	report := Report{
		Endpoint:    *endpoint,
		Mode:        *mode,
		HeadersSize: hdrBytes,
		BodySize:    bodyBytes,
		Duration:    duration.String(),
		Started:     time.Now().UTC().Format(time.RFC3339),
	}

	fmt.Fprintf(os.Stderr, "retain-bench mode=%s headers=%d body=%d steps=%v\n",
		*mode, hdrBytes, bodyBytes, steps)

	for _, n := range steps {
		step, err := runStep(stepConfig{
			endpoint:   *endpoint,
			region:     *region,
			access:     *access,
			secret:     *secret,
			hdrBucket:  *hdrBucket,
			bodyBucket: *bodyBucket,
			mode:       *mode,
			workers:    n,
			duration:   *duration,
			warmup:     *warmup,
			timeout:    *timeout,
			stamp:      stamp,
			hdr:        hdrPayload,
			body:       bodyPayload,
		})
		if err != nil {
			return err
		}
		report.Steps = append(report.Steps, step)
		fmt.Fprintf(os.Stderr,
			"  workers=%2d  req/s=%7.1f  obj/s=%7.1f  MiB/s=%6.1f  p50=%s  p99=%s  err=%d\n",
			step.Workers, step.RequestsPerSec, step.ObjectsPerSec, step.MebibytesPerSec,
			time.Duration(step.P50PutNs), time.Duration(step.P99PutNs), step.Errors)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

type Report struct {
	Endpoint    string `json:"endpoint"`
	Mode        string `json:"mode"`
	HeadersSize int    `json:"headers_size"`
	BodySize    int    `json:"body_size"`
	Duration    string `json:"duration"`
	Started     string `json:"started"`
	Steps       []Step `json:"steps"`
}

type Step struct {
	Workers         int     `json:"workers"`
	Requests        int64   `json:"requests"`
	Objects         int64   `json:"objects"`
	Errors          int64   `json:"errors"`
	Bytes           int64   `json:"bytes"`
	ElapsedNs       int64   `json:"elapsed_ns"`
	RequestsPerSec  float64 `json:"requests_per_sec"`
	ObjectsPerSec   float64 `json:"objects_per_sec"`
	MebibytesPerSec float64 `json:"mebibytes_per_sec"`
	P50PutNs        int64   `json:"p50_put_ns"`
	P99PutNs        int64   `json:"p99_put_ns"`
	FirstError      string  `json:"first_error,omitempty"`
}

type stepConfig struct {
	endpoint, region, access, secret string
	hdrBucket, bodyBucket, mode      string
	workers                          int
	duration, warmup, timeout        time.Duration
	stamp                            string
	hdr, body                        []byte
}

func runStep(cfg stepConfig) (Step, error) {
	up := retain.NewUploader(retain.Config{
		S3: retain.S3Config{
			Endpoint: cfg.endpoint,
			Region:   cfg.region,
			Access:   cfg.access,
			Secret:   cfg.secret,
		},
		Workers:   cfg.workers,
		OpTimeout: cfg.timeout,
	})

	var (
		seq   atomic.Uint64
		okReq atomic.Int64
		okObj atomic.Int64
		errN  atomic.Int64
		bytes atomic.Int64
		first atomic.Value
		latMu sync.Mutex
		lat   []time.Duration
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	ready := make(chan struct{})

	worker := func(id int) {
		defer wg.Done()
		<-ready

		payloadH := append([]byte(nil), cfg.hdr...)
		payloadB := append([]byte(nil), cfg.body...)

		for ctx.Err() == nil {
			n := seq.Add(1)
			binary.BigEndian.PutUint64(payloadH, n)
			if len(payloadB) >= 8 {
				binary.BigEndian.PutUint64(payloadB, n)
			}

			start := time.Now()
			objects, written, err := putOnce(ctx, up, cfg, id, n, payloadH, payloadB)
			took := time.Since(start)

			if err != nil {
				if ctx.Err() != nil {
					return
				}
				errN.Add(1)
				first.CompareAndSwap(nil, err.Error())
				continue
			}

			okReq.Add(1)
			okObj.Add(int64(objects))
			bytes.Add(int64(written))
			latMu.Lock()
			lat = append(lat, took)
			latMu.Unlock()
		}
	}

	wg.Add(cfg.workers)
	for i := 0; i < cfg.workers; i++ {
		go worker(i)
	}

	close(ready)
	time.Sleep(cfg.warmup)

	okReq.Store(0)
	okObj.Store(0)
	errN.Store(0)
	bytes.Store(0)
	latMu.Lock()
	lat = lat[:0]
	latMu.Unlock()

	t0 := time.Now()
	time.Sleep(cfg.duration)
	cancel()
	wg.Wait()
	elapsed := time.Since(t0)

	step := Step{
		Workers:   cfg.workers,
		Requests:  okReq.Load(),
		Objects:   okObj.Load(),
		Errors:    errN.Load(),
		Bytes:     bytes.Load(),
		ElapsedNs: elapsed.Nanoseconds(),
	}

	sec := elapsed.Seconds()
	if sec > 0 {
		step.RequestsPerSec = float64(step.Requests) / sec
		step.ObjectsPerSec = float64(step.Objects) / sec
		step.MebibytesPerSec = float64(step.Bytes) / sec / (1024 * 1024)
	}

	latMu.Lock()
	step.P50PutNs = percentile(lat, 50).Nanoseconds()
	step.P99PutNs = percentile(lat, 99).Nanoseconds()
	latMu.Unlock()

	if v := first.Load(); v != nil {
		step.FirstError = v.(string)
	}

	return step, nil
}

func putOnce(ctx context.Context, up *retain.Uploader, cfg stepConfig, worker int, n uint64, hdr, body []byte) (objects, written int, err error) {
	tag := "waf-retain-ttl=3600"
	base := fmt.Sprintf("bench/%s/w%d/%d", cfg.stamp, worker, n)

	switch cfg.mode {
	case "headers":
		_, err = up.Put(ctx, cfg.hdrBucket, base+".hdr", hdr, tag)
		return 1, len(hdr), err
	case "body":
		_, err = up.Put(ctx, cfg.bodyBucket, base+".body", body, tag)
		return 1, len(body), err
	case "pair":
		if _, err = up.Put(ctx, cfg.hdrBucket, base+".hdr", hdr, tag); err != nil {
			return 0, 0, err
		}
		if _, err = up.Put(ctx, cfg.bodyBucket, base+".body", body, tag); err != nil {
			return 1, len(hdr), err
		}
		return 2, len(hdr) + len(body), nil
	default:
		return 0, 0, fmt.Errorf("unknown mode %q", cfg.mode)
	}
}

func parseSize(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	mult := 1
	switch {
	case strings.HasSuffix(s, "k"):
		mult, s = 1024, strings.TrimSuffix(s, "k")
	case strings.HasSuffix(s, "m"):
		mult, s = 1024*1024, strings.TrimSuffix(s, "m")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return n * mult, nil
}

func parseWorkers(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("workers: %q", part)
		}
		out = append(out, n)
	}
	return out, nil
}

func percentile(samples []time.Duration, p int) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), samples...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	i := (len(cp) - 1) * p / 100
	return cp[i]
}
