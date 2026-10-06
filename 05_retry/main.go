package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxAttempts = 5
	requestTimeout     = 5 * time.Second
	baseDelay          = 200 * time.Millisecond
	maxDelay           = 2000 * time.Millisecond
)

func doRequest(client *http.Client, method string, url string, idempotencyKey string) (int, time.Duration, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return 0, 0, err
	}

	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))

	return resp.StatusCode, retryAfter, nil
}

func shouldRetryStatus(status int) bool {
	switch status {
	case 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}

func calculateDelay(nextAttempt int, retryAfter time.Duration, rng *rand.Rand) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}

	// min(2000, 200 * 2^(n-1))
	delay := 200
	for i := 1; i < nextAttempt; i++ {
		delay *= 2
		if delay >= 2000 {
			delay = 2000
			break
		}
	}

	return time.Duration(rng.Int63n(int64(delay)+1)) * time.Millisecond
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	seconds, err := strconv.Atoi(value)
	if err != nil || seconds < 0 {
		return 0
	}

	return time.Duration(seconds) * time.Second
}

func errorText(err error) string {
	return strings.ReplaceAll(err.Error(), "\n", " ")
}

func isHTTPURL(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "http://")
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "no arguments")
		os.Exit(1)
	}

	url := args[0]

	method := "GET"
	maxAttempts := defaultMaxAttempts
	idempotencyKey := ""

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--method":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "missing value for method")
				os.Exit(1)
			}
			method = strings.ToUpper(args[i+1])
			i++

		case "--max-attempts":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "missing value for max-attempts")
				os.Exit(1)
			}
			value, err := strconv.Atoi(args[i+1])
			if err != nil || value < 1 {
				fmt.Fprintln(os.Stderr, "invalid max-attempts")
				os.Exit(1)
			}
			maxAttempts = value
			i++

		case "--idempotency-key":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "missing value for idempotency-key")
				os.Exit(1)
			}
			idempotencyKey = args[i+1]
			i++

		default:
			fmt.Fprintln(os.Stderr, "unknown argument:", args[i])
			os.Exit(1)
		}
	}

	if !isHTTPURL(url) {
		fmt.Fprintln(os.Stderr, "only http scheme supported")
		os.Exit(1)
	}

	if method == "POST" && idempotencyKey == "" {
		maxAttempts = 1
	}

	client := &http.Client{
		Timeout: requestTimeout,
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	success := false
	attempts := 0

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attempts = attempt
		status, retryAfter, err := doRequest(client, method, url, idempotencyKey)
		if err != nil {
			fmt.Printf("attempt %d error %s\n", attempt, errorText(err))
			if attempt == maxAttempts {
				break
			}
			delay := calculateDelay(attempt+1, retryAfter, rng)
			fmt.Printf("sleep_ms %d\n", delay.Milliseconds())
			time.Sleep(delay)
			continue
		}

		fmt.Printf("attempt %d status %d\n", attempt, status)

		if status >= 200 && status <= 399 {
			success = true
			break
		}
		if !shouldRetryStatus(status) {
			break
		}
		if attempt == maxAttempts {
			break
		}

		delay := calculateDelay(attempt+1, retryAfter, rng)
		fmt.Printf("sleep_ms %d\n", delay.Milliseconds())
		time.Sleep(delay)
	}

	if success {
		fmt.Printf("result success attempts %d\n", attempts)
		os.Exit(0)
	}

	fmt.Printf("result failure attempts %d\n", attempts)
	os.Exit(1)
}
