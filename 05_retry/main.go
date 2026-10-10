package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
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
	maxRetryAfter      = 30 * time.Second
	maxDrainBytes      = 1 << 20
)

func doRequest(client *http.Client, template *http.Request) (int, time.Duration, bool, error) {
	req := template.Clone(template.Context())
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, false, err
	}

	retryAfter, hasRetryAfter := parseRetryAfter(
		resp.Header.Get("Retry-After"),
	)

	_, _ = io.CopyN(io.Discard, resp.Body, maxDrainBytes)
	_ = resp.Body.Close()

	return resp.StatusCode, retryAfter, hasRetryAfter, nil
}

func shouldRetryStatus(status int) bool {
	switch status {
	case 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}

func calculateDelay(nextAttempt int, retryAfter time.Duration, hasRetryAfter bool) time.Duration {
	if hasRetryAfter {
		if retryAfter > maxRetryAfter {
			retryAfter = maxRetryAfter
		}
		return retryAfter.Truncate(time.Millisecond)
	}

	shift := nextAttempt - 2
	if shift < 0 {
		shift = 0
	}

	maxShift := 0
	for baseDelay*(1<<maxShift) < maxDelay {
		maxShift++
	}

	if shift > maxShift {
		shift = maxShift
	}

	delay := min(maxDelay, baseDelay*time.Duration(1<<shift))
	maxMillis := delay.Milliseconds()

	return time.Duration(rand.Int63n(maxMillis+1)) * time.Millisecond
}

func parseRetryAfter(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}

	isDigits := true
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			isDigits = false
			break
		}
	}

	if isDigits {
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return maxRetryAfter, true
		}

		delay := time.Duration(0)
		if seconds > int64(maxRetryAfter/time.Second) {
			delay = maxRetryAfter
		} else {
			delay = time.Duration(seconds) * time.Second
		}

		return delay, true
	}

	retryTime, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}

	delay := time.Until(retryTime)
	if delay < 0 {
		delay = 0
	}
	if delay > maxRetryAfter {
		delay = maxRetryAfter
	}

	return delay.Truncate(time.Millisecond), true
}

func errorText(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

func validateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}

	if strings.ToLower(u.Scheme) != "http" || u.Host == "" {
		return fmt.Errorf("only valid http URLs are supported")
	}

	return nil
}

func isIdempotentMethod(method string) bool {
	switch method {
	case http.MethodGet,
		http.MethodHead,
		http.MethodPut,
		http.MethodDelete,
		http.MethodOptions,
		http.MethodTrace:
		return true
	default:
		return false
	}
}

func parseArgs(args []string) (string, string, int, string, bool, error) {
	if len(args) == 0 {
		return "", "", 0, "", false, fmt.Errorf("no arguments")
	}

	rawURL := args[0]
	method := http.MethodGet
	maxAttempts := defaultMaxAttempts
	idempotencyKey := ""
	maxAttemptsSpecified := false

	for i := 1; i < len(args); i++ {
		arg := args[i]
		name, value, hasEquals := strings.Cut(arg, "=")

		switch name {
		case "--method", "--max-attempts", "--idempotency-key":
			if !hasEquals {
				if i+1 >= len(args) {
					return "", "", 0, "", false,
						fmt.Errorf("missing value for %s", name)
				}
				i++
				value = args[i]
			}

			switch name {
			case "--method":
				method = strings.ToUpper(value)
				if method == "" {
					return "", "", 0, "", false,
						fmt.Errorf("empty method")
				}
			case "--max-attempts":
				n, err := strconv.Atoi(value)
				if err != nil || n < 1 {
					return "", "", 0, "", false,
						fmt.Errorf("invalid max-attempts")
				}
				maxAttempts = n
				maxAttemptsSpecified = true
			case "--idempotency-key":
				idempotencyKey = value
			}
		default:
			return "", "", 0, "", false,
				fmt.Errorf("unknown argument: %s", arg)
		}
	}

	return rawURL, method, maxAttempts, idempotencyKey,
		maxAttemptsSpecified, nil
}

func main() {
	rawURL, method, maxAttempts, idempotencyKey,
		maxAttemptsSpecified, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := validateURL(rawURL); err != nil {
		fmt.Fprintln(os.Stderr, "invalid URL:", errorText(err))
		os.Exit(1)
	}

	template, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid request:", errorText(err))
		os.Exit(1)
	}

	if idempotencyKey != "" {
		template.Header.Set("Idempotency-Key", idempotencyKey)
	}

	if !isIdempotentMethod(method) && idempotencyKey == "" {
		if maxAttemptsSpecified && maxAttempts > 1 {
			fmt.Fprintln(
				os.Stderr,
				"non-idempotent method without Idempotency-Key: retries disabled",
			)
		}
		maxAttempts = 1
	}

	client := &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	success := false
	attempt := 0

	for attempt < maxAttempts {
		attempt++

		status, retryAfter, hasRetryAfter, requestErr :=
			doRequest(client, template)

		retryable := requestErr != nil

		if requestErr != nil {
			fmt.Printf("attempt %d error %s\n", attempt, errorText(requestErr))
		} else {
			fmt.Printf("attempt %d status %d\n", attempt, status)

			if status >= 200 && status <= 399 {
				success = true
				break
			}

			retryable = shouldRetryStatus(status)
		}

		if !retryable || attempt == maxAttempts {
			break
		}

		if hasRetryAfter && retryAfter > maxRetryAfter {
			break
		}

		delay := calculateDelay(attempt+1, retryAfter, hasRetryAfter)
		fmt.Printf("sleep_ms %d\n", delay.Milliseconds())
		time.Sleep(delay)
	}

	if success {
		fmt.Printf("result success attempts %d\n", attempt)
		return
	}

	fmt.Printf("result failure attempts %d\n", attempt)
	os.Exit(1)
}
