package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	runtime.GOMAXPROCS(2)
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(768 << 20)

	envURL := strings.TrimRight(os.Getenv("MAKEFUN_ENV_URL"), "/")
	token := os.Getenv("MAKEFUN_SHOP_TOKEN")
	viewerLogin := os.Getenv("MAKEFUN_FORGE_LOGIN")
	if viewerLogin == "" {
		viewerLogin = "adaiversen"
	}

	store := NewStore(viewerLogin, token)
	srv := NewServer(store)

	listenFD, port, err := listenRawTCP()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[forge] listen failed: %v\n", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	doneCh := make(chan struct{})
	go func() {
		srv.ServeFD(listenFD)
	}()

	if envURL != "" {
		if err := registerPort(envURL, port); err != nil {
			fmt.Fprintf(os.Stderr, "[forge] register failed: %v\n", err)
			os.Exit(1)
		}
		go pollDone(envURL, doneCh)
	} else {
		fmt.Fprintf(os.Stdout, "LISTEN http://127.0.0.1:%d\n", port)
	}

	select {
	case <-doneCh:
	case <-sigCh:
	}
	_ = syscall.Close(listenFD)
	os.Exit(0)
}

func rawLocalHTTP(method, rawURL, contentType string, body []byte, timeout time.Duration) (int, []byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0, nil, err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var req bytes.Buffer
	req.WriteString(method)
	req.WriteByte(' ')
	req.WriteString(path)
	req.WriteString(" HTTP/1.1\r\nHost: ")
	req.WriteString(u.Host)
	req.WriteString("\r\nConnection: close\r\n")
	if contentType != "" {
		req.WriteString("Content-Type: ")
		req.WriteString(contentType)
		req.WriteString("\r\n")
	}
	if len(body) > 0 {
		req.WriteString("Content-Length: ")
		req.WriteString(strconv.Itoa(len(body)))
		req.WriteString("\r\n")
	}
	req.WriteString("\r\n")
	if len(body) > 0 {
		req.Write(body)
	}

	if _, err := conn.Write(req.Bytes()); err != nil {
		return 0, nil, err
	}
	raw, err := io.ReadAll(conn)
	if err != nil && len(raw) == 0 {
		return 0, nil, err
	}
	hdrEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		return 0, nil, fmt.Errorf("malformed HTTP response")
	}
	hdrBytes := raw[:hdrEnd]
	respBody := raw[hdrEnd+4:]

	firstLineEnd := bytes.Index(hdrBytes, []byte("\r\n"))
	statusLine := hdrBytes
	if firstLineEnd >= 0 {
		statusLine = hdrBytes[:firstLineEnd]
	}
	parts := bytes.SplitN(statusLine, []byte(" "), 3)
	if len(parts) < 2 {
		return 0, nil, fmt.Errorf("malformed status line")
	}
	statusCode, err := strconv.Atoi(string(parts[1]))
	if err != nil {
		return 0, nil, err
	}
	if bytes.Contains(bytes.ToLower(hdrBytes), []byte("transfer-encoding: chunked")) {
		if decoded, _, ok, _ := parseChunkedComplete(respBody); ok {
			respBody = decoded
		}
	}
	return statusCode, respBody, nil
}

func registerPort(envURL string, port int) error {
	body := []byte(fmt.Sprintf(`{"port":%d}`, port))
	backoff := 50 * time.Millisecond
	for attempt := 0; attempt < 60; attempt++ {
		code, _, err := rawLocalHTTP("POST", envURL+"/register", "application/json", body, 10*time.Second)
		if err == nil {
			if code == 200 || code == 409 {
				return nil
			}
			if code == 400 || code == 405 {
				return fmt.Errorf("register rejected HTTP %d", code)
			}
		}
		time.Sleep(backoff)
		if backoff < time.Second {
			backoff *= 2
		}
	}
	return fmt.Errorf("register timed out")
}

func pollDone(envURL string, doneCh chan<- struct{}) {
	type doneResp struct {
		Done bool `json:"done"`
	}
	backoff := 1500 * time.Millisecond
	for {
		code, data, err := rawLocalHTTP("GET", envURL+"/done", "", nil, 15*time.Second)
		if err == nil {
			if code == 200 {
				var dr doneResp
				if json.Unmarshal(data, &dr) == nil && dr.Done {
					close(doneCh)
					return
				}
			}
			backoff = 1500 * time.Millisecond
		} else {
			if backoff < 2*time.Second {
				backoff *= 2
			}
		}
		time.Sleep(backoff)
	}
}
