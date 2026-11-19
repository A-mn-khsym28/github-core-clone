package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
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
}

func registerPort(envURL string, port int) error {
	client := &http.Client{Timeout: 10 * time.Second}
	body := []byte(fmt.Sprintf(`{"port":%d}`, port))
	backoff := 50 * time.Millisecond
	for attempt := 0; attempt < 60; attempt++ {
		req, err := http.NewRequest("POST", envURL+"/register", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 || resp.StatusCode == 409 {
				return nil
			}
			if resp.StatusCode == 400 || resp.StatusCode == 405 {
				return fmt.Errorf("register rejected HTTP %d", resp.StatusCode)
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
	client := &http.Client{Timeout: 15 * time.Second}
	type doneResp struct {
		Done bool `json:"done"`
	}
	backoff := 800 * time.Millisecond
	for {
		resp, err := client.Get(envURL + "/done")
		if err == nil {
			data, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				var dr doneResp
				if json.Unmarshal(data, &dr) == nil && dr.Done {
					close(doneCh)
					return
				}
			}
			backoff = 800 * time.Millisecond
		} else {
			if backoff < time.Second {
				backoff *= 2
			}
		}
		time.Sleep(backoff)
	}
}
