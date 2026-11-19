package main

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
)

type Server struct {
	store *Store
}

func NewServer(store *Store) *Server {
	return &Server{store: store}
}

func (srv *Server) Serve(ln *net.TCPListener) {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		_ = conn.SetNoDelay(true)
		go srv.serveConn(conn)
	}
}

func equalFoldASCII(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca == cb {
			continue
		}
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func parsePositiveIntBytes(b []byte) (int, bool) {
	if len(b) == 0 || len(b) > 10 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, n > 0
}

func writeAll(conn *net.TCPConn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// serveConn implements a zero-allocation raw HTTP/1.1 keep-alive loop directly on the TCP socket.
func (srv *Server) serveConn(conn *net.TCPConn) {
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 131072) // 128 KiB reusable read buffer
	scratch := make([]byte, 0, 16384)
	rPos := 0
	wPos := 0

	ensureBytes := func(need int) bool {
		for wPos-rPos < need {
			if rPos > 0 {
				copy(buf, buf[rPos:wPos])
				wPos -= rPos
				rPos = 0
			}
			if need > len(buf) {
				newCap := len(buf) * 2
				for newCap < need {
					newCap *= 2
				}
				nb := make([]byte, newCap)
				copy(nb, buf[:wPos])
				buf = nb
			}
			n, err := conn.Read(buf[wPos:])
			if n > 0 {
				wPos += n
			}
			if err != nil {
				return wPos-rPos >= need
			}
		}
		return true
	}

	for {
		// Locate end of HTTP headers (\r\n\r\n)
		hdrEnd := -1
		for {
			if wPos > rPos {
				if idx := bytes.Index(buf[rPos:wPos], []byte("\r\n\r\n")); idx >= 0 {
					hdrEnd = rPos + idx
					break
				}
			}
			if rPos > 0 {
				copy(buf, buf[rPos:wPos])
				wPos -= rPos
				rPos = 0
			}
			if wPos == len(buf) {
				nb := make([]byte, len(buf)*2)
				copy(nb, buf[:wPos])
				buf = nb
			}
			n, err := conn.Read(buf[wPos:])
			if n > 0 {
				wPos += n
			}
			if err != nil {
				if err == io.EOF && wPos == rPos {
					return
				}
				if wPos > rPos {
					if idx := bytes.Index(buf[rPos:wPos], []byte("\r\n\r\n")); idx >= 0 {
						hdrEnd = rPos + idx
						break
					}
				}
				return
			}
		}

		reqBytes := buf[rPos:hdrEnd]
		bodyStart := hdrEnd + 4

		// Parse request line: METHOD SP TARGET SP HTTP/1.x
		firstNL := bytes.IndexByte(reqBytes, '\r')
		var reqLine []byte
		var hdrBlock []byte
		if firstNL < 0 {
			reqLine = reqBytes
		} else {
			reqLine = reqBytes[:firstNL]
			if firstNL+2 <= len(reqBytes) {
				hdrBlock = reqBytes[firstNL+2:]
			}
		}
		sp1 := bytes.IndexByte(reqLine, ' ')
		if sp1 <= 0 {
			return
		}
		method := reqLine[:sp1]
		restLine := reqLine[sp1+1:]
		sp2 := bytes.IndexByte(restLine, ' ')
		if sp2 <= 0 {
			return
		}
		target := restLine[:sp2]

		// Parse only needed headers with zero allocation
		var authHdr []byte
		var hostHdr []byte
		var gitProto []byte
		contentLen := 0
		chunked := false
		closeConn := false

		hPos := 0
		for hPos < len(hdrBlock) {
			nl := bytes.IndexByte(hdrBlock[hPos:], '\r')
			var line []byte
			if nl < 0 {
				line = hdrBlock[hPos:]
				hPos = len(hdrBlock)
			} else {
				line = hdrBlock[hPos : hPos+nl]
				hPos += nl + 2
			}
			colon := bytes.IndexByte(line, ':')
			if colon <= 0 {
				continue
			}
			k := line[:colon]
			v := bytes.TrimSpace(line[colon+1:])
			switch len(k) {
			case 4:
				if (k[0] == 'H' || k[0] == 'h') && equalFoldASCII(k, []byte("host")) {
					hostHdr = v
				}
			case 10:
				if (k[0] == 'C' || k[0] == 'c') && equalFoldASCII(k, []byte("connection")) && equalFoldASCII(v, []byte("close")) {
					closeConn = true
				}
			case 12:
				if (k[0] == 'G' || k[0] == 'g') && equalFoldASCII(k, []byte("git-protocol")) {
					gitProto = v
				}
			case 13:
				if (k[0] == 'A' || k[0] == 'a') && equalFoldASCII(k, []byte("authorization")) {
					authHdr = v
				}
			case 14:
				if (k[0] == 'C' || k[0] == 'c') && equalFoldASCII(k, []byte("content-length")) {
					if cl, err := strconv.Atoi(string(v)); err == nil && cl > 0 {
						contentLen = cl
					}
				}
			case 17:
				if (k[0] == 'T' || k[0] == 't') && equalFoldASCII(k, []byte("transfer-encoding")) && bytes.Contains(bytes.ToLower(v), []byte("chunked")) {
					chunked = true
				}
			}
		}

		// Extract body. Copy tiny header slices ONLY if we need to read more bytes (multi-packet body or chunked),
		// so in-place compaction in ensureBytes can never overwrite active header slices, while single-packet
		// hot-path requests stay 100% zero-allocation!
		var body []byte
		rPos = bodyStart
		cloneBytes := func(src []byte) []byte {
			if len(src) == 0 {
				return nil
			}
			cp := make([]byte, len(src))
			copy(cp, src)
			return cp
		}
		if chunked || (contentLen > 0 && wPos-rPos < contentLen) {
			method = cloneBytes(method)
			target = cloneBytes(target)
			authHdr = cloneBytes(authHdr)
			hostHdr = cloneBytes(hostHdr)
			gitProto = cloneBytes(gitProto)
		}

		if chunked {
			// Decode HTTP/1.1 chunked body
			var decoded []byte
			for {
				lineEnd := -1
				for {
					if wPos > rPos {
						if idx := bytes.Index(buf[rPos:wPos], []byte("\r\n")); idx >= 0 {
							lineEnd = rPos + idx
							break
						}
					}
					if !ensureBytes(wPos - rPos + 1) {
						return
					}
				}
				szLine := bytes.TrimSpace(buf[rPos:lineEnd])
				if semi := bytes.IndexByte(szLine, ';'); semi >= 0 {
					szLine = szLine[:semi]
				}
				chunkSz, err := strconv.ParseInt(string(szLine), 16, 64)
				if err != nil || chunkSz < 0 {
					return
				}
				rPos = lineEnd + 2
				if chunkSz == 0 {
					if !ensureBytes(2) {
						return
					}
					rPos += 2
					break
				}
				if !ensureBytes(int(chunkSz) + 2) {
					return
				}
				decoded = append(decoded, buf[rPos:rPos+int(chunkSz)]...)
				rPos += int(chunkSz) + 2
			}
			body = decoded
		} else if contentLen > 0 {
			if !ensureBytes(contentLen) {
				return
			}
			body = buf[rPos : rPos+contentLen]
			rPos += contentLen
		}

		resp := srv.dispatchRequest(method, target, authHdr, hostHdr, gitProto, body, scratch)
		if err := writeAll(conn, resp); err != nil {
			return
		}
		if closeConn {
			return
		}
		if rPos == wPos {
			rPos = 0
			wPos = 0
		}
	}
}

func (srv *Server) dispatchRequest(method, target, authHdr, hostHdr, gitProto, body, scratch []byte) []byte {
	// Split path and query
	path := target
	var query []byte
	if qIdx := bytes.IndexByte(target, '?'); qIdx >= 0 {
		path = target[:qIdx]
		query = target[qIdx+1:]
	}

	// 1. /healthz (unauthenticated)
	if len(path) == 8 && bytes.Equal(path, []byte("/healthz")) {
		return respHealthzHTTP
	}

	// 2. Bearer auth check (all surfaces require token when MAKEFUN_SHOP_TOKEN is set)
	if srv.store.Token != "" {
		if !bytes.Equal(authHdr, srv.store.AuthHeader) {
			return respUnauthorized
		}
	}

	// 3. ULTRA-HOT FAST PATHS (ZERO ALLOCATION!)
	// 3a. /api/v3/repos/{owner}/{repo}/issues[/{num}]
	if len(path) > 14 && bytes.HasPrefix(path, []byte("/api/v3/repos/")) {
		rest := path[14:]
		s1 := bytes.IndexByte(rest, '/')
		if s1 > 0 {
			owner := rest[:s1]
			rest2 := rest[s1+1:]
			s2 := bytes.IndexByte(rest2, '/')
			if s2 > 0 {
				repoName := rest2[:s2]
				tail := rest2[s2:]
				// Fast GET /issues/{num}
				if len(method) == 3 && method[0] == 'G' && len(tail) > 8 && bytes.HasPrefix(tail, []byte("/issues/")) {
					numBytes := tail[8:]
					if bytes.IndexByte(numBytes, '/') < 0 {
						if num, ok := parsePositiveIntBytes(numBytes); ok {
							return srv.FastGetIssueHTTP(owner, repoName, num)
						}
					}
				}
				// Fast POST /issues
				if len(method) == 4 && method[0] == 'P' && method[1] == 'O' && bytes.Equal(tail, []byte("/issues")) {
					return srv.FastCreateIssueHTTP(owner, repoName, body, scratch)
				}
			}
		}
		return srv.handleREST(string(method), string(path), string(query), string(hostHdr), body)
	}

	// 3b. /api/v3...
	if bytes.HasPrefix(path, []byte("/api/v3")) {
		return srv.handleREST(string(method), string(path), string(query), string(hostHdr), body)
	}

	// 3c. /api/graphql
	if bytes.Equal(path, []byte("/api/graphql")) {
		if !bytes.Equal(method, []byte("POST")) {
			return respNotFoundJSON
		}
		return srv.handleGraphQL(body)
	}

	// 3d. /mcp
	if bytes.Equal(path, []byte("/mcp")) {
		if !bytes.Equal(method, []byte("POST")) {
			return respNotFoundJSON
		}
		return srv.handleMCP(body)
	}

	// 3e. Git Smart HTTP: /{owner}/{repo}.git/...
	if len(path) > 1 && path[0] == '/' {
		if gitIdx := bytes.Index(path, []byte(".git/")); gitIdx > 0 {
			prefix := path[1:gitIdx]
			if slash := bytes.IndexByte(prefix, '/'); slash > 0 {
				owner := prefix[:slash]
				repoName := prefix[slash+1:]
				gitSub := path[gitIdx+5:]
				if len(method) == 3 && method[0] == 'G' && bytes.Equal(gitSub, []byte("info/refs")) {
					return srv.handleGitInfoRefs(owner, repoName, query, gitProto)
				}
				if len(method) == 4 && method[0] == 'P' && bytes.Equal(gitSub, []byte("git-upload-pack")) {
					return srv.handleGitUploadPack(owner, repoName, gitProto, body)
				}
				if len(method) == 4 && method[0] == 'P' && bytes.Equal(gitSub, []byte("git-receive-pack")) {
					return srv.handleGitReceivePack(owner, repoName, body)
				}
			}
		}
	}

	_ = strings.Builder{}
	return respNotFoundJSON
}
