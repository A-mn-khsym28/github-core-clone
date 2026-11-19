package main

import (
	"bytes"
	"io"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

var (
	hdrDelimCRLFCRLF  = []byte("\r\n\r\n")
	hdrDelimCRLF      = []byte("\r\n")
	prefixReposAPI    = []byte("/api/v3/repos/")
	prefixAPIV3       = []byte("/api/v3")
	prefixIssuesSlash = []byte("/issues/")
	pathIssuesExact   = []byte("/issues")
	pathHealthz       = []byte("/healthz")
	pathGraphQL       = []byte("/api/graphql")
	pathMCP           = []byte("/mcp")
	dotGitSlash       = []byte(".git/")
	gitInfoRefs       = []byte("info/refs")
	gitUploadPack     = []byte("git-upload-pack")
	gitReceivePack    = []byte("git-receive-pack")
	hdrHost           = []byte("host")
	hdrConnection     = []byte("connection")
	hdrClose          = []byte("close")
	hdrCloseTitle     = []byte("Close")
	hdrGitProto       = []byte("git-protocol")
	hdrAuthorization  = []byte("authorization")
	hdrContentLength  = []byte("content-length")
	hdrTransferEnc    = []byte("transfer-encoding")
	valChunked        = []byte("chunked")
	methodPOST        = []byte("POST")
)

type Server struct {
	store       *Store
	readBufPool sync.Pool
	scratchPool sync.Pool
}

func NewServer(store *Store) *Server {
	srv := &Server{
		store: store,
		readBufPool: sync.Pool{
			New: func() any {
				b := make([]byte, 16384)
				return &b
			},
		},
		scratchPool: sync.Pool{
			New: func() any {
				b := make([]byte, 0, 8192)
				return &b
			},
		},
	}
	// Pre-warm pooled buffers at startup to avoid gVisor page faults during concurrent clone bursts.
	preRead := make([]*[]byte, 64)
	preScratch := make([]*[]byte, 64)
	for i := 0; i < 64; i++ {
		rb := make([]byte, 16384)
		sb := make([]byte, 0, 8192)
		preRead[i] = &rb
		preScratch[i] = &sb
	}
	for i := 0; i < 64; i++ {
		srv.readBufPool.Put(preRead[i])
		srv.scratchPool.Put(preScratch[i])
	}
	return srv
}

func listenRawTCP() (int, int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, 0, err
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	sa := &syscall.SockaddrInet4{Port: 0, Addr: [4]byte{0, 0, 0, 0}}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return -1, 0, err
	}
	if err := syscall.Listen(fd, 1024); err != nil {
		_ = syscall.Close(fd)
		return -1, 0, err
	}
	lsa, err := syscall.Getsockname(fd)
	if err != nil {
		_ = syscall.Close(fd)
		return -1, 0, err
	}
	inet4, ok := lsa.(*syscall.SockaddrInet4)
	if !ok {
		_ = syscall.Close(fd)
		return -1, 0, syscall.EINVAL
	}
	return fd, inet4.Port, nil
}

func (srv *Server) ServeFD(listenFD int) {
	for {
		fd, _, err := syscall.Accept(listenFD)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}
			return
		}
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
		go srv.serveFD(fd)
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

func containsFoldASCII(haystack, needle []byte) bool {
	n := len(needle)
	if n == 0 || len(haystack) < n {
		return false
	}
	for i := 0; i <= len(haystack)-n; i++ {
		if equalFoldASCII(haystack[i:i+n], needle) {
			return true
		}
	}
	return false
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

func parseNonNegIntBytes(b []byte) (int, bool) {
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
	return n, true
}

func rawRead(fd int, p []byte) (int, error) {
	for {
		n, err := syscall.Read(fd, p)
		if err == syscall.EINTR {
			continue
		}
		return n, err
	}
}

func rawWriteAll(fd int, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	// Fast path for normal responses (<= 32 KiB): bypass Go entersyscall/exitsyscall with RawSyscall(SYS_WRITE).
	if len(data) <= 32768 {
		for len(data) > 0 {
			r1, _, errno := syscall.RawSyscall(
				syscall.SYS_WRITE,
				uintptr(fd),
				uintptr(unsafe.Pointer(&data[0])),
				uintptr(len(data)),
			)
			if errno != 0 {
				if errno == syscall.EINTR {
					continue
				}
				if errno == syscall.EAGAIN {
					break
				}
				return errno
			}
			n := int(r1)
			if n <= 0 {
				return io.ErrShortWrite
			}
			data = data[n:]
		}
		if len(data) == 0 {
			return nil
		}
	}
	for len(data) > 0 {
		n, err := syscall.Write(fd, data)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// serveFD implements a zero-allocation raw blocking-syscall HTTP/1.1 keep-alive loop directly on fd.
// Completely bypasses Go's netpoller (0 EAGAIN, 0 epoll_ctl, 0 epoll_pwait, 0 futex -> 2 syscalls/req).
func (srv *Server) serveFD(fd int) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer func() { _ = syscall.Close(fd) }()

	bufPtr := srv.readBufPool.Get().(*[]byte)
	buf := *bufPtr
	scratchPtr := srv.scratchPool.Get().(*[]byte)
	scratch := (*scratchPtr)[:0]
	defer func() {
		if cap(buf) <= 65536 {
			*bufPtr = buf[:cap(buf)]
			srv.readBufPool.Put(bufPtr)
		}
		if cap(scratch) <= 32768 {
			*scratchPtr = scratch[:0]
			srv.scratchPool.Put(scratchPtr)
		}
	}()

	// Connection-local repo cache (avoids even atomic map hash lookups on keep-alive connections!)
	var lastOwnerBuf [64]byte
	var lastRepoBuf [128]byte
	lastOwnerLen := 0
	lastRepoLen := 0
	var lastRepo *Repo

	lookupRepo := func(owner, repoName []byte) *Repo {
		if lastRepo != nil && !lastRepo.deleted.Load() &&
			len(owner) == lastOwnerLen && len(repoName) == lastRepoLen &&
			bytes.Equal(owner, lastOwnerBuf[:lastOwnerLen]) &&
			bytes.Equal(repoName, lastRepoBuf[:lastRepoLen]) {
			return lastRepo
		}
		r := srv.store.GetRepoBytes(owner, repoName)
		if r != nil && len(owner) <= len(lastOwnerBuf) && len(repoName) <= len(lastRepoBuf) {
			copy(lastOwnerBuf[:], owner)
			copy(lastRepoBuf[:], repoName)
			lastOwnerLen = len(owner)
			lastRepoLen = len(repoName)
			lastRepo = r
		}
		return r
	}

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
			n, err := rawRead(fd, buf[wPos:])
			if n > 0 {
				wPos += n
			}
			if n == 0 || err != nil {
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
				if idx := bytes.Index(buf[rPos:wPos], hdrDelimCRLFCRLF); idx >= 0 {
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
			n, err := rawRead(fd, buf[wPos:])
			if n > 0 {
				wPos += n
			}
			if n == 0 || err != nil {
				if wPos > rPos {
					if idx := bytes.Index(buf[rPos:wPos], hdrDelimCRLFCRLF); idx >= 0 {
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

		// ULTRA-HOT SIMD FAST PATH: GET /api/v3/repos/{owner}/{repo}/issues/{num}
		// Skips header line-by-line loop entirely using a single AVX2 bytes.Index auth verification.
		if len(method) == 3 && method[0] == 'G' && method[1] == 'E' && method[2] == 'T' &&
			len(target) > 22 && bytes.HasPrefix(target, prefixReposAPI) &&
			bytes.IndexByte(target, '?') < 0 {
			rest := target[14:]
			if s1 := bytes.IndexByte(rest, '/'); s1 > 0 {
				rest2 := rest[s1+1:]
				if s2 := bytes.IndexByte(rest2, '/'); s2 > 0 {
					tail := rest2[s2:]
					if len(tail) > 8 && bytes.HasPrefix(tail, prefixIssuesSlash) && bytes.IndexByte(tail[8:], '/') < 0 {
						if num, ok := parsePositiveIntBytes(tail[8:]); ok {
							authOK := srv.store.Token == ""
							if !authOK {
								if idx := bytes.Index(hdrBlock, srv.store.AuthHeader); idx >= 15 {
									endPos := idx + len(srv.store.AuthHeader)
									if endPos == len(hdrBlock) || hdrBlock[endPos] == '\r' {
										p := idx - 1
										for p >= 0 && (hdrBlock[p] == ' ' || hdrBlock[p] == '\t') {
											p--
										}
										if p >= 13 && hdrBlock[p] == ':' && equalFoldASCII(hdrBlock[p-13:p], hdrAuthorization) {
											if p-13 == 0 || hdrBlock[p-14] == '\n' {
												authOK = true
											}
										}
									}
								}
							}
							if authOK && bytes.Index(hdrBlock, hdrClose) < 0 && bytes.Index(hdrBlock, hdrCloseTitle) < 0 {
								r := lookupRepo(rest[:s1], rest2[:s2])
								resp := srv.FastGetIssueHTTP(r, num)
								if err := rawWriteAll(fd, resp); err != nil {
									return
								}
								rPos = bodyStart
								if rPos == wPos {
									rPos = 0
									wPos = 0
								}
								continue
							}
						}
					}
				}
			}
		}

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
				if (k[0] == 'H' || k[0] == 'h') && equalFoldASCII(k, hdrHost) {
					hostHdr = v
				}
			case 10:
				if (k[0] == 'C' || k[0] == 'c') && equalFoldASCII(k, hdrConnection) && equalFoldASCII(v, hdrClose) {
					closeConn = true
				}
			case 12:
				if (k[0] == 'G' || k[0] == 'g') && equalFoldASCII(k, hdrGitProto) {
					gitProto = v
				}
			case 13:
				if (k[0] == 'A' || k[0] == 'a') && equalFoldASCII(k, hdrAuthorization) {
					authHdr = v
				}
			case 14:
				if (k[0] == 'C' || k[0] == 'c') && equalFoldASCII(k, hdrContentLength) {
					if cl, ok := parseNonNegIntBytes(v); ok {
						contentLen = cl
					}
				}
			case 17:
				if (k[0] == 'T' || k[0] == 't') && equalFoldASCII(k, hdrTransferEnc) && containsFoldASCII(v, valChunked) {
					chunked = true
				}
			}
		}

		// Extract body. Copy tiny header slices ONLY if we need to read more bytes (multi-packet body or chunked),
		// so in-place compaction in ensureBytes can never overwrite active header slices, while single-packet
		// hot-path requests stay 100% zero-allocation!
		var body []byte
		rPos = bodyStart
		if chunked || (contentLen > 0 && wPos-rPos < contentLen) {
			cloneBytes := func(src []byte) []byte {
				if len(src) == 0 {
					return nil
				}
				cp := make([]byte, len(src))
				copy(cp, src)
				return cp
			}
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
						if idx := bytes.Index(buf[rPos:wPos], hdrDelimCRLF); idx >= 0 {
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

		resp := srv.dispatchRequest(method, target, authHdr, hostHdr, gitProto, body, scratch, lookupRepo)
		if err := rawWriteAll(fd, resp); err != nil {
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

func (srv *Server) dispatchRequest(
	method, target, authHdr, hostHdr, gitProto, body, scratch []byte,
	lookupRepo func(owner, repoName []byte) *Repo,
) []byte {
	// Split path and query
	path := target
	var query []byte
	if qIdx := bytes.IndexByte(target, '?'); qIdx >= 0 {
		path = target[:qIdx]
		query = target[qIdx+1:]
	}

	// 1. /healthz (unauthenticated)
	if len(path) == 8 && bytes.Equal(path, pathHealthz) {
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
	if len(path) > 14 && bytes.HasPrefix(path, prefixReposAPI) {
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
				if len(method) == 3 && method[0] == 'G' && len(tail) > 8 && bytes.HasPrefix(tail, prefixIssuesSlash) {
					numBytes := tail[8:]
					if bytes.IndexByte(numBytes, '/') < 0 {
						if num, ok := parsePositiveIntBytes(numBytes); ok {
							return srv.FastGetIssueHTTP(lookupRepo(owner, repoName), num)
						}
					}
				}
				// Fast POST /issues
				if len(method) == 4 && method[0] == 'P' && method[1] == 'O' && bytes.Equal(tail, pathIssuesExact) {
					return srv.FastCreateIssueHTTP(lookupRepo(owner, repoName), body, scratch)
				}
			}
		}
		return srv.handleREST(string(method), string(path), string(query), string(hostHdr), body)
	}

	// 3b. /api/v3...
	if bytes.HasPrefix(path, prefixAPIV3) {
		return srv.handleREST(string(method), string(path), string(query), string(hostHdr), body)
	}

	// 3c. /api/graphql
	if bytes.Equal(path, pathGraphQL) {
		if !bytes.Equal(method, methodPOST) {
			return respNotFoundJSON
		}
		return srv.handleGraphQL(body)
	}

	// 3d. /mcp
	if bytes.Equal(path, pathMCP) {
		if !bytes.Equal(method, methodPOST) {
			return respNotFoundJSON
		}
		return srv.handleMCP(body)
	}

	// 3e. Git Smart HTTP: /{owner}/{repo}.git/...
	if len(path) > 1 && path[0] == '/' {
		if gitIdx := bytes.Index(path, dotGitSlash); gitIdx > 0 {
			prefix := path[1:gitIdx]
			if slash := bytes.IndexByte(prefix, '/'); slash > 0 {
				owner := prefix[:slash]
				repoName := prefix[slash+1:]
				gitSub := path[gitIdx+5:]
				if len(method) == 3 && method[0] == 'G' && bytes.Equal(gitSub, gitInfoRefs) {
					return srv.handleGitInfoRefs(lookupRepo(owner, repoName), query, gitProto)
				}
				if len(method) == 4 && method[0] == 'P' && bytes.Equal(gitSub, gitUploadPack) {
					return srv.handleGitUploadPack(lookupRepo(owner, repoName), gitProto, body)
				}
				if len(method) == 4 && method[0] == 'P' && bytes.Equal(gitSub, gitReceivePack) {
					return srv.handleGitReceivePack(lookupRepo(owner, repoName), body)
				}
			}
		}
	}

	return respNotFoundJSON
}
