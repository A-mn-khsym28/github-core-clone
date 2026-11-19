package main

import (
	"bytes"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

var (
	hdrDelimCRLFCRLF     = []byte("\r\n\r\n")
	hdrDelimCRLF         = []byte("\r\n")
	prefixReposAPI       = []byte("/api/v3/repos/")
	prefixAPIV3          = []byte("/api/v3")
	prefixIssuesSlash    = []byte("/issues/")
	pathIssuesExact      = []byte("/issues")
	pathHealthz          = []byte("/healthz")
	pathGraphQL          = []byte("/api/graphql")
	pathMCP              = []byte("/mcp")
	dotGitSlash          = []byte(".git/")
	suffixInfoRefsUpload = []byte(".git/info/refs?service=git-upload-pack")
	suffixInfoRefsRecv   = []byte(".git/info/refs?service=git-receive-pack")
	gitInfoRefs          = []byte("info/refs")
	gitUploadPack        = []byte("git-upload-pack")
	gitReceivePack       = []byte("git-receive-pack")
	hdrHost              = []byte("host")
	hdrConnection        = []byte("connection")
	hdrClose             = []byte("close")
	hdrCloseTitle        = []byte("Close")
	hdrGitProto          = []byte("git-protocol")
	hdrGitProtoV2Lower   = []byte("git-protocol: version=2")
	hdrGitProtoV2Title   = []byte("Git-Protocol: version=2")
	hdrAuthorization     = []byte("authorization")
	hdrContentLength     = []byte("content-length")
	hdrTransferEnc       = []byte("transfer-encoding")
	valChunked           = []byte("chunked")
	methodPOST           = []byte("POST")
)

type connState struct {
	fd           int
	buf          []byte
	rPos         int
	wPos         int
	pendingWrite []byte
	closeAfter   bool
	wantOut      bool

	// Connection-local repo cache (skips atomic map hash on keep-alive connections)
	lastOwnerBuf [64]byte
	lastRepoBuf  [128]byte
	lastOwnerLen int
	lastRepoLen  int
	lastRepo     *Repo
}

func (c *connState) lookupRepo(srv *Server, owner, repoName []byte) *Repo {
	if c.lastRepo != nil && !c.lastRepo.deleted.Load() &&
		len(owner) == c.lastOwnerLen && len(repoName) == c.lastRepoLen &&
		bytes.Equal(owner, c.lastOwnerBuf[:c.lastOwnerLen]) &&
		bytes.Equal(repoName, c.lastRepoBuf[:c.lastRepoLen]) {
		return c.lastRepo
	}
	r := srv.store.GetRepoBytes(owner, repoName)
	if r != nil && len(owner) <= len(c.lastOwnerBuf) && len(repoName) <= len(c.lastRepoBuf) {
		copy(c.lastOwnerBuf[:], owner)
		copy(c.lastRepoBuf[:], repoName)
		c.lastOwnerLen = len(owner)
		c.lastRepoLen = len(repoName)
		c.lastRepo = r
	}
	return r
}

type Server struct {
	store     *Store
	scratch   []byte
	connsArr  [512]*connState
	connsMap  map[int]*connState
	freeConns []*connState
}

func NewServer(store *Store) *Server {
	srv := &Server{
		store:     store,
		scratch:   make([]byte, 0, 16384),
		connsMap:  make(map[int]*connState, 16),
		freeConns: make([]*connState, 0, 64),
	}
	// Pre-warm 64 connection structs + 16 KiB buffers at startup (0 page faults on 50-clone burst!)
	for i := 0; i < 64; i++ {
		srv.freeConns = append(srv.freeConns, &connState{
			fd:  -1,
			buf: make([]byte, 16384),
		})
	}
	return srv
}

func (srv *Server) allocConn(fd int) *connState {
	var c *connState
	if n := len(srv.freeConns); n > 0 {
		c = srv.freeConns[n-1]
		srv.freeConns = srv.freeConns[:n-1]
		c.fd = fd
		c.rPos = 0
		c.wPos = 0
		c.pendingWrite = nil
		c.closeAfter = false
		c.wantOut = false
		c.lastOwnerLen = 0
		c.lastRepoLen = 0
		c.lastRepo = nil
	} else {
		c = &connState{
			fd:  fd,
			buf: make([]byte, 16384),
		}
	}
	if fd >= 0 && fd < len(srv.connsArr) {
		srv.connsArr[fd] = c
	} else {
		srv.connsMap[fd] = c
	}
	return c
}

func (srv *Server) getConn(fd int) *connState {
	if fd >= 0 && fd < len(srv.connsArr) {
		return srv.connsArr[fd]
	}
	return srv.connsMap[fd]
}

func (srv *Server) closeConn(c *connState) {
	fd := c.fd
	if fd < 0 {
		return
	}
	if fd < len(srv.connsArr) {
		srv.connsArr[fd] = nil
	} else {
		delete(srv.connsMap, fd)
	}
	c.fd = -1
	_, _, _ = syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(fd), 0, 0)
	c.pendingWrite = nil
	c.lastRepo = nil
	if len(c.buf) > 65536 {
		c.buf = make([]byte, 16384)
	}
	if len(srv.freeConns) < 128 {
		srv.freeConns = append(srv.freeConns, c)
	}
}

func listenRawTCP() (int, int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
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

func rawEpollCtl(epfd, op, fd int, events uint32) syscall.Errno {
	ev := syscall.EpollEvent{Events: events, Fd: int32(fd)}
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_EPOLL_CTL,
		uintptr(epfd),
		uintptr(op),
		uintptr(fd),
		uintptr(unsafe.Pointer(&ev)),
		0,
		0,
	)
	return errno
}

func rawNonBlockRead(fd int, p []byte) (int, syscall.Errno) {
	for {
		r1, _, errno := syscall.RawSyscall(
			syscall.SYS_READ,
			uintptr(fd),
			uintptr(unsafe.Pointer(&p[0])),
			uintptr(len(p)),
		)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return 0, errno
		}
		return int(r1), 0
	}
}

func rawNonBlockWrite(fd int, p []byte) (int, syscall.Errno) {
	for {
		r1, _, errno := syscall.RawSyscall(
			syscall.SYS_WRITE,
			uintptr(fd),
			uintptr(unsafe.Pointer(&p[0])),
			uintptr(len(p)),
		)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return 0, errno
		}
		return int(r1), 0
	}
}

// ServeFD runs a single-threaded raw Linux epoll event loop pinned to one OS thread.
// Zero Go netpoller, zero goroutine-per-conn, zero thread spawns on clone bursts,
// zero EAGAIN reads on steady-state keep-alive requests (3 raw syscalls/req total).
func (srv *Server) ServeFD(listenFD int) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return
	}
	defer func() { _ = syscall.Close(epfd) }()

	if errno := rawEpollCtl(epfd, syscall.EPOLL_CTL_ADD, listenFD, syscall.EPOLLIN); errno != 0 {
		return
	}

	var events [64]syscall.EpollEvent
	one := int32(1)
	negOne := ^uintptr(0)

	for {
		r1, _, errno := syscall.RawSyscall6(
			syscall.SYS_EPOLL_PWAIT,
			uintptr(epfd),
			uintptr(unsafe.Pointer(&events[0])),
			uintptr(len(events)),
			negOne,
			0,
			8,
		)
		if errno != 0 {
			if errno == syscall.EINTR {
				continue
			}
			return
		}
		n := int(r1)
		for i := 0; i < n; i++ {
			fd := int(events[i].Fd)
			ev := events[i].Events
			if fd == listenFD {
				for {
					cr1, _, cerr := syscall.RawSyscall6(
						syscall.SYS_ACCEPT4,
						uintptr(listenFD),
						0,
						0,
						uintptr(syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC),
						0,
						0,
					)
					if cerr != 0 {
						if cerr == syscall.EINTR {
							continue
						}
						break
					}
					cfd := int(cr1)
					_, _, _ = syscall.RawSyscall6(
						syscall.SYS_SETSOCKOPT,
						uintptr(cfd),
						uintptr(syscall.IPPROTO_TCP),
						uintptr(syscall.TCP_NODELAY),
						uintptr(unsafe.Pointer(&one)),
						4,
						0,
					)
					if rawEpollCtl(epfd, syscall.EPOLL_CTL_ADD, cfd, syscall.EPOLLIN) != 0 {
						_, _, _ = syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(cfd), 0, 0)
						continue
					}
					srv.allocConn(cfd)
				}
				continue
			}

			c := srv.getConn(fd)
			if c == nil {
				continue
			}
			if (ev&(syscall.EPOLLERR|syscall.EPOLLHUP)) != 0 && (ev&syscall.EPOLLIN) == 0 {
				srv.closeConn(c)
				continue
			}
			if (ev & syscall.EPOLLOUT) != 0 {
				srv.flushPending(epfd, c)
				if c.fd < 0 {
					continue
				}
			}
			if (ev & syscall.EPOLLIN) != 0 {
				srv.onReadable(epfd, c)
			}
		}
	}
}

func (srv *Server) flushPending(epfd int, c *connState) {
	for len(c.pendingWrite) > 0 {
		n, errno := rawNonBlockWrite(c.fd, c.pendingWrite)
		if errno == syscall.EAGAIN {
			return
		}
		if errno != 0 || n <= 0 {
			srv.closeConn(c)
			return
		}
		c.pendingWrite = c.pendingWrite[n:]
	}
	if c.closeAfter {
		srv.closeConn(c)
		return
	}
	if c.wantOut {
		c.wantOut = false
		_ = rawEpollCtl(epfd, syscall.EPOLL_CTL_MOD, c.fd, syscall.EPOLLIN)
	}
	if c.wPos > c.rPos {
		srv.processBuffered(epfd, c)
	}
}

func (srv *Server) sendResp(epfd int, c *connState, resp []byte, closeAfter bool) bool {
	if len(resp) > 0 {
		n, errno := rawNonBlockWrite(c.fd, resp)
		if errno == 0 && n == len(resp) {
			if closeAfter {
				srv.closeConn(c)
				return false
			}
			return true
		}
		if errno != 0 && errno != syscall.EAGAIN {
			srv.closeConn(c)
			return false
		}
		rem := resp[n:]
		cp := make([]byte, len(rem))
		copy(cp, rem)
		c.pendingWrite = cp
		c.closeAfter = closeAfter
		if !c.wantOut {
			c.wantOut = true
			_ = rawEpollCtl(epfd, syscall.EPOLL_CTL_MOD, c.fd, syscall.EPOLLIN|syscall.EPOLLOUT)
		}
		return false
	}
	if closeAfter {
		srv.closeConn(c)
		return false
	}
	return true
}

func (srv *Server) onReadable(epfd int, c *connState) {
	if len(c.pendingWrite) > 0 {
		srv.flushPending(epfd, c)
		if c.fd < 0 || len(c.pendingWrite) > 0 {
			return
		}
	}
	if c.wPos == len(c.buf) {
		if c.rPos > 0 {
			copy(c.buf, c.buf[c.rPos:c.wPos])
			c.wPos -= c.rPos
			c.rPos = 0
		}
		if c.wPos == len(c.buf) {
			nb := make([]byte, len(c.buf)*2)
			copy(nb, c.buf[:c.wPos])
			c.buf = nb
		}
	}
	n, errno := rawNonBlockRead(c.fd, c.buf[c.wPos:])
	if errno == syscall.EAGAIN {
		return
	}
	if errno != 0 || n == 0 {
		srv.closeConn(c)
		return
	}
	c.wPos += n
	srv.processBuffered(epfd, c)
}

func (srv *Server) verifyAuthSIMD(hdrBlock []byte) bool {
	if srv.store.Token == "" {
		return true
	}
	idx := bytes.Index(hdrBlock, srv.store.AuthHeader)
	if idx < 15 {
		return false
	}
	endPos := idx + len(srv.store.AuthHeader)
	if endPos != len(hdrBlock) && hdrBlock[endPos] != '\r' {
		return false
	}
	p := idx - 1
	for p >= 0 && (hdrBlock[p] == ' ' || hdrBlock[p] == '\t') {
		p--
	}
	if p < 13 || hdrBlock[p] != ':' || !equalFoldASCII(hdrBlock[p-13:p], hdrAuthorization) {
		return false
	}
	return p-13 == 0 || hdrBlock[p-14] == '\n'
}

func (srv *Server) processBuffered(epfd int, c *connState) {
	for c.wPos > c.rPos {
		hdrRel := bytes.Index(c.buf[c.rPos:c.wPos], hdrDelimCRLFCRLF)
		if hdrRel < 0 {
			if c.rPos > 0 {
				copy(c.buf, c.buf[c.rPos:c.wPos])
				c.wPos -= c.rPos
				c.rPos = 0
			}
			return
		}
		hdrEnd := c.rPos + hdrRel
		reqBytes := c.buf[c.rPos:hdrEnd]
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
			srv.closeConn(c)
			return
		}
		method := reqLine[:sp1]
		restLine := reqLine[sp1+1:]
		sp2 := bytes.IndexByte(restLine, ' ')
		if sp2 <= 0 {
			srv.closeConn(c)
			return
		}
		target := restLine[:sp2]

		// ULTRA-HOT SIMD GET FAST PATHS (0 header loop, 0 alloc, 0 lock!)
		if len(method) == 3 && method[0] == 'G' && method[1] == 'E' && method[2] == 'T' {
			// Fast Path A: GET /api/v3/repos/{owner}/{repo}/issues/{num}
			if len(target) > 22 && bytes.HasPrefix(target, prefixReposAPI) && bytes.IndexByte(target, '?') < 0 {
				rest := target[14:]
				if s1 := bytes.IndexByte(rest, '/'); s1 > 0 {
					rest2 := rest[s1+1:]
					if s2 := bytes.IndexByte(rest2, '/'); s2 > 0 {
						tail := rest2[s2:]
						if len(tail) > 8 && bytes.HasPrefix(tail, prefixIssuesSlash) && bytes.IndexByte(tail[8:], '/') < 0 {
							if num, ok := parsePositiveIntBytes(tail[8:]); ok {
								if srv.verifyAuthSIMD(hdrBlock) && bytes.Index(hdrBlock, hdrClose) < 0 && bytes.Index(hdrBlock, hdrCloseTitle) < 0 {
									r := c.lookupRepo(srv, rest[:s1], rest2[:s2])
									resp := srv.FastGetIssueHTTP(r, num)
									c.rPos = bodyStart
									if c.rPos == c.wPos {
										c.rPos = 0
										c.wPos = 0
									}
									if !srv.sendResp(epfd, c, resp, false) {
										return
									}
									continue
								}
							}
						}
					}
				}
			}

			// Fast Path B1: GET /{owner}/{repo}.git/info/refs?service=git-upload-pack (v2)
			if len(target) > len(suffixInfoRefsUpload)+2 && target[0] == '/' && bytes.HasSuffix(target, suffixInfoRefsUpload) {
				if srv.verifyAuthSIMD(hdrBlock) && bytes.Index(hdrBlock, hdrClose) < 0 && bytes.Index(hdrBlock, hdrCloseTitle) < 0 {
					if bytes.Index(hdrBlock, hdrGitProtoV2Title) >= 0 || bytes.Index(hdrBlock, hdrGitProtoV2Lower) >= 0 {
						prefix := target[1 : len(target)-len(suffixInfoRefsUpload)]
						if slash := bytes.IndexByte(prefix, '/'); slash > 0 {
							if c.lookupRepo(srv, prefix[:slash], prefix[slash+1:]) != nil {
								c.rPos = bodyStart
								if c.rPos == c.wPos {
									c.rPos = 0
									c.wPos = 0
								}
								if !srv.sendResp(epfd, c, staticUploadPackV2AdvHTTP, false) {
									return
								}
								continue
							}
						}
					}
				}
			}

			// Fast Path B2: GET /{owner}/{repo}.git/info/refs?service=git-receive-pack
			if len(target) > len(suffixInfoRefsRecv)+2 && target[0] == '/' && bytes.HasSuffix(target, suffixInfoRefsRecv) {
				if srv.verifyAuthSIMD(hdrBlock) && bytes.Index(hdrBlock, hdrClose) < 0 && bytes.Index(hdrBlock, hdrCloseTitle) < 0 {
					prefix := target[1 : len(target)-len(suffixInfoRefsRecv)]
					if slash := bytes.IndexByte(prefix, '/'); slash > 0 {
						if r := c.lookupRepo(srv, prefix[:slash], prefix[slash+1:]); r != nil {
							if p := r.recvRefsCache.Load(); p != nil {
								c.rPos = bodyStart
								if c.rPos == c.wPos {
									c.rPos = 0
									c.wPos = 0
								}
								if !srv.sendResp(epfd, c, *p, false) {
									return
								}
								continue
							}
						}
					}
				}
			}
		}

		// General header loop (zero allocation)
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

		// Ensure complete body is buffered before dispatching (never blocks!)
		var body []byte
		nextRPos := bodyStart
		if chunked {
			decoded, consumed, ok, bad := parseChunkedComplete(c.buf[bodyStart:c.wPos])
			if bad {
				srv.closeConn(c)
				return
			}
			if !ok {
				if c.rPos > 0 {
					copy(c.buf, c.buf[c.rPos:c.wPos])
					c.wPos -= c.rPos
					c.rPos = 0
				}
				if srv.drainMoreInto(c, len(c.buf)) {
					continue
				}
				return
			}
			body = decoded
			nextRPos = bodyStart + consumed
		} else if contentLen > 0 {
			if c.wPos-bodyStart < contentLen {
				headerLen := bodyStart - c.rPos
				if c.rPos > 0 {
					copy(c.buf, c.buf[c.rPos:c.wPos])
					c.wPos -= c.rPos
					c.rPos = 0
				}
				needTotal := headerLen + contentLen
				if needTotal > len(c.buf) {
					newCap := len(c.buf) * 2
					for newCap < needTotal {
						newCap *= 2
					}
					nb := make([]byte, newCap)
					copy(nb, c.buf[:c.wPos])
					c.buf = nb
				}
				if srv.drainUntil(c, needTotal) {
					continue
				}
				return
			}
			body = c.buf[bodyStart : bodyStart+contentLen]
			nextRPos = bodyStart + contentLen
		}

		resp := srv.dispatchRequest(c, method, target, authHdr, hostHdr, gitProto, body, srv.scratch)
		c.rPos = nextRPos
		if c.rPos == c.wPos {
			c.rPos = 0
			c.wPos = 0
		}
		if !srv.sendResp(epfd, c, resp, closeConn) {
			return
		}
	}
}

func (srv *Server) drainUntil(c *connState, needTotal int) bool {
	for c.wPos < needTotal {
		n, errno := rawNonBlockRead(c.fd, c.buf[c.wPos:])
		if errno == syscall.EAGAIN {
			return false
		}
		if errno != 0 || n == 0 {
			srv.closeConn(c)
			return false
		}
		c.wPos += n
	}
	return true
}

func (srv *Server) drainMoreInto(c *connState, _ int) bool {
	readAny := false
	for {
		if c.wPos == len(c.buf) {
			nb := make([]byte, len(c.buf)*2)
			copy(nb, c.buf[:c.wPos])
			c.buf = nb
		}
		n, errno := rawNonBlockRead(c.fd, c.buf[c.wPos:])
		if errno == syscall.EAGAIN {
			return readAny
		}
		if errno != 0 || n == 0 {
			srv.closeConn(c)
			return false
		}
		c.wPos += n
		readAny = true
	}
}

func parseChunkedComplete(data []byte) ([]byte, int, bool, bool) {
	pos := 0
	var decoded []byte
	for {
		rel := bytes.Index(data[pos:], hdrDelimCRLF)
		if rel < 0 {
			return nil, 0, false, false
		}
		szLine := bytes.TrimSpace(data[pos : pos+rel])
		if semi := bytes.IndexByte(szLine, ';'); semi >= 0 {
			szLine = szLine[:semi]
		}
		chunkSz, err := strconv.ParseInt(string(szLine), 16, 64)
		if err != nil || chunkSz < 0 {
			return nil, 0, false, true
		}
		pos += rel + 2
		if chunkSz == 0 {
			if pos+2 > len(data) {
				return nil, 0, false, false
			}
			if data[pos] == '\r' && data[pos+1] == '\n' {
				return decoded, pos + 2, true, false
			}
			// Optional trailers ending with \r\n\r\n
			endTr := bytes.Index(data[pos:], hdrDelimCRLFCRLF)
			if endTr < 0 {
				return nil, 0, false, false
			}
			return decoded, pos + endTr + 4, true, false
		}
		need := pos + int(chunkSz) + 2
		if need > len(data) {
			return nil, 0, false, false
		}
		decoded = append(decoded, data[pos:pos+int(chunkSz)]...)
		pos = need
	}
}

func (srv *Server) dispatchRequest(
	c *connState,
	method, target, authHdr, hostHdr, gitProto, body, scratch []byte,
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
							return srv.FastGetIssueHTTP(c.lookupRepo(srv, owner, repoName), num)
						}
					}
				}
				// Fast POST /issues
				if len(method) == 4 && method[0] == 'P' && method[1] == 'O' && bytes.Equal(tail, pathIssuesExact) {
					return srv.FastCreateIssueHTTP(c.lookupRepo(srv, owner, repoName), body, scratch)
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
					return srv.handleGitInfoRefs(c.lookupRepo(srv, owner, repoName), query, gitProto)
				}
				if len(method) == 4 && method[0] == 'P' && bytes.Equal(gitSub, gitUploadPack) {
					return srv.handleGitUploadPack(c.lookupRepo(srv, owner, repoName), gitProto, body)
				}
				if len(method) == 4 && method[0] == 'P' && bytes.Equal(gitSub, gitReceivePack) {
					return srv.handleGitReceivePack(c.lookupRepo(srv, owner, repoName), body)
				}
			}
		}
	}

	return respNotFoundJSON
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
