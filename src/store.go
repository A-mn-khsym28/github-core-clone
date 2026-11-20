package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	ObjCommit   byte = 1
	ObjTree     byte = 2
	ObjBlob     byte = 3
	ObjTag      byte = 4
	ObjOfsDelta byte = 6
	ObjRefDelta byte = 7

	ZeroHex = "0000000000000000000000000000000000000000"
)

var ZeroOID [20]byte

type GitObject struct {
	Type      byte
	OID       [20]byte
	Hex       string
	Data      []byte
	Zlib      []byte // Original compressed zlib stream for zero-deflate pack writing
	TreeOID   [20]byte
	Parents   [][20]byte
	parentBuf [1][20]byte // Inline backing array for single-parent commits (0 alloc!)
	TagObj    [20]byte
}

type Label struct {
	Name  string
	Color string
}

type Comment struct {
	ID        int
	NodeID    string
	Body      string
	Author    string
	CreatedAt string
}

type Issue struct {
	ID            int
	NodeID        string
	Number        int
	Title         string
	Body          string
	State         string // "open" or "closed"
	Labels        []Label
	Comments      []*Comment
	CreatedSeq    int
	CreatedAt     string
	UpdatedAt     string
	cachedGetHTTP atomic.Pointer[[]byte]
}

type PullRequest struct {
	ID             int
	NodeID         string
	Number         int
	Title          string
	Body           string
	State          string // "open" or "closed"
	Merged         bool
	MergedAt       string
	MergeCommitSHA string
	HeadRef        string
	HeadSHA        string
	BaseRef        string
	BaseSHA        string
	CreatedSeq     int
	CreatedAt      string
	UpdatedAt      string
}

type ShallowFetchCache struct {
	WantOID  [20]byte
	Depth    int
	HTTPResp []byte
}

type RawReqRespCache struct {
	ReqBody  []byte
	HTTPResp []byte
}

type Repo struct {
	mu            sync.RWMutex
	deleted       atomic.Bool
	ID            int
	NodeID        string
	Owner         string
	Name          string
	FullName      string
	Private       bool
	Description   string
	DefaultBranch string
	CreatedSeq    int

	// Git store
	Objects      map[[20]byte]*GitObject
	hasPending   atomic.Bool
	pendingPacks [][]byte // Deferred raw pack bodies (without 20B trailer) materialized lazily on object reads
	packArena    []byte   // Reusable slab arena for zero-alloc push pack copies & commit bytes
	objArena     []GitObject
	Refs         map[string][20]byte
	RefGen       uint64
	CommitSeq    int

	// Atomic hot-path HTTP response caches (complete HTTP/1.1 bytes, 100% lock-free reads!)
	recvRefsCache     atomic.Pointer[[]byte]
	recvMainHTTP      [2][]byte // Ping-pong reusable single-ref HTTP/1.1 buffers updated in-place
	recvMainOIDOfs    int
	recvMainSlot      int
	lsRefsCache       atomic.Pointer[[]byte]
	lsRefsReqCache    atomic.Pointer[RawReqRespCache]
	fetchReqCache     atomic.Pointer[RawReqRespCache]
	shallowFetchCache atomic.Pointer[ShallowFetchCache]

	// Issues, labels, PRs
	Labels          map[string]Label
	Issues          []*Issue                 // 0-indexed, issue number = index+1
	issuesSnap      atomic.Pointer[[]*Issue] // Lock-free snapshot for GET /issues/{n}
	IssuesByNum     map[int]*Issue
	NextIssueNumber int
	Pulls           []*PullRequest
	PullsByNum      map[int]*PullRequest
	NextPullNumber  int
}

type Store struct {
	mu               sync.RWMutex
	ViewerLogin      string
	ViewerLoginBytes []byte
	ViewerID         int
	ViewerName       string
	ViewerEmail      string
	Token            string
	AuthHeader       []byte // "Bearer <token>"
	AuthHeaderCRLF   []byte // "Bearer <token>\r\n" for single-pass SIMD auth check
	ReposByName      map[string]*Repo
	reposSnap        atomic.Pointer[map[string]*Repo] // Lock-free COW snapshot!
	ReposByID        map[int]*Repo
	RepoList         []*Repo
	NextRepoID       int
	NextIssueID      atomic.Int64
	NextPullID       atomic.Int64
	NextCommentID    atomic.Int64

	// Reverse lookup for GraphQL node(id:) and mutations
	NodeRepos  map[string]*Repo
	NodeIssues map[string]struct {
		Repo  *Repo
		Issue *Issue
	}
	NodePulls map[string]struct {
		Repo *Repo
		Pull *PullRequest
	}
}

func NewStore(viewerLogin, token string) *Store {
	s := &Store{
		ViewerLogin:      viewerLogin,
		ViewerLoginBytes: []byte(viewerLogin),
		ViewerID:         1000,
		ViewerName:       "ada iversen",
		ViewerEmail:      viewerLogin + "@example.invalid",
		Token:            token,
		AuthHeader:       []byte("Bearer " + token),
		AuthHeaderCRLF:   []byte("Bearer " + token + "\r\n"),
		ReposByName:      make(map[string]*Repo, 64),
		ReposByID:        make(map[int]*Repo, 64),
		RepoList:         make([]*Repo, 0, 64),
		NodeRepos:        make(map[string]*Repo, 64),
		NodeIssues: make(map[string]struct {
			Repo  *Repo
			Issue *Issue
		}, 128),
		NodePulls: make(map[string]struct {
			Repo *Repo
			Pull *PullRequest
		}, 64),
	}
	emptyMap := make(map[string]*Repo)
	s.reposSnap.Store(&emptyMap)
	return s
}

func (s *Store) publishReposSnapLocked() {
	cp := make(map[string]*Repo, len(s.ReposByName))
	for k, v := range s.ReposByName {
		cp[k] = v
	}
	s.reposSnap.Store(&cp)
}

func encodeNodeID(kind string, parts ...int) string {
	var b strings.Builder
	b.WriteString(kind)
	for _, p := range parts {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(p))
	}
	return base64.StdEncoding.EncodeToString([]byte(b.String()))
}

func (s *Store) CreateRepo(name, description string, private bool, defaultBranch string) (*Repo, bool) {
	if defaultBranch == "" {
		defaultBranch = "main"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.ReposByName[name]; ok {
		return existing, false
	}
	s.NextRepoID++
	id := s.NextRepoID
	nodeID := encodeNodeID("Repository", id)
	r := &Repo{
		ID:            id,
		NodeID:        nodeID,
		Owner:         s.ViewerLogin,
		Name:          name,
		FullName:      s.ViewerLogin + "/" + name,
		Private:       private,
		Description:   description,
		DefaultBranch: defaultBranch,
		CreatedSeq:    id,
		Objects:       make(map[[20]byte]*GitObject, 256),
		Refs:          make(map[string][20]byte, 8),
		Labels:        make(map[string]Label, 8),
		Issues:        make([]*Issue, 0, 256),
		IssuesByNum:   make(map[int]*Issue, 64),
		Pulls:         make([]*PullRequest, 0, 16),
		PullsByNum:    make(map[int]*PullRequest, 16),
	}
	r.rebuildGitCachesLocked()
	s.ReposByName[name] = r
	s.ReposByID[id] = r
	s.RepoList = append(s.RepoList, r)
	s.NodeRepos[nodeID] = r
	s.publishReposSnapLocked()
	return r, true
}

func (s *Store) GetRepo(owner, name string) *Repo {
	if owner != s.ViewerLogin {
		return nil
	}
	m := s.reposSnap.Load()
	r := (*m)[name]
	if r != nil {
		r.ensureMaterialized()
	}
	return r
}

func (s *Store) GetRepoBytes(owner, name []byte) *Repo {
	if !bytes.Equal(owner, s.ViewerLoginBytes) {
		return nil
	}
	m := s.reposSnap.Load()
	return (*m)[string(name)]
}

func (s *Store) DeleteRepo(owner, name string) bool {
	if owner != s.ViewerLogin {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.ReposByName[name]
	if !ok {
		return false
	}
	r.deleted.Store(true)
	delete(s.ReposByName, name)
	delete(s.ReposByID, r.ID)
	delete(s.NodeRepos, r.NodeID)
	for i, item := range s.RepoList {
		if item == r {
			s.RepoList = append(s.RepoList[:i], s.RepoList[i+1:]...)
			break
		}
	}
	s.publishReposSnapLocked()
	return true
}

func (s *Store) NextIssueGlobalID() int {
	return int(s.NextIssueID.Add(1))
}

func (s *Store) NextCommentGlobalID() int {
	return int(s.NextCommentID.Add(1))
}

func (s *Store) NextPullGlobalID() int {
	return int(s.NextPullID.Add(1))
}

// ResolveIssueByNodeID decodes base64("Issue:<repoID>:<num>") without needing any global map write during POST /issues.
func (s *Store) ResolveIssueByNodeID(nodeID string) (*Repo, *Issue) {
	raw, err := base64.StdEncoding.DecodeString(nodeID)
	if err != nil {
		return nil, nil
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 3 || parts[0] != "Issue" {
		return nil, nil
	}
	repoID, err1 := strconv.Atoi(parts[1])
	num, err2 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil {
		return nil, nil
	}
	s.mu.RLock()
	r := s.ReposByID[repoID]
	s.mu.RUnlock()
	if r == nil {
		return nil, nil
	}
	r.mu.RLock()
	iss := r.IssuesByNum[num]
	r.mu.RUnlock()
	return r, iss
}

func (s *Store) RegisterIssueNode(r *Repo, iss *Issue) {
	s.mu.Lock()
	s.NodeIssues[iss.NodeID] = struct {
		Repo  *Repo
		Issue *Issue
	}{Repo: r, Issue: iss}
	s.mu.Unlock()
}

func (s *Store) RegisterPullNode(r *Repo, pr *PullRequest) {
	s.mu.Lock()
	s.NodePulls[pr.NodeID] = struct {
		Repo *Repo
		Pull *PullRequest
	}{Repo: r, Pull: pr}
	s.mu.Unlock()
}

// ---------- Git Object Helpers ----------

func objTypeName(t byte) string {
	switch t {
	case ObjCommit:
		return "commit"
	case ObjTree:
		return "tree"
	case ObjBlob:
		return "blob"
	case ObjTag:
		return "tag"
	default:
		return ""
	}
}

func hashGitObject(objType byte, data []byte) [20]byte {
	h := sha1.New()
	var hdr [32]byte
	b := hdr[:0]
	b = append(b, objTypeName(objType)...)
	b = append(b, ' ')
	b = strconv.AppendInt(b, int64(len(data)), 10)
	b = append(b, 0)
	_, _ = h.Write(b)
	_, _ = h.Write(data)
	var oid [20]byte
	h.Sum(oid[:0])
	return oid
}

func parseOIDHex(s string) ([20]byte, bool) {
	var oid [20]byte
	if len(s) != 40 {
		return oid, false
	}
	_, err := hex.Decode(oid[:], []byte(s))
	return oid, err == nil
}

func parseOIDHexBytes(b []byte) ([20]byte, bool) {
	var oid [20]byte
	if len(b) != 40 {
		return oid, false
	}
	_, err := hex.Decode(oid[:], b)
	return oid, err == nil
}

func oidToHex(oid [20]byte) string {
	return hex.EncodeToString(oid[:])
}

func newGitObject(objType byte, data, zlibBytes []byte) *GitObject {
	oid := hashGitObject(objType, data)
	obj := &GitObject{
		Type: objType,
		OID:  oid,
		Hex:  hex.EncodeToString(oid[:]),
		Data: data,
		Zlib: zlibBytes,
	}
	if objType == ObjCommit {
		parseCommitMeta(obj)
	} else if objType == ObjTag {
		parseTagMeta(obj)
	}
	return obj
}

func parseCommitMeta(obj *GitObject) {
	data := obj.Data
	for len(data) > 0 {
		nl := bytes.IndexByte(data, '\n')
		var line []byte
		if nl < 0 {
			line = data
			data = nil
		} else {
			line = data[:nl]
			data = data[nl+1:]
		}
		if len(line) == 0 {
			break
		}
		if bytes.HasPrefix(line, []byte("tree ")) && len(line) >= 45 {
			if oid, ok := parseOIDHexBytes(line[5:45]); ok {
				obj.TreeOID = oid
			}
		} else if bytes.HasPrefix(line, []byte("parent ")) && len(line) >= 47 {
			if oid, ok := parseOIDHexBytes(line[7:47]); ok {
				if len(obj.Parents) == 0 {
					obj.parentBuf[0] = oid
					obj.Parents = obj.parentBuf[:1]
				} else {
					obj.Parents = append(obj.Parents, oid)
				}
			}
		}
	}
}

func parseTagMeta(obj *GitObject) {
	data := obj.Data
	for len(data) > 0 {
		nl := bytes.IndexByte(data, '\n')
		var line []byte
		if nl < 0 {
			line = data
			data = nil
		} else {
			line = data[:nl]
			data = data[nl+1:]
		}
		if len(line) == 0 {
			break
		}
		if bytes.HasPrefix(line, []byte("object ")) && len(line) >= 47 {
			if oid, ok := parseOIDHexBytes(line[7:47]); ok {
				obj.TagObj = oid
			}
			break
		}
	}
}

func commitMessage(data []byte) string {
	idx := bytes.Index(data, []byte("\n\n"))
	if idx < 0 {
		return ""
	}
	return strings.TrimSuffix(string(data[idx+2:]), "\n")
}

func (r *Repo) PutObjectLocked(objType byte, data, zlibBytes []byte) *GitObject {
	oid := hashGitObject(objType, data)
	if existing, ok := r.Objects[oid]; ok {
		if existing.Zlib == nil && zlibBytes != nil {
			existing.Zlib = zlibBytes
		}
		return existing
	}
	obj := &GitObject{
		Type: objType,
		OID:  oid,
		Hex:  hex.EncodeToString(oid[:]),
		Data: data,
		Zlib: zlibBytes,
	}
	if objType == ObjCommit {
		parseCommitMeta(obj)
	} else if objType == ObjTag {
		parseTagMeta(obj)
	}
	r.Objects[oid] = obj
	return obj
}

func (r *Repo) PutPrecomputedObjectLocked(obj *GitObject) {
	if existing, ok := r.Objects[obj.OID]; ok {
		if existing.Zlib == nil && obj.Zlib != nil {
			existing.Zlib = obj.Zlib
		}
		return
	}
	r.Objects[obj.OID] = obj
}

// IsAncestorLocked reports whether ancestorOID is reachable from descendantOID.
func (r *Repo) IsAncestorLocked(ancestorOID, descendantOID [20]byte) bool {
	if ancestorOID == descendantOID {
		return true
	}
	// Fast O(1) check for single-commit fast-forward!
	if obj := r.Objects[descendantOID]; obj != nil && obj.Type == ObjCommit {
		for _, p := range obj.Parents {
			if p == ancestorOID {
				return true
			}
		}
	}
	visited := make(map[[20]byte]struct{}, 32)
	queue := [][20]byte{descendantOID}
	visited[descendantOID] = struct{}{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		obj := r.Objects[cur]
		if obj == nil || obj.Type != ObjCommit {
			continue
		}
		for _, p := range obj.Parents {
			if p == ancestorOID {
				return true
			}
			if _, seen := visited[p]; !seen {
				visited[p] = struct{}{}
				queue = append(queue, p)
			}
		}
	}
	return false
}

// ---------- Tree Operations (for REST Contents, PR Files, and 3-Way Squash Merge) ----------

type TreeEntry struct {
	Mode string
	Name string
	OID  [20]byte
}

func parseTreeEntries(data []byte) []TreeEntry {
	var out []TreeEntry
	pos := 0
	for pos < len(data) {
		sp := bytes.IndexByte(data[pos:], ' ')
		if sp < 0 {
			break
		}
		mode := string(data[pos : pos+sp])
		pos += sp + 1
		nul := bytes.IndexByte(data[pos:], 0)
		if nul < 0 || pos+nul+1+20 > len(data) {
			break
		}
		name := string(data[pos : pos+nul])
		pos += nul + 1
		var oid [20]byte
		copy(oid[:], data[pos:pos+20])
		pos += 20
		out = append(out, TreeEntry{Mode: mode, Name: name, OID: oid})
	}
	return out
}

func gitTreeSortKey(e TreeEntry) string {
	if e.Mode == "40000" || e.Mode == "040000" {
		return e.Name + "/"
	}
	return e.Name
}

func encodeTree(entries []TreeEntry) []byte {
	sorted := make([]TreeEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return gitTreeSortKey(sorted[i]) < gitTreeSortKey(sorted[j])
	})
	var buf bytes.Buffer
	for _, e := range sorted {
		mode := e.Mode
		if mode == "040000" {
			mode = "40000"
		}
		buf.WriteString(mode)
		buf.WriteByte(' ')
		buf.WriteString(e.Name)
		buf.WriteByte(0)
		buf.Write(e.OID[:])
	}
	return buf.Bytes()
}

// FlattenTreeLocked maps repo-relative file path -> blob OID.
func (r *Repo) FlattenTreeLocked(treeOID [20]byte) map[string][20]byte {
	files := make(map[string][20]byte)
	var walk func(oid [20]byte, prefix string)
	walk = func(oid [20]byte, prefix string) {
		obj := r.Objects[oid]
		if obj == nil || obj.Type != ObjTree {
			return
		}
		for _, e := range parseTreeEntries(obj.Data) {
			p := e.Name
			if prefix != "" {
				p = prefix + "/" + e.Name
			}
			if e.Mode == "40000" || e.Mode == "040000" {
				walk(e.OID, p)
			} else {
				files[p] = e.OID
			}
		}
	}
	if treeOID != ZeroOID {
		walk(treeOID, "")
	}
	return files
}

// BuildTreeFromFilesLocked builds nested git tree objects from path -> blob OID map.
func (r *Repo) BuildTreeFromFilesLocked(files map[string][20]byte) [20]byte {
	type dirNode struct {
		files map[string][20]byte
		dirs  map[string]*dirNode
	}
	newNode := func() *dirNode {
		return &dirNode{
			files: make(map[string][20]byte),
			dirs:  make(map[string]*dirNode),
		}
	}
	root := newNode()
	for p, oid := range files {
		p = strings.Trim(p, "/")
		if p == "" {
			continue
		}
		parts := strings.Split(p, "/")
		cur := root
		for i := 0; i < len(parts)-1; i++ {
			d, ok := cur.dirs[parts[i]]
			if !ok {
				d = newNode()
				cur.dirs[parts[i]] = d
			}
			cur = d
		}
		cur.files[parts[len(parts)-1]] = oid
	}
	var build func(n *dirNode) [20]byte
	build = func(n *dirNode) [20]byte {
		entries := make([]TreeEntry, 0, len(n.files)+len(n.dirs))
		for name, oid := range n.files {
			entries = append(entries, TreeEntry{Mode: "100644", Name: name, OID: oid})
		}
		for name, sub := range n.dirs {
			subOID := build(sub)
			entries = append(entries, TreeEntry{Mode: "40000", Name: name, OID: subOID})
		}
		raw := encodeTree(entries)
		obj := r.PutObjectLocked(ObjTree, raw, nil)
		return obj.OID
	}
	return build(root)
}

func (r *Repo) ResolveTreeEntryLocked(treeOID [20]byte, path string) (*TreeEntry, [20]byte, bool) {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil, treeOID, treeOID != ZeroOID
	}
	parts := strings.Split(path, "/")
	curTree := treeOID
	for i, part := range parts {
		obj := r.Objects[curTree]
		if obj == nil || obj.Type != ObjTree {
			return nil, ZeroOID, false
		}
		var found *TreeEntry
		for _, e := range parseTreeEntries(obj.Data) {
			if e.Name == part {
				ec := e
				found = &ec
				break
			}
		}
		if found == nil {
			return nil, ZeroOID, false
		}
		if i == len(parts)-1 {
			return found, found.OID, true
		}
		if found.Mode != "40000" && found.Mode != "040000" {
			return nil, ZeroOID, false
		}
		curTree = found.OID
	}
	return nil, ZeroOID, false
}

func (r *Repo) CreateCommitLocked(treeOID [20]byte, parents [][20]byte, message, authorName, authorEmail string) *GitObject {
	r.CommitSeq++
	ts := 1735689600 + r.CommitSeq
	var buf bytes.Buffer
	buf.WriteString("tree ")
	buf.WriteString(oidToHex(treeOID))
	buf.WriteByte('\n')
	for _, p := range parents {
		buf.WriteString("parent ")
		buf.WriteString(oidToHex(p))
		buf.WriteByte('\n')
	}
	idLine := fmt.Sprintf("%s <%s> %d +0000", authorName, authorEmail, ts)
	buf.WriteString("author ")
	buf.WriteString(idLine)
	buf.WriteString("\ncommitter ")
	buf.WriteString(idLine)
	buf.WriteString("\n\n")
	buf.WriteString(message)
	if !strings.HasSuffix(message, "\n") {
		buf.WriteByte('\n')
	}
	return r.PutObjectLocked(ObjCommit, buf.Bytes(), nil)
}

func (r *Repo) MergeBaseLocked(a, b [20]byte) [20]byte {
	if a == b {
		return a
	}
	ancA := make(map[[20]byte]struct{}, 32)
	q := [][20]byte{a}
	ancA[a] = struct{}{}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		obj := r.Objects[cur]
		if obj == nil || obj.Type != ObjCommit {
			continue
		}
		for _, p := range obj.Parents {
			if _, ok := ancA[p]; !ok {
				ancA[p] = struct{}{}
				q = append(q, p)
			}
		}
	}
	seenB := make(map[[20]byte]struct{}, 32)
	q = [][20]byte{b}
	seenB[b] = struct{}{}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if _, ok := ancA[cur]; ok {
			return cur
		}
		obj := r.Objects[cur]
		if obj == nil || obj.Type != ObjCommit {
			continue
		}
		for _, p := range obj.Parents {
			if _, ok := seenB[p]; !ok {
				seenB[p] = struct{}{}
				q = append(q, p)
			}
		}
	}
	return ZeroOID
}

func (r *Repo) TreeForCommitLocked(commitOID [20]byte) [20]byte {
	if commitOID == ZeroOID {
		return ZeroOID
	}
	obj := r.Objects[commitOID]
	if obj == nil || obj.Type != ObjCommit {
		return ZeroOID
	}
	return obj.TreeOID
}

type DiffFile struct {
	Filename  string `json:"filename"`
	Status    string `json:"status"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Changes   int    `json:"changes"`
}

func countLines(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	n := bytes.Count(b, []byte{'\n'})
	if b[len(b)-1] != '\n' {
		n++
	}
	return n
}

func (r *Repo) DiffCommitsLocked(baseOID, headOID [20]byte) []DiffFile {
	baseFiles := r.FlattenTreeLocked(r.TreeForCommitLocked(baseOID))
	headFiles := r.FlattenTreeLocked(r.TreeForCommitLocked(headOID))
	allPaths := make(map[string]struct{}, len(baseFiles)+len(headFiles))
	for p := range baseFiles {
		allPaths[p] = struct{}{}
	}
	for p := range headFiles {
		allPaths[p] = struct{}{}
	}
	paths := make([]string, 0, len(allPaths))
	for p := range allPaths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var diffs []DiffFile
	for _, p := range paths {
		bOID, inBase := baseFiles[p]
		hOID, inHead := headFiles[p]
		if inBase && inHead && bOID == hOID {
			continue
		}
		if !inBase && inHead {
			lines := 1
			if obj := r.Objects[hOID]; obj != nil {
				lines = countLines(obj.Data)
				if lines == 0 {
					lines = 1
				}
			}
			diffs = append(diffs, DiffFile{Filename: p, Status: "added", Additions: lines, Deletions: 0, Changes: lines})
		} else if inBase && !inHead {
			lines := 1
			if obj := r.Objects[bOID]; obj != nil {
				lines = countLines(obj.Data)
				if lines == 0 {
					lines = 1
				}
			}
			diffs = append(diffs, DiffFile{Filename: p, Status: "removed", Additions: 0, Deletions: lines, Changes: lines})
		} else {
			bLines, hLines := 0, 0
			if obj := r.Objects[bOID]; obj != nil {
				bLines = countLines(obj.Data)
			}
			if obj := r.Objects[hOID]; obj != nil {
				hLines = countLines(obj.Data)
			}
			add := hLines
			if add < 1 {
				add = 1
			}
			del := bLines
			diffs = append(diffs, DiffFile{Filename: p, Status: "modified", Additions: add, Deletions: del, Changes: add + del})
		}
	}
	return diffs
}

// ThreeWayMergeLocked returns (mergedFiles, conflict).
func (r *Repo) ThreeWayMergeLocked(baseOID, headOID [20]byte) (map[string][20]byte, bool) {
	lca := r.MergeBaseLocked(baseOID, headOID)
	ancFiles := r.FlattenTreeLocked(r.TreeForCommitLocked(lca))
	baseFiles := r.FlattenTreeLocked(r.TreeForCommitLocked(baseOID))
	headFiles := r.FlattenTreeLocked(r.TreeForCommitLocked(headOID))

	allPaths := make(map[string]struct{}, len(ancFiles)+len(baseFiles)+len(headFiles))
	for p := range ancFiles {
		allPaths[p] = struct{}{}
	}
	for p := range baseFiles {
		allPaths[p] = struct{}{}
	}
	for p := range headFiles {
		allPaths[p] = struct{}{}
	}

	merged := make(map[string][20]byte, len(allPaths))
	for p := range allPaths {
		aOID, inA := ancFiles[p]
		bOID, inB := baseFiles[p]
		hOID, inH := headFiles[p]

		bChanged := inB != inA || (inB && bOID != aOID)
		hChanged := inH != inA || (inH && hOID != aOID)

		if !bChanged && !hChanged {
			if inA {
				merged[p] = aOID
			}
		} else if bChanged && !hChanged {
			if inB {
				merged[p] = bOID
			}
		} else if !bChanged && hChanged {
			if inH {
				merged[p] = hOID
			}
		} else {
			// Both changed
			if inB == inH && (!inB || bOID == hOID) {
				if inB {
					merged[p] = bOID
				}
			} else {
				return nil, true
			}
		}
	}
	return merged, false
}

// ResolveRefLocked resolves branch name, full ref, or 40-char sha.
func (r *Repo) ResolveRefLocked(ref string) ([20]byte, bool) {
	if ref == "" {
		if oid, ok := r.Refs["refs/heads/"+r.DefaultBranch]; ok {
			return oid, true
		}
		return ZeroOID, false
	}
	if oid, ok := r.Refs[ref]; ok {
		return oid, true
	}
	if oid, ok := r.Refs["refs/heads/"+ref]; ok {
		return oid, true
	}
	if oid, ok := r.Refs["refs/tags/"+ref]; ok {
		return oid, true
	}
	if oid, ok := parseOIDHex(ref); ok {
		if _, exists := r.Objects[oid]; exists {
			return oid, true
		}
	}
	return ZeroOID, false
}
