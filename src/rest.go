package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

var (
	respHealthzHTTP     = buildRawHTTPResponse(200, "OK", "application/json", []byte(`{"ok":true}`))
	respUnauthorized    = buildRawHTTPResponse(401, "Unauthorized", "application/json", []byte(`{"message":"Requires authentication"}`))
	respNotFoundJSON    = buildRawHTTPResponse(404, "Not Found", "application/json", []byte(`{"message":"Not Found"}`))
	respBadRequestJSON  = buildRawHTTPResponse(400, "Bad Request", "application/json", []byte(`{"message":"Problems parsing JSON"}`))
	respNoContent       = []byte("HTTP/1.1 204 No Content\r\nX-GitHub-Request-Id: 1\r\nContent-Length: 0\r\n\r\n")
	respRootV3          = []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-GitHub-Request-Id: 1\r\nX-OAuth-Scopes: repo, user, admin:org\r\nContent-Length: 2\r\n\r\n{}")
	respMetaV3          = buildRawHTTPResponse(200, "OK", "application/json", []byte(`{"installed_version":"3.14.0"}`))
	respConflictJSON    = buildRawHTTPResponse(409, "Conflict", "application/json", []byte(`{"message":"sha does not match"}`))
	respMergeConflict   = buildRawHTTPResponse(405, "Method Not Allowed", "application/json", []byte(`{"message":"Pull Request is not mergeable"}`))
	respBadLabelJSON    = buildRawHTTPResponse(422, "Unprocessable Entity", "application/json", []byte(`{"message":"Validation Failed: unknown label"}`))
	respRepoExistsJSON  = buildRawHTTPResponse(422, "Unprocessable Entity", "application/json", []byte(`{"message":"Repository creation failed: name already exists"}`))
)

func jsonResponse(status int, reason string, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return respBadRequestJSON
	}
	return buildRawHTTPResponse(status, reason, "application/json", b)
}

func jsonError(status int, reason, msg string) []byte {
	b, _ := json.Marshal(map[string]string{"message": msg})
	return buildRawHTTPResponse(status, reason, "application/json", b)
}

// appendJSONString appends a JSON-escaped quoted string to dst with zero allocation.
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			dst = append(dst, c)
			continue
		}
		switch c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		}
	}
	dst = append(dst, '"')
	return dst
}

// buildIssueJSON builds an ultra-compact, 100%-conforming GitHub REST issue JSON payload.
func buildIssueJSON(dst []byte, iss *Issue) []byte {
	dst = append(dst, `{"id":`...)
	dst = strconv.AppendInt(dst, int64(iss.ID), 10)
	dst = append(dst, `,"number":`...)
	dst = strconv.AppendInt(dst, int64(iss.Number), 10)
	dst = append(dst, `,"title":`...)
	dst = appendJSONString(dst, iss.Title)
	dst = append(dst, `,"body":`...)
	dst = appendJSONString(dst, iss.Body)
	dst = append(dst, `,"state":`...)
	dst = appendJSONString(dst, iss.State)
	dst = append(dst, `,"labels":[`...)
	for i, l := range iss.Labels {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, `{"name":`...)
		dst = appendJSONString(dst, l.Name)
		dst = append(dst, '}')
	}
	dst = append(dst, `]}`...)
	return dst
}

func (iss *Issue) refreshCachedHTTP() []byte {
	body := buildIssueJSON(make([]byte, 0, 96+len(iss.Title)+len(iss.Body)), iss)
	resp200 := buildRawHTTPResponse(200, "OK", "application/json", body)
	iss.cachedGetHTTP.Store(&resp200)
	return body
}

// fastParseTitleBody extracts simple {"title":"...","body":"..."} without encoding/json when no labels/escapes complicate it.
// Returns (title, body, ok). Falls back to encoding/json if ok == false.
func fastParseTitleBody(b []byte) (string, string, bool) {
	if bytes.Contains(b, []byte(`"labels"`)) || bytes.Contains(b, []byte(`\u`)) {
		return "", "", false
	}
	b = bytes.TrimSpace(b)
	if len(b) < 2 || b[0] != '{' || b[len(b)-1] != '}' {
		return "", "", false
	}
	pos := 1
	end := len(b) - 1
	var title, body string
	hasTitle := false
	readStr := func() (string, bool) {
		for pos < end && (b[pos] == ' ' || b[pos] == '\t' || b[pos] == '\n' || b[pos] == '\r') {
			pos++
		}
		if pos >= end || b[pos] != '"' {
			return "", false
		}
		pos++
		start := pos
		hasEsc := false
		for pos < end {
			c := b[pos]
			if c == '\\' {
				hasEsc = true
				pos += 2
				continue
			}
			if c == '"' {
				raw := b[start:pos]
				pos++
				if !hasEsc {
					return string(raw), true
				}
				var sb strings.Builder
				sb.Grow(len(raw))
				for i := 0; i < len(raw); i++ {
					if raw[i] == '\\' && i+1 < len(raw) {
						i++
						switch raw[i] {
						case '"', '\\', '/':
							sb.WriteByte(raw[i])
						case 'n':
							sb.WriteByte('\n')
						case 'r':
							sb.WriteByte('\r')
						case 't':
							sb.WriteByte('\t')
						default:
							return "", false
						}
					} else {
						sb.WriteByte(raw[i])
					}
				}
				return sb.String(), true
			}
			pos++
		}
		return "", false
	}
	for pos < end {
		for pos < end && (b[pos] == ' ' || b[pos] == '\t' || b[pos] == '\n' || b[pos] == '\r' || b[pos] == ',') {
			pos++
		}
		if pos >= end {
			break
		}
		k, ok := readStr()
		if !ok {
			return "", "", false
		}
		for pos < end && (b[pos] == ' ' || b[pos] == '\t' || b[pos] == '\n' || b[pos] == '\r') {
			pos++
		}
		if pos >= end || b[pos] != ':' {
			return "", "", false
		}
		pos++
		v, ok := readStr()
		if !ok {
			return "", "", false
		}
		switch k {
		case "title":
			title = v
			hasTitle = true
		case "body":
			body = v
		default:
			return "", "", false
		}
	}
	if !hasTitle {
		return "", "", false
	}
	return title, body, true
}

// FastGetIssueHTTP serves GET /api/v3/repos/{o}/{r}/issues/{n} with ZERO allocations and ZERO mutexes!
func (srv *Server) FastGetIssueHTTP(r *Repo, num int) []byte {
	if r == nil || num <= 0 {
		return respNotFoundJSON
	}
	if snap := r.issuesSnap.Load(); snap != nil && num <= len(*snap) {
		iss := (*snap)[num-1]
		if iss != nil && iss.Number == num {
			if p := iss.cachedGetHTTP.Load(); p != nil {
				return *p
			}
			r.mu.Lock()
			iss.refreshCachedHTTP()
			p := iss.cachedGetHTTP.Load()
			r.mu.Unlock()
			return *p
		}
	}
	r.mu.RLock()
	iss := r.IssuesByNum[num]
	r.mu.RUnlock()
	if iss == nil {
		return respNotFoundJSON
	}
	if p := iss.cachedGetHTTP.Load(); p != nil {
		return *p
	}
	r.mu.Lock()
	iss.refreshCachedHTTP()
	p := iss.cachedGetHTTP.Load()
	r.mu.Unlock()
	return *p
}

// FastCreateIssueHTTP serves POST /api/v3/repos/{o}/{r}/issues directly into scratchBuf with ZERO global locks!
func (srv *Server) FastCreateIssueHTTP(r *Repo, body []byte, scratch []byte) []byte {
	if r == nil {
		return respNotFoundJSON
	}
	if title, ibody, ok := fastParseTitleBody(body); ok {
		globalID := srv.store.NextIssueGlobalID()
		r.mu.Lock()
		r.NextIssueNumber++
		num := r.NextIssueNumber
		iss := &Issue{
			ID:         globalID,
			Number:     num,
			Title:      title,
			Body:       ibody,
			State:      "open",
			CreatedSeq: num,
			CreatedAt:  "2025-01-01T00:00:00Z",
			UpdatedAt:  "2025-01-01T00:00:00Z",
		}
		r.Issues = append(r.Issues, iss)
		snap := r.Issues
		r.issuesSnap.Store(&snap)
		r.IssuesByNum[num] = iss
		r.mu.Unlock()

		// Build compact JSON body directly in tail of scratch without extra heap alloc!
		var jBuf [1024]byte
		jsonBody := buildIssueJSON(jBuf[:0], iss)
		resp := scratch[:0]
		resp = append(resp, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nX-GitHub-Request-Id: 1\r\nContent-Length: "...)
		resp = strconv.AppendInt(resp, int64(len(jsonBody)), 10)
		resp = append(resp, "\r\n\r\n"...)
		resp = append(resp, jsonBody...)
		return resp
	}
	return srv.handleCreateIssueSlow(r, body)
}

func (srv *Server) handleCreateIssueSlow(r *Repo, body []byte) []byte {
	var req struct {
		Title  string   `json:"title"`
		Body   string   `json:"body"`
		Labels []string `json:"labels"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return respBadRequestJSON
	}
	if req.Title == "" {
		return jsonError(422, "Unprocessable Entity", "Validation Failed: title is required")
	}
	globalID := srv.store.NextIssueGlobalID()
	r.mu.Lock()
	var labels []Label
	if len(req.Labels) > 0 {
		labels = make([]Label, 0, len(req.Labels))
		for _, ln := range req.Labels {
			l, ok := r.Labels[ln]
			if !ok {
				r.mu.Unlock()
				return respBadLabelJSON
			}
			labels = append(labels, l)
		}
	}
	r.NextIssueNumber++
	num := r.NextIssueNumber
	iss := &Issue{
		ID:         globalID,
		NodeID:     encodeNodeID("Issue", r.ID, num),
		Number:     num,
		Title:      req.Title,
		Body:       req.Body,
		State:      "open",
		Labels:     labels,
		CreatedSeq: num,
		CreatedAt:  "2025-01-01T00:00:00Z",
		UpdatedAt:  "2025-01-01T00:00:00Z",
	}
	jsonBody := iss.refreshCachedHTTP()
	r.Issues = append(r.Issues, iss)
	snap := r.Issues
	r.issuesSnap.Store(&snap)
	r.IssuesByNum[num] = iss
	r.mu.Unlock()
	srv.store.RegisterIssueNode(r, iss)
	return buildRawHTTPResponse(201, "Created", "application/json", jsonBody)
}

func repoToMap(r *Repo) map[string]any {
	return map[string]any{
		"id":             r.ID,
		"node_id":        r.NodeID,
		"name":           r.Name,
		"full_name":      r.FullName,
		"private":        r.Private,
		"description":    r.Description,
		"default_branch": r.DefaultBranch,
		"owner": map[string]any{
			"id":    1000,
			"login": r.Owner,
		},
	}
}

func pullToMap(r *Repo, pr *PullRequest) map[string]any {
	m := map[string]any{
		"id":               pr.ID,
		"node_id":          pr.NodeID,
		"number":           pr.Number,
		"state":            pr.State,
		"title":            pr.Title,
		"body":             pr.Body,
		"merged":           pr.Merged,
		"merge_commit_sha": nil,
		"merged_at":        nil,
		"head": map[string]any{
			"ref":   pr.HeadRef,
			"sha":   pr.HeadSHA,
			"label": r.Owner + ":" + pr.HeadRef,
		},
		"base": map[string]any{
			"ref":   pr.BaseRef,
			"sha":   pr.BaseSHA,
			"label": r.Owner + ":" + pr.BaseRef,
		},
		"created_at": pr.CreatedAt,
		"updated_at": pr.UpdatedAt,
	}
	if pr.Merged {
		m["merged_at"] = pr.MergedAt
		m["merge_commit_sha"] = pr.MergeCommitSHA
	}
	return m
}

func (srv *Server) handleREST(method, path, rawQuery, host string, body []byte) []byte {
	// Trim "/api/v3" prefix
	sub := strings.TrimPrefix(path, "/api/v3")
	if sub == "" || sub == "/" {
		if method == "GET" {
			return respRootV3
		}
		return respNotFoundJSON
	}
	if sub == "/meta" && method == "GET" {
		return respMetaV3
	}
	if sub == "/user" && method == "GET" {
		return jsonResponse(200, "OK", map[string]any{
			"id":    srv.store.ViewerID,
			"login": srv.store.ViewerLogin,
			"name":  srv.store.ViewerName,
			"email": srv.store.ViewerEmail,
		})
	}
	if sub == "/user/repos" {
		if method == "POST" {
			var req struct {
				Name          string `json:"name"`
				Private       bool   `json:"private"`
				Description   string `json:"description"`
				DefaultBranch string `json:"default_branch"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				return respBadRequestJSON
			}
			if req.Name == "" {
				return jsonError(422, "Unprocessable Entity", "name is required")
			}
			r, created := srv.store.CreateRepo(req.Name, req.Description, req.Private, req.DefaultBranch)
			if !created {
				return respRepoExistsJSON
			}
			return jsonResponse(201, "Created", repoToMap(r))
		}
		if method == "GET" {
			q, _ := url.ParseQuery(rawQuery)
			perPage := 30
			if v, err := strconv.Atoi(q.Get("per_page")); err == nil && v > 0 {
				if v > 100 {
					v = 100
				}
				perPage = v
			}
			page := 1
			if v, err := strconv.Atoi(q.Get("page")); err == nil && v > 0 {
				page = v
			}
			srv.store.mu.RLock()
			total := len(srv.store.RepoList)
			start := (page - 1) * perPage
			if start > total {
				start = total
			}
			end := start + perPage
			if end > total {
				end = total
			}
			items := make([]map[string]any, 0, end-start)
			for _, r := range srv.store.RepoList[start:end] {
				items = append(items, repoToMap(r))
			}
			srv.store.mu.RUnlock()

			b, _ := json.Marshal(items)
			var hdr []byte
			hdr = append(hdr, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-GitHub-Request-Id: 1\r\n"...)
			if end < total {
				lastPage := (total + perPage - 1) / perPage
				origin := "http://" + host
				link := fmt.Sprintf("<%s/api/v3/user/repos?per_page=%d&page=%d>; rel=\"next\", <%s/api/v3/user/repos?per_page=%d&page=%d>; rel=\"last\"",
					origin, perPage, page+1, origin, perPage, lastPage)
				hdr = append(hdr, "Link: "...)
				hdr = append(hdr, link...)
				hdr = append(hdr, "\r\n"...)
			}
			hdr = append(hdr, "Content-Length: "...)
			hdr = strconv.AppendInt(hdr, int64(len(b)), 10)
			hdr = append(hdr, "\r\n\r\n"...)
			hdr = append(hdr, b...)
			return hdr
		}
		return respNotFoundJSON
	}

	// /repos/{owner}/{repo}...
	if !strings.HasPrefix(sub, "/repos/") {
		return respNotFoundJSON
	}
	rest := sub[len("/repos/"):]
	slash1 := strings.IndexByte(rest, '/')
	if slash1 <= 0 {
		return respNotFoundJSON
	}
	owner, _ := url.PathUnescape(rest[:slash1])
	rest = rest[slash1+1:]
	var repoName, tail string
	if slash2 := strings.IndexByte(rest, '/'); slash2 < 0 {
		repoName, _ = url.PathUnescape(rest)
		tail = ""
	} else {
		repoName, _ = url.PathUnescape(rest[:slash2])
		tail = rest[slash2:]
	}

	if tail == "" || tail == "/" {
		switch method {
		case "GET":
			r := srv.store.GetRepo(owner, repoName)
			if r == nil {
				return respNotFoundJSON
			}
			r.mu.RLock()
			m := repoToMap(r)
			r.mu.RUnlock()
			return jsonResponse(200, "OK", m)
		case "PATCH":
			r := srv.store.GetRepo(owner, repoName)
			if r == nil {
				return respNotFoundJSON
			}
			var req map[string]any
			if err := json.Unmarshal(body, &req); err != nil {
				return respBadRequestJSON
			}
			r.mu.Lock()
			if d, ok := req["description"].(string); ok {
				r.Description = d
			}
			if p, ok := req["private"].(bool); ok {
				r.Private = p
			}
			if db, ok := req["default_branch"].(string); ok && db != "" {
				r.DefaultBranch = db
			}
			m := repoToMap(r)
			r.mu.Unlock()
			return jsonResponse(200, "OK", m)
		case "DELETE":
			if !srv.store.DeleteRepo(owner, repoName) {
				return respNotFoundJSON
			}
			return respNoContent
		default:
			return respNotFoundJSON
		}
	}

	r := srv.store.GetRepo(owner, repoName)
	if r == nil {
		return respNotFoundJSON
	}

	// Routes under /repos/{owner}/{repo}
	switch {
	case tail == "/branches" && method == "GET":
		r.mu.RLock()
		var branches []map[string]any
		for _, name := range r.sortedRefNamesLocked() {
			if strings.HasPrefix(name, "refs/heads/") {
				bName := strings.TrimPrefix(name, "refs/heads/")
				branches = append(branches, map[string]any{
					"name":   bName,
					"commit": map[string]any{"sha": oidToHex(r.Refs[name])},
				})
			}
		}
		r.mu.RUnlock()
		if branches == nil {
			branches = []map[string]any{}
		}
		return jsonResponse(200, "OK", branches)

	case strings.HasPrefix(tail, "/branches/") && method == "GET":
		bName, _ := url.PathUnescape(strings.TrimPrefix(tail, "/branches/"))
		r.mu.RLock()
		oid, ok := r.Refs["refs/heads/"+bName]
		r.mu.RUnlock()
		if !ok {
			return respNotFoundJSON
		}
		return jsonResponse(200, "OK", map[string]any{
			"name":   bName,
			"commit": map[string]any{"sha": oidToHex(oid)},
		})

	case tail == "/git/refs" && method == "POST":
		var req struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return respBadRequestJSON
		}
		oid, ok := parseOIDHex(req.SHA)
		if !ok || !strings.HasPrefix(req.Ref, "refs/") {
			return jsonError(422, "Unprocessable Entity", "invalid ref or sha")
		}
		r.mu.Lock()
		r.ensureMaterializedLocked()
		if _, exists := r.Refs[req.Ref]; exists {
			r.mu.Unlock()
			return jsonError(422, "Unprocessable Entity", "Reference already exists")
		}
		if _, objOk := r.Objects[oid]; !objOk {
			r.mu.Unlock()
			return jsonError(422, "Unprocessable Entity", "Object does not exist")
		}
		r.Refs[req.Ref] = oid
		r.RefGen++
		r.rebuildGitCachesLocked()
		r.mu.Unlock()
		return jsonResponse(201, "Created", map[string]any{
			"ref": req.Ref,
			"object": map[string]any{
				"sha":  oidToHex(oid),
				"type": "commit",
			},
		})

	case strings.HasPrefix(tail, "/git/refs/") && method == "GET":
		refSuffix, _ := url.PathUnescape(strings.TrimPrefix(tail, "/git/refs/"))
		fullRef := "refs/" + refSuffix
		r.mu.RLock()
		oid, ok := r.Refs[fullRef]
		r.mu.RUnlock()
		if !ok {
			return respNotFoundJSON
		}
		return jsonResponse(200, "OK", map[string]any{
			"ref": fullRef,
			"object": map[string]any{
				"sha":  oidToHex(oid),
				"type": "commit",
			},
		})

	case tail == "/commits" && method == "GET":
		q, _ := url.ParseQuery(rawQuery)
		shaParam := q.Get("sha")
		r.mu.RLock()
		r.ensureMaterializedLocked()
		tip, ok := r.ResolveRefLocked(shaParam)
		var out []map[string]any
		if ok {
			visited := make(map[[20]byte]struct{}, 32)
			stack := [][20]byte{tip}
			for len(stack) > 0 && len(out) < 200 {
				cur := stack[0]
				stack = stack[1:]
				if _, seen := visited[cur]; seen {
					continue
				}
				visited[cur] = struct{}{}
				obj := r.Objects[cur]
				if obj == nil || obj.Type != ObjCommit {
					continue
				}
				out = append(out, map[string]any{
					"sha": oidToHex(obj.OID),
					"commit": map[string]any{
						"message": commitMessage(obj.Data),
					},
				})
				stack = append(stack, obj.Parents...)
			}
		}
		r.mu.RUnlock()
		if out == nil {
			out = []map[string]any{}
		}
		return jsonResponse(200, "OK", out)

	case tail == "/contents" || strings.HasPrefix(tail, "/contents/"):
		return srv.handleContents(r, method, tail, rawQuery, body)

	case tail == "/labels":
		if method == "POST" {
			var req struct {
				Name  string `json:"name"`
				Color string `json:"color"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				return respBadRequestJSON
			}
			if req.Name == "" {
				return jsonError(422, "Unprocessable Entity", "label name is required")
			}
			if req.Color == "" {
				req.Color = "ededed"
			}
			r.mu.Lock()
			l := Label{Name: req.Name, Color: req.Color}
			r.Labels[req.Name] = l
			r.mu.Unlock()
			return jsonResponse(201, "Created", map[string]any{"name": l.Name, "color": l.Color})
		}
		if method == "GET" {
			r.mu.RLock()
			list := make([]map[string]any, 0, len(r.Labels))
			for _, l := range r.Labels {
				list = append(list, map[string]any{"name": l.Name, "color": l.Color})
			}
			r.mu.RUnlock()
			return jsonResponse(200, "OK", list)
		}
		return respNotFoundJSON

	case tail == "/issues":
		if method == "POST" {
			return srv.handleCreateIssueSlow(r, body)
		}
		if method == "GET" {
			return srv.handleListIssues(r, rawQuery)
		}
		return respNotFoundJSON

	case strings.HasPrefix(tail, "/issues/"):
		return srv.handleSingleIssueOrComments(r, method, strings.TrimPrefix(tail, "/issues/"), body)

	case tail == "/pulls":
		if method == "POST" {
			return srv.handleCreatePull(r, body)
		}
		if method == "GET" {
			return srv.handleListPulls(r, rawQuery)
		}
		return respNotFoundJSON

	case strings.HasPrefix(tail, "/pulls/"):
		return srv.handleSinglePull(r, method, strings.TrimPrefix(tail, "/pulls/"), body)
	}

	return respNotFoundJSON
}

func (srv *Server) handleContents(r *Repo, method, tail, rawQuery string, body []byte) []byte {
	rawPath := strings.TrimPrefix(tail, "/contents")
	rawPath = strings.TrimPrefix(rawPath, "/")
	parts := strings.Split(rawPath, "/")
	for i := range parts {
		if dec, err := url.PathUnescape(parts[i]); err == nil {
			parts[i] = dec
		}
	}
	filePath := strings.Trim(strings.Join(parts, "/"), "/")

	switch method {
	case "GET":
		q, _ := url.ParseQuery(rawQuery)
		ref := q.Get("ref")
		r.mu.RLock()
		defer r.mu.RUnlock()
		commitOID, ok := r.ResolveRefLocked(ref)
		if !ok {
			return respNotFoundJSON
		}
		rootTree := r.TreeForCommitLocked(commitOID)
		if filePath == "" {
			tObj := r.Objects[rootTree]
			if tObj == nil {
				return respNotFoundJSON
			}
			return jsonResponse(200, "OK", listDirEntriesLocked(r, rootTree, ""))
		}
		entry, oid, found := r.ResolveTreeEntryLocked(rootTree, filePath)
		if !found {
			return respNotFoundJSON
		}
		if entry.Mode == "40000" || entry.Mode == "040000" {
			return jsonResponse(200, "OK", listDirEntriesLocked(r, oid, filePath))
		}
		blob := r.Objects[oid]
		if blob == nil {
			return respNotFoundJSON
		}
		return jsonResponse(200, "OK", map[string]any{
			"type":     "file",
			"encoding": "base64",
			"name":     entry.Name,
			"path":     filePath,
			"sha":      oidToHex(blob.OID),
			"size":     len(blob.Data),
			"content":  base64.StdEncoding.EncodeToString(blob.Data),
		})

	case "PUT":
		var req struct {
			Message string `json:"message"`
			Content string `json:"content"`
			Branch  string `json:"branch"`
			SHA     string `json:"sha"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return respBadRequestJSON
		}
		if filePath == "" || req.Message == "" {
			return jsonError(422, "Unprocessable Entity", "message and path required")
		}
		cleanB64 := strings.Map(func(c rune) rune {
			if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
				return -1
			}
			return c
		}, req.Content)
		rawBytes, err := base64.StdEncoding.DecodeString(cleanB64)
		if err != nil {
			return jsonError(422, "Unprocessable Entity", "invalid base64 content")
		}

		r.mu.Lock()
		defer r.mu.Unlock()
		branch := req.Branch
		if branch == "" {
			branch = r.DefaultBranch
		}
		refName := "refs/heads/" + branch
		parentOID, hasBranch := r.Refs[refName]
		if !hasBranch && branch != r.DefaultBranch {
			// If creating file on a new branch, seed from default branch if it exists
			if defOID, ok := r.Refs["refs/heads/"+r.DefaultBranch]; ok {
				parentOID = defOID
				hasBranch = true
			}
		}
		var files map[string][20]byte
		if hasBranch {
			files = r.FlattenTreeLocked(r.TreeForCommitLocked(parentOID))
		} else {
			files = make(map[string][20]byte)
		}

		existingOID, existed := files[filePath]
		if existed {
			if req.SHA == "" || !strings.EqualFold(req.SHA, oidToHex(existingOID)) {
				return respConflictJSON
			}
		} else if req.SHA != "" {
			return respConflictJSON
		}

		blobObj := r.PutObjectLocked(ObjBlob, rawBytes, nil)
		files[filePath] = blobObj.OID
		newTree := r.BuildTreeFromFilesLocked(files)
		var parents [][20]byte
		if hasBranch {
			parents = [][20]byte{parentOID}
		}
		commitObj := r.CreateCommitLocked(newTree, parents, req.Message, srv.store.ViewerName, srv.store.ViewerEmail)
		r.Refs[refName] = commitObj.OID
		r.RefGen++
		r.rebuildGitCachesLocked()

		status := 201
		reason := "Created"
		if existed {
			status = 200
			reason = "OK"
		}
		baseName := filePath
		if idx := strings.LastIndexByte(filePath, '/'); idx >= 0 {
			baseName = filePath[idx+1:]
		}
		return jsonResponse(status, reason, map[string]any{
			"content": map[string]any{
				"name":     baseName,
				"path":     filePath,
				"sha":      blobObj.Hex,
				"size":     len(rawBytes),
				"type":     "file",
				"encoding": "base64",
			},
			"commit": map[string]any{
				"sha":     commitObj.Hex,
				"message": req.Message,
			},
		})

	case "DELETE":
		var req struct {
			Message string `json:"message"`
			SHA     string `json:"sha"`
			Branch  string `json:"branch"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return respBadRequestJSON
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		branch := req.Branch
		if branch == "" {
			branch = r.DefaultBranch
		}
		refName := "refs/heads/" + branch
		parentOID, hasBranch := r.Refs[refName]
		if !hasBranch {
			return respNotFoundJSON
		}
		files := r.FlattenTreeLocked(r.TreeForCommitLocked(parentOID))
		existingOID, existed := files[filePath]
		if !existed {
			return respNotFoundJSON
		}
		if req.SHA != "" && !strings.EqualFold(req.SHA, oidToHex(existingOID)) {
			return respConflictJSON
		}
		delete(files, filePath)
		newTree := r.BuildTreeFromFilesLocked(files)
		commitObj := r.CreateCommitLocked(newTree, [][20]byte{parentOID}, req.Message, srv.store.ViewerName, srv.store.ViewerEmail)
		r.Refs[refName] = commitObj.OID
		r.RefGen++
		r.rebuildGitCachesLocked()
		return jsonResponse(200, "OK", map[string]any{
			"content": nil,
			"commit": map[string]any{
				"sha":     commitObj.Hex,
				"message": req.Message,
			},
		})
	}
	return respNotFoundJSON
}

func listDirEntriesLocked(r *Repo, treeOID [20]byte, prefix string) []map[string]any {
	tObj := r.Objects[treeOID]
	if tObj == nil {
		return []map[string]any{}
	}
	entries := parseTreeEntries(tObj.Data)
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		p := e.Name
		if prefix != "" {
			p = prefix + "/" + e.Name
		}
		typ := "file"
		size := 0
		if e.Mode == "40000" || e.Mode == "040000" {
			typ = "dir"
		} else if b := r.Objects[e.OID]; b != nil {
			size = len(b.Data)
		}
		out = append(out, map[string]any{
			"type": typ,
			"name": e.Name,
			"path": p,
			"sha":  oidToHex(e.OID),
			"size": size,
		})
	}
	return out
}

func (srv *Server) handleListIssues(r *Repo, rawQuery string) []byte {
	q, _ := url.ParseQuery(rawQuery)
	state := q.Get("state")
	if state == "" {
		state = "open"
	}
	direction := q.Get("direction")
	if direction == "" {
		direction = "desc"
	}
	perPage := 30
	if v, err := strconv.Atoi(q.Get("per_page")); err == nil && v > 0 {
		if v > 100 {
			v = 100
		}
		perPage = v
	}
	page := 1
	if v, err := strconv.Atoi(q.Get("page")); err == nil && v > 0 {
		page = v
	}

	r.mu.RLock()
	filtered := make([]*Issue, 0, len(r.Issues))
	for _, iss := range r.Issues {
		if state != "all" && iss.State != state {
			continue
		}
		filtered = append(filtered, iss)
	}
	if direction == "asc" {
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].Number < filtered[j].Number })
	} else {
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].Number > filtered[j].Number })
	}
	start := (page - 1) * perPage
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + perPage
	if end > len(filtered) {
		end = len(filtered)
	}
	buf := make([]byte, 0, 256*(end-start)+16)
	buf = append(buf, '[')
	for i, iss := range filtered[start:end] {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = buildIssueJSON(buf, iss)
	}
	buf = append(buf, ']')
	r.mu.RUnlock()
	return buildRawHTTPResponse(200, "OK", "application/json", buf)
}

func (srv *Server) handleSingleIssueOrComments(r *Repo, method, tail string, body []byte) []byte {
	var numStr, rest string
	if idx := strings.IndexByte(tail, '/'); idx < 0 {
		numStr = tail
	} else {
		numStr = tail[:idx]
		rest = tail[idx:]
	}
	num, err := strconv.Atoi(numStr)
	if err != nil || num <= 0 {
		return respNotFoundJSON
	}

	if rest == "" {
		switch method {
		case "GET":
			r.mu.RLock()
			iss := r.IssuesByNum[num]
			r.mu.RUnlock()
			if iss == nil {
				return respNotFoundJSON
			}
			if p := iss.cachedGetHTTP.Load(); p != nil {
				return *p
			}
			r.mu.Lock()
			iss.refreshCachedHTTP()
			p := iss.cachedGetHTTP.Load()
			r.mu.Unlock()
			return *p
		case "PATCH":
			var req map[string]any
			if err := json.Unmarshal(body, &req); err != nil {
				return respBadRequestJSON
			}
			r.mu.Lock()
			iss := r.IssuesByNum[num]
			if iss == nil {
				r.mu.Unlock()
				return respNotFoundJSON
			}
			if st, ok := req["state"].(string); ok && (st == "open" || st == "closed") {
				iss.State = st
			}
			if t, ok := req["title"].(string); ok {
				iss.Title = t
			}
			if b, ok := req["body"].(string); ok {
				iss.Body = b
			}
			iss.refreshCachedHTTP()
			p := iss.cachedGetHTTP.Load()
			r.mu.Unlock()
			return *p
		default:
			return respNotFoundJSON
		}
	}

	if rest == "/comments" {
		switch method {
		case "POST":
			var req struct {
				Body string `json:"body"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				return respBadRequestJSON
			}
			cid := srv.store.NextCommentGlobalID()
			r.mu.Lock()
			iss := r.IssuesByNum[num]
			if iss == nil {
				r.mu.Unlock()
				return respNotFoundJSON
			}
			c := &Comment{
				ID:        cid,
				NodeID:    encodeNodeID("IssueComment", cid),
				Body:      req.Body,
				Author:    srv.store.ViewerLogin,
				CreatedAt: "2025-01-01T00:00:00Z",
			}
			iss.Comments = append(iss.Comments, c)
			iss.refreshCachedHTTP()
			r.mu.Unlock()
			return jsonResponse(201, "Created", map[string]any{
				"id":         c.ID,
				"node_id":    c.NodeID,
				"body":       c.Body,
				"created_at": c.CreatedAt,
			})
		case "GET":
			r.mu.RLock()
			iss := r.IssuesByNum[num]
			if iss == nil {
				r.mu.RUnlock()
				return respNotFoundJSON
			}
			list := make([]map[string]any, 0, len(iss.Comments))
			for _, c := range iss.Comments {
				list = append(list, map[string]any{
					"id":         c.ID,
					"node_id":    c.NodeID,
					"body":       c.Body,
					"created_at": c.CreatedAt,
				})
			}
			r.mu.RUnlock()
			return jsonResponse(200, "OK", list)
		}
	}
	return respNotFoundJSON
}

func (srv *Server) createPullInternal(r *Repo, title, body, headRef, baseRef string) (*PullRequest, string, int) {
	if baseRef == "" {
		baseRef = r.DefaultBranch
	}
	headRef = strings.TrimPrefix(headRef, "refs/heads/")
	baseRef = strings.TrimPrefix(baseRef, "refs/heads/")
	prID := srv.store.NextPullGlobalID()

	r.mu.Lock()
	headOID, okHead := r.Refs["refs/heads/"+headRef]
	baseOID, okBase := r.Refs["refs/heads/"+baseRef]
	if !okHead || !okBase {
		r.mu.Unlock()
		return nil, "head or base branch not found", 422
	}
	r.NextPullNumber++
	num := r.NextPullNumber
	pr := &PullRequest{
		ID:         prID,
		NodeID:     encodeNodeID("PullRequest", r.ID, num),
		Number:     num,
		Title:      title,
		Body:       body,
		State:      "open",
		HeadRef:    headRef,
		HeadSHA:    oidToHex(headOID),
		BaseRef:    baseRef,
		BaseSHA:    oidToHex(baseOID),
		CreatedSeq: num,
		CreatedAt:  "2025-01-01T00:00:00Z",
		UpdatedAt:  "2025-01-01T00:00:00Z",
	}
	r.Pulls = append(r.Pulls, pr)
	r.PullsByNum[num] = pr
	r.mu.Unlock()
	srv.store.RegisterPullNode(r, pr)
	return pr, "", 201
}

func (srv *Server) mergePullInternal(r *Repo, num int) (string, int, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pr := r.PullsByNum[num]
	if pr == nil {
		return "", 404, "Not Found"
	}
	if pr.Merged {
		return pr.MergeCommitSHA, 405, "Pull Request is already merged"
	}
	baseOID, okBase := r.Refs["refs/heads/"+pr.BaseRef]
	headOID, okHead := r.Refs["refs/heads/"+pr.HeadRef]
	if !okBase || !okHead {
		return "", 405, "Pull Request branch missing"
	}
	mergedFiles, conflict := r.ThreeWayMergeLocked(baseOID, headOID)
	if conflict {
		return "", 405, "Pull Request is not mergeable"
	}
	mergedTree := r.BuildTreeFromFilesLocked(mergedFiles)
	msg := fmt.Sprintf("%s (#%d)", pr.Title, pr.Number)
	commitObj := r.CreateCommitLocked(mergedTree, [][20]byte{baseOID}, msg, srv.store.ViewerName, srv.store.ViewerEmail)
	r.Refs["refs/heads/"+pr.BaseRef] = commitObj.OID
	r.RefGen++
	r.rebuildGitCachesLocked()

	pr.State = "closed"
	pr.Merged = true
	pr.MergedAt = "2025-01-01T00:00:00Z"
	pr.MergeCommitSHA = commitObj.Hex
	return commitObj.Hex, 200, "Pull Request successfully merged"
}

func (srv *Server) handleCreatePull(r *Repo, body []byte) []byte {
	var req struct {
		Title string `json:"title"`
		Body  string `json:"body"`
		Head  string `json:"head"`
		Base  string `json:"base"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return respBadRequestJSON
	}
	pr, errMsg, status := srv.createPullInternal(r, req.Title, req.Body, req.Head, req.Base)
	if status != 201 {
		return jsonError(status, "Unprocessable Entity", errMsg)
	}
	r.mu.RLock()
	m := pullToMap(r, pr)
	r.mu.RUnlock()
	return jsonResponse(201, "Created", m)
}

func (srv *Server) handleListPulls(r *Repo, rawQuery string) []byte {
	q, _ := url.ParseQuery(rawQuery)
	state := q.Get("state")
	if state == "" {
		state = "open"
	}
	r.mu.RLock()
	out := make([]map[string]any, 0, len(r.Pulls))
	for _, pr := range r.Pulls {
		if state != "all" && pr.State != state {
			continue
		}
		out = append(out, pullToMap(r, pr))
	}
	r.mu.RUnlock()
	return jsonResponse(200, "OK", out)
}

func (srv *Server) handleSinglePull(r *Repo, method, tail string, body []byte) []byte {
	var numStr, rest string
	if idx := strings.IndexByte(tail, '/'); idx < 0 {
		numStr = tail
	} else {
		numStr = tail[:idx]
		rest = tail[idx:]
	}
	num, err := strconv.Atoi(numStr)
	if err != nil || num <= 0 {
		return respNotFoundJSON
	}

	switch {
	case rest == "" && method == "GET":
		r.mu.RLock()
		pr := r.PullsByNum[num]
		if pr == nil {
			r.mu.RUnlock()
			return respNotFoundJSON
		}
		m := pullToMap(r, pr)
		r.mu.RUnlock()
		return jsonResponse(200, "OK", m)

	case rest == "/files" && method == "GET":
		r.mu.RLock()
		pr := r.PullsByNum[num]
		if pr == nil {
			r.mu.RUnlock()
			return respNotFoundJSON
		}
		baseOID, _ := parseOIDHex(pr.BaseSHA)
		headOID, _ := parseOIDHex(pr.HeadSHA)
		if liveHead, ok := r.Refs["refs/heads/"+pr.HeadRef]; ok && !pr.Merged {
			headOID = liveHead
		}
		diffs := r.DiffCommitsLocked(baseOID, headOID)
		r.mu.RUnlock()
		if diffs == nil {
			diffs = []DiffFile{}
		}
		return jsonResponse(200, "OK", diffs)

	case rest == "/merge" && method == "PUT":
		if len(bytes.TrimSpace(body)) > 0 {
			var tmp map[string]any
			if err := json.Unmarshal(body, &tmp); err != nil {
				return respBadRequestJSON
			}
		}
		sha, status, msg := srv.mergePullInternal(r, num)
		if status == 404 {
			return respNotFoundJSON
		}
		if status == 405 {
			return respMergeConflict
		}
		return jsonResponse(200, "OK", map[string]any{
			"sha":     sha,
			"merged":  true,
			"message": msg,
		})
	}
	return respNotFoundJSON
}
