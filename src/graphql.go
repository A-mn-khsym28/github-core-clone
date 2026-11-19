package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ---------- Minimal Complete GraphQL Lexer & Recursive-Descent Parser ----------

type gqlTokKind int

const (
	tokEOF gqlTokKind = iota
	tokName
	tokInt
	tokFloat
	tokString
	tokPunct // { } ( ) [ ] : = $ @ !
	tokSpread
)

type gqlTok struct {
	kind gqlTokKind
	val  string
}

type gqlLexer struct {
	src string
	pos int
}

func (l *gqlLexer) next() gqlTok {
	n := len(l.src)
	for l.pos < n {
		c := l.src[l.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' {
			l.pos++
			continue
		}
		if c == '#' {
			for l.pos < n && l.src[l.pos] != '\n' {
				l.pos++
			}
			continue
		}
		break
	}
	if l.pos >= n {
		return gqlTok{kind: tokEOF}
	}
	c := l.src[l.pos]
	if c == '.' && l.pos+2 < n && l.src[l.pos+1] == '.' && l.src[l.pos+2] == '.' {
		l.pos += 3
		return gqlTok{kind: tokSpread, val: "..."}
	}
	switch c {
	case '{', '}', '(', ')', '[', ']', ':', '=', '$', '@', '!':
		l.pos++
		return gqlTok{kind: tokPunct, val: string(c)}
	case '"':
		return l.readString()
	}
	if c == '-' || (c >= '0' && c <= '9') {
		start := l.pos
		if c == '-' {
			l.pos++
		}
		for l.pos < n && l.src[l.pos] >= '0' && l.src[l.pos] <= '9' {
			l.pos++
		}
		isFloat := false
		if l.pos < n && l.src[l.pos] == '.' {
			isFloat = true
			l.pos++
			for l.pos < n && l.src[l.pos] >= '0' && l.src[l.pos] <= '9' {
				l.pos++
			}
		}
		if isFloat {
			return gqlTok{kind: tokFloat, val: l.src[start:l.pos]}
		}
		return gqlTok{kind: tokInt, val: l.src[start:l.pos]}
	}
	if isGqlNameStart(c) {
		start := l.pos
		l.pos++
		for l.pos < n && isGqlNameCont(l.src[l.pos]) {
			l.pos++
		}
		return gqlTok{kind: tokName, val: l.src[start:l.pos]}
	}
	l.pos++
	return gqlTok{kind: tokPunct, val: string(c)}
}

func (l *gqlLexer) readString() gqlTok {
	n := len(l.src)
	if l.pos+2 < n && l.src[l.pos:l.pos+3] == `"""` {
		l.pos += 3
		start := l.pos
		for l.pos+2 < n && l.src[l.pos:l.pos+3] != `"""` {
			l.pos++
		}
		val := l.src[start:l.pos]
		if l.pos+3 <= n {
			l.pos += 3
		}
		return gqlTok{kind: tokString, val: val}
	}
	l.pos++ // skip opening "
	var sb strings.Builder
	for l.pos < n {
		c := l.src[l.pos]
		l.pos++
		if c == '"' {
			break
		}
		if c == '\\' && l.pos < n {
			esc := l.src[l.pos]
			l.pos++
			switch esc {
			case '"', '\\', '/':
				sb.WriteByte(esc)
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			default:
				sb.WriteByte(esc)
			}
		} else {
			sb.WriteByte(c)
		}
	}
	return gqlTok{kind: tokString, val: sb.String()}
}

func isGqlNameStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func isGqlNameCont(c byte) bool {
	return isGqlNameStart(c) || (c >= '0' && c <= '9')
}

type gqlField struct {
	alias      string
	name       string
	args       map[string]any
	selections []gqlSelection
}

type gqlSelection struct {
	field          *gqlField
	inlineType     string
	inlineSels     []gqlSelection
	fragmentSpread string
}

type gqlOp struct {
	kind       string // "query" or "mutation"
	name       string
	selections []gqlSelection
}

type gqlDoc struct {
	ops       []gqlOp
	fragments map[string][]gqlSelection
}

type gqlParser struct {
	toks []gqlTok
	pos  int
	vars map[string]any
}

func parseGQL(src string, vars map[string]any) (*gqlDoc, error) {
	lex := gqlLexer{src: src}
	var toks []gqlTok
	for {
		t := lex.next()
		toks = append(toks, t)
		if t.kind == tokEOF {
			break
		}
	}
	p := &gqlParser{toks: toks, vars: vars}
	doc := &gqlDoc{fragments: make(map[string][]gqlSelection)}
	for p.peek().kind != tokEOF {
		t := p.peek()
		if t.kind == tokPunct && t.val == "{" {
			sels, err := p.parseSelectionSet()
			if err != nil {
				return nil, err
			}
			doc.ops = append(doc.ops, gqlOp{kind: "query", selections: sels})
		} else if t.kind == tokName && (t.val == "query" || t.val == "mutation") {
			kind := p.consume().val
			opName := ""
			if p.peek().kind == tokName {
				opName = p.consume().val
			}
			if p.peek().kind == tokPunct && p.peek().val == "(" {
				p.skipParens()
			}
			for p.peek().kind == tokPunct && p.peek().val == "@" {
				p.skipDirective()
			}
			sels, err := p.parseSelectionSet()
			if err != nil {
				return nil, err
			}
			doc.ops = append(doc.ops, gqlOp{kind: kind, name: opName, selections: sels})
		} else if t.kind == tokName && t.val == "fragment" {
			p.consume()
			fragName := p.consume().val
			if p.peek().kind == tokName && p.peek().val == "on" {
				p.consume()
				p.consume() // type name
			}
			sels, err := p.parseSelectionSet()
			if err != nil {
				return nil, err
			}
			doc.fragments[fragName] = sels
		} else {
			return nil, fmt.Errorf("unexpected token %q", t.val)
		}
	}
	return doc, nil
}

func (p *gqlParser) peek() gqlTok {
	if p.pos >= len(p.toks) {
		return gqlTok{kind: tokEOF}
	}
	return p.toks[p.pos]
}

func (p *gqlParser) consume() gqlTok {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}

func (p *gqlParser) skipParens() {
	if p.peek().val != "(" {
		return
	}
	depth := 0
	for p.peek().kind != tokEOF {
		v := p.consume().val
		if v == "(" {
			depth++
		} else if v == ")" {
			depth--
			if depth == 0 {
				break
			}
		}
	}
}

func (p *gqlParser) skipDirective() {
	p.consume() // @
	p.consume() // name
	if p.peek().val == "(" {
		p.skipParens()
	}
}

func (p *gqlParser) parseSelectionSet() ([]gqlSelection, error) {
	if p.consume().val != "{" {
		return nil, fmt.Errorf("expected '{'")
	}
	var sels []gqlSelection
	for p.peek().kind != tokEOF && p.peek().val != "}" {
		if p.peek().kind == tokSpread {
			p.consume()
			if p.peek().kind == tokName && p.peek().val == "on" {
				p.consume()
				typeName := p.consume().val
				sub, err := p.parseSelectionSet()
				if err != nil {
					return nil, err
				}
				sels = append(sels, gqlSelection{inlineType: typeName, inlineSels: sub})
			} else if p.peek().kind == tokName {
				sels = append(sels, gqlSelection{fragmentSpread: p.consume().val})
			} else if p.peek().val == "{" {
				sub, err := p.parseSelectionSet()
				if err != nil {
					return nil, err
				}
				sels = append(sels, gqlSelection{inlineSels: sub})
			}
			continue
		}
		if p.peek().kind != tokName {
			return nil, fmt.Errorf("expected field name, got %q", p.peek().val)
		}
		first := p.consume().val
		alias := first
		name := first
		if p.peek().val == ":" {
			p.consume()
			name = p.consume().val
		}
		var args map[string]any
		if p.peek().val == "(" {
			var err error
			args, err = p.parseArgs()
			if err != nil {
				return nil, err
			}
		}
		for p.peek().val == "@" {
			p.skipDirective()
		}
		var sub []gqlSelection
		if p.peek().val == "{" {
			var err error
			sub, err = p.parseSelectionSet()
			if err != nil {
				return nil, err
			}
		}
		sels = append(sels, gqlSelection{
			field: &gqlField{alias: alias, name: name, args: args, selections: sub},
		})
	}
	if p.consume().val != "}" {
		return nil, fmt.Errorf("expected '}'")
	}
	return sels, nil
}

func (p *gqlParser) parseArgs() (map[string]any, error) {
	p.consume() // (
	args := make(map[string]any)
	for p.peek().kind != tokEOF && p.peek().val != ")" {
		k := p.consume().val
		if p.consume().val != ":" {
			return nil, fmt.Errorf("expected ':' after arg %q", k)
		}
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		args[k] = v
	}
	p.consume() // )
	return args, nil
}

func (p *gqlParser) parseValue() (any, error) {
	t := p.peek()
	switch t.kind {
	case tokString:
		p.consume()
		return t.val, nil
	case tokInt:
		p.consume()
		iv, _ := strconv.Atoi(t.val)
		return iv, nil
	case tokFloat:
		p.consume()
		fv, _ := strconv.ParseFloat(t.val, 64)
		return fv, nil
	case tokName:
		p.consume()
		switch t.val {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "null":
			return nil, nil
		default:
			return t.val, nil // enum literal
		}
	case tokPunct:
		switch t.val {
		case "$":
			p.consume()
			varName := p.consume().val
			if p.vars != nil {
				return p.vars[varName], nil
			}
			return nil, nil
		case "[":
			p.consume()
			var arr []any
			for p.peek().kind != tokEOF && p.peek().val != "]" {
				v, err := p.parseValue()
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			p.consume()
			return arr, nil
		case "{":
			p.consume()
			obj := make(map[string]any)
			for p.peek().kind != tokEOF && p.peek().val != "}" {
				k := p.consume().val
				if p.consume().val != ":" {
					return nil, fmt.Errorf("expected ':' in input object")
				}
				v, err := p.parseValue()
				if err != nil {
					return nil, err
				}
				obj[k] = v
			}
			p.consume()
			return obj, nil
		}
	}
	return nil, fmt.Errorf("unexpected value token %q", t.val)
}

// ---------- GraphQL Schema Metadata for __type Introspection ----------

var gqlTypeFields = map[string][]string{
	"Issue": {
		"id", "databaseId", "number", "title", "state", "body", "createdAt", "updatedAt", "labels", "comments", "author",
	},
	"PullRequest": {
		"id", "databaseId", "number", "title", "body", "headRefName", "baseRefName", "mergeable", "state", "merged", "mergedAt", "mergeCommit", "files",
	},
	"Repository": {
		"id", "databaseId", "name", "nameWithOwner", "description", "isPrivate", "owner", "defaultBranchRef", "viewerPermission", "hasIssuesEnabled", "issue", "issues", "pullRequests", "pullRequest",
	},
	"User": {
		"id", "login", "name", "email",
	},
	"Query": {
		"viewer", "repository", "node", "__type", "__schema",
	},
	"Mutation": {
		"createIssue", "closeIssue", "createPullRequest", "mergePullRequest", "addComment",
	},
}

var gqlEnumValues = map[string][]string{
	"SearchType":           {"ISSUE", "ISSUE_ADVANCED", "REPOSITORY", "USER", "DISCUSSION"},
	"IssueState":           {"OPEN", "CLOSED"},
	"PullRequestState":     {"OPEN", "CLOSED", "MERGED"},
	"MergeableState":       {"MERGEABLE", "CONFLICTING", "UNKNOWN"},
	"PullRequestMergeMethod": {"MERGE", "SQUASH", "REBASE"},
	"RepositoryPermission": {"ADMIN", "MAINTAIN", "WRITE", "TRIAGE", "READ"},
	"IssueOrderField":      {"CREATED_AT", "UPDATED_AT", "COMMENTS"},
	"OrderDirection":       {"ASC", "DESC"},
}

type gqlReq struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName"`
	Variables     map[string]any `json:"variables"`
}

type gqlExec struct {
	srv       *Server
	fragments map[string][]gqlSelection
	errors    []map[string]string
}

func (e *gqlExec) addErr(msg string) {
	e.errors = append(e.errors, map[string]string{"message": msg})
}

func (e *gqlExec) flatten(sels []gqlSelection, typeName string) []*gqlField {
	var out []*gqlField
	for _, s := range sels {
		if s.field != nil {
			out = append(out, s.field)
		} else if s.fragmentSpread != "" {
			if fs, ok := e.fragments[s.fragmentSpread]; ok {
				out = append(out, e.flatten(fs, typeName)...)
			}
		} else if s.inlineType == "" || s.inlineType == typeName {
			out = append(out, e.flatten(s.inlineSels, typeName)...)
		}
	}
	return out
}

func argString(args map[string]any, k string) string {
	if args == nil {
		return ""
	}
	if s, ok := args[k].(string); ok {
		return s
	}
	return ""
}

func argInt(args map[string]any, k string, def int) int {
	if args == nil {
		return def
	}
	switch v := args[k].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func argMap(args map[string]any, k string) map[string]any {
	if args == nil {
		return nil
	}
	if m, ok := args[k].(map[string]any); ok {
		return m
	}
	return nil
}

func (srv *Server) handleGraphQL(body []byte) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return respBadRequestJSON
	}
	if trimmed[0] == '[' {
		var batch []gqlReq
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return respBadRequestJSON
		}
		results := make([]map[string]any, len(batch))
		for i, req := range batch {
			results[i] = srv.executeGQL(req)
		}
		return jsonResponse(200, "OK", results)
	}
	var req gqlReq
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return respBadRequestJSON
	}
	return jsonResponse(200, "OK", srv.executeGQL(req))
}

func (srv *Server) executeGQL(req gqlReq) map[string]any {
	doc, err := parseGQL(req.Query, req.Variables)
	if err != nil || len(doc.ops) == 0 {
		msg := "syntax error"
		if err != nil {
			msg = err.Error()
		}
		return map[string]any{
			"data":   nil,
			"errors": []map[string]string{{"message": msg}},
		}
	}
	op := doc.ops[0]
	if req.OperationName != "" {
		for _, candidate := range doc.ops {
			if candidate.name == req.OperationName {
				op = candidate
				break
			}
		}
	}
	ex := &gqlExec{srv: srv, fragments: doc.fragments}
	var data map[string]any
	if op.kind == "mutation" {
		data = ex.execMutation(op.selections)
	} else {
		data = ex.execQuery(op.selections)
	}
	resp := map[string]any{"data": data}
	if len(ex.errors) > 0 {
		resp["errors"] = ex.errors
	}
	return resp
}

func (e *gqlExec) execQuery(sels []gqlSelection) map[string]any {
	out := make(map[string]any)
	for _, f := range e.flatten(sels, "Query") {
		switch f.name {
		case "__typename":
			out[f.alias] = "Query"
		case "viewer":
			out[f.alias] = e.resolveUser(f.selections)
		case "repository":
			owner := argString(f.args, "owner")
			name := argString(f.args, "name")
			r := e.srv.store.GetRepo(owner, name)
			if r == nil {
				out[f.alias] = nil
			} else {
				out[f.alias] = e.resolveRepo(r, f.selections)
			}
		case "node":
			id := argString(f.args, "id")
			out[f.alias] = e.resolveNode(id, f.selections)
		case "__type":
			tName := argString(f.args, "name")
			out[f.alias] = e.resolveIntrospectionType(tName, f.selections)
		default:
			e.addErr(fmt.Sprintf("Field '%s' doesn't exist on type 'Query'", f.name))
		}
	}
	return out
}

func (e *gqlExec) resolveUser(sels []gqlSelection) map[string]any {
	out := make(map[string]any)
	for _, f := range e.flatten(sels, "User") {
		switch f.name {
		case "__typename":
			out[f.alias] = "User"
		case "id":
			out[f.alias] = encodeNodeID("User", e.srv.store.ViewerID)
		case "login":
			out[f.alias] = e.srv.store.ViewerLogin
		case "name":
			out[f.alias] = e.srv.store.ViewerName
		case "email":
			out[f.alias] = e.srv.store.ViewerEmail
		default:
			e.addErr(fmt.Sprintf("Field '%s' doesn't exist on type 'User'", f.name))
		}
	}
	return out
}

func (e *gqlExec) resolveIntrospectionType(tName string, sels []gqlSelection) any {
	fields, hasFields := gqlTypeFields[tName]
	enums, hasEnums := gqlEnumValues[tName]
	if !hasFields && !hasEnums {
		return nil
	}
	out := make(map[string]any)
	for _, f := range e.flatten(sels, "__Type") {
		switch f.name {
		case "name":
			out[f.alias] = tName
		case "kind":
			if hasEnums {
				out[f.alias] = "ENUM"
			} else {
				out[f.alias] = "OBJECT"
			}
		case "fields":
			if !hasFields {
				out[f.alias] = nil
			} else {
				list := make([]map[string]any, 0, len(fields))
				for _, fn := range fields {
					item := make(map[string]any)
					for _, sf := range e.flatten(f.selections, "__Field") {
						if sf.name == "name" {
							item[sf.alias] = fn
						} else if sf.name == "isDeprecated" {
							item[sf.alias] = false
						}
					}
					list = append(list, item)
				}
				out[f.alias] = list
			}
		case "enumValues":
			if !hasEnums {
				out[f.alias] = nil
			} else {
				list := make([]map[string]any, 0, len(enums))
				for _, ev := range enums {
					item := make(map[string]any)
					for _, sf := range e.flatten(f.selections, "__EnumValue") {
						if sf.name == "name" {
							item[sf.alias] = ev
						} else if sf.name == "isDeprecated" {
							item[sf.alias] = false
						}
					}
					list = append(list, item)
				}
				out[f.alias] = list
			}
		}
	}
	return out
}

func (e *gqlExec) resolveNode(id string, sels []gqlSelection) any {
	e.srv.store.mu.RLock()
	r := e.srv.store.NodeRepos[id]
	prRef, hasPR := e.srv.store.NodePulls[id]
	e.srv.store.mu.RUnlock()

	if r != nil {
		return e.resolveRepo(r, sels)
	}
	if ir, iss := e.srv.store.ResolveIssueByNodeID(id); ir != nil && iss != nil {
		return e.resolveIssue(ir, iss, sels)
	}
	if hasPR {
		return e.resolvePull(prRef.Repo, prRef.Pull, sels)
	}
	return nil
}

func (e *gqlExec) resolveRepo(r *Repo, sels []gqlSelection) map[string]any {
	out := make(map[string]any)
	for _, f := range e.flatten(sels, "Repository") {
		switch f.name {
		case "__typename":
			out[f.alias] = "Repository"
		case "id":
			out[f.alias] = r.NodeID
		case "databaseId":
			out[f.alias] = r.ID
		case "name":
			out[f.alias] = r.Name
		case "nameWithOwner":
			out[f.alias] = r.FullName
		case "description":
			r.mu.RLock()
			out[f.alias] = r.Description
			r.mu.RUnlock()
		case "isPrivate":
			r.mu.RLock()
			out[f.alias] = r.Private
			r.mu.RUnlock()
		case "viewerPermission":
			out[f.alias] = "ADMIN"
		case "hasIssuesEnabled":
			out[f.alias] = true
		case "owner":
			out[f.alias] = e.resolveUser(f.selections)
		case "defaultBranchRef":
			r.mu.RLock()
			defName := r.DefaultBranch
			_, hasRef := r.Refs["refs/heads/"+defName]
			r.mu.RUnlock()
			if !hasRef {
				out[f.alias] = nil
			} else {
				refObj := make(map[string]any)
				for _, sf := range e.flatten(f.selections, "Ref") {
					switch sf.name {
					case "name":
						refObj[sf.alias] = defName
					case "prefix":
						refObj[sf.alias] = "refs/heads/"
					}
				}
				out[f.alias] = refObj
			}
		case "issue":
			num := argInt(f.args, "number", 0)
			r.mu.RLock()
			iss := r.IssuesByNum[num]
			r.mu.RUnlock()
			if iss == nil {
				out[f.alias] = nil
			} else {
				out[f.alias] = e.resolveIssue(r, iss, f.selections)
			}
		case "issues":
			out[f.alias] = e.resolveIssuesConnection(r, f.args, f.selections)
		case "pullRequest":
			num := argInt(f.args, "number", 0)
			r.mu.RLock()
			pr := r.PullsByNum[num]
			r.mu.RUnlock()
			if pr == nil {
				out[f.alias] = nil
			} else {
				out[f.alias] = e.resolvePull(r, pr, f.selections)
			}
		case "pullRequests":
			out[f.alias] = e.resolvePullsConnection(r, f.args, f.selections)
		default:
			e.addErr(fmt.Sprintf("Field '%s' doesn't exist on type 'Repository'", f.name))
		}
	}
	return out
}

func (e *gqlExec) resolveIssue(r *Repo, iss *Issue, sels []gqlSelection) map[string]any {
	out := make(map[string]any)
	for _, f := range e.flatten(sels, "Issue") {
		switch f.name {
		case "__typename":
			out[f.alias] = "Issue"
		case "id":
			if iss.NodeID == "" {
				iss.NodeID = encodeNodeID("Issue", r.ID, iss.Number)
			}
			out[f.alias] = iss.NodeID
		case "databaseId":
			out[f.alias] = iss.ID
		case "number":
			out[f.alias] = iss.Number
		case "title":
			out[f.alias] = iss.Title
		case "body":
			out[f.alias] = iss.Body
		case "state":
			out[f.alias] = strings.ToUpper(iss.State)
		case "createdAt":
			out[f.alias] = iss.CreatedAt
		case "updatedAt":
			out[f.alias] = iss.UpdatedAt
		default:
			e.addErr(fmt.Sprintf("Field '%s' doesn't exist on type 'Issue'", f.name))
		}
	}
	return out
}

func (e *gqlExec) resolveIssuesConnection(r *Repo, args map[string]any, sels []gqlSelection) map[string]any {
	first := argInt(args, "first", 100)
	after := argString(args, "after")
	var stateFilter map[string]bool
	if rawStates, ok := args["states"].([]any); ok && len(rawStates) > 0 {
		stateFilter = make(map[string]bool, len(rawStates))
		for _, s := range rawStates {
			if ss, ok := s.(string); ok {
				stateFilter[strings.ToUpper(ss)] = true
			}
		}
	}
	dir := "ASC"
	if orderBy := argMap(args, "orderBy"); orderBy != nil {
		if d := argString(orderBy, "direction"); d != "" {
			dir = strings.ToUpper(d)
		}
	}

	r.mu.RLock()
	list := make([]*Issue, 0, len(r.Issues))
	for _, iss := range r.Issues {
		if stateFilter != nil && !stateFilter[strings.ToUpper(iss.State)] {
			continue
		}
		list = append(list, iss)
	}
	r.mu.RUnlock()

	if dir == "DESC" {
		sort.Slice(list, func(i, j int) bool { return list[i].Number > list[j].Number })
	} else {
		sort.Slice(list, func(i, j int) bool { return list[i].Number < list[j].Number })
	}

	startIdx := 0
	if after != "" {
		if dec, err := base64.StdEncoding.DecodeString(after); err == nil {
			if idx, err := strconv.Atoi(strings.TrimPrefix(string(dec), "cursor:")); err == nil {
				startIdx = idx + 1
			}
		}
	}
	if startIdx > len(list) {
		startIdx = len(list)
	}
	endIdx := startIdx + first
	hasNext := false
	if endIdx < len(list) {
		hasNext = true
	} else {
		endIdx = len(list)
	}
	page := list[startIdx:endIdx]
	var endCursor any
	if len(page) > 0 {
		endCursor = base64.StdEncoding.EncodeToString([]byte("cursor:" + strconv.Itoa(endIdx-1)))
	}

	out := make(map[string]any)
	for _, f := range e.flatten(sels, "IssueConnection") {
		switch f.name {
		case "nodes":
			nodes := make([]map[string]any, 0, len(page))
			for _, iss := range page {
				nodes = append(nodes, e.resolveIssue(r, iss, f.selections))
			}
			out[f.alias] = nodes
		case "totalCount":
			out[f.alias] = len(list)
		case "pageInfo":
			pi := make(map[string]any)
			for _, pf := range e.flatten(f.selections, "PageInfo") {
				switch pf.name {
				case "hasNextPage":
					pi[pf.alias] = hasNext
				case "endCursor":
					pi[pf.alias] = endCursor
				}
			}
			out[f.alias] = pi
		}
	}
	return out
}

func (e *gqlExec) resolvePull(r *Repo, pr *PullRequest, sels []gqlSelection) map[string]any {
	out := make(map[string]any)
	for _, f := range e.flatten(sels, "PullRequest") {
		switch f.name {
		case "__typename":
			out[f.alias] = "PullRequest"
		case "id":
			out[f.alias] = pr.NodeID
		case "databaseId":
			out[f.alias] = pr.ID
		case "number":
			out[f.alias] = pr.Number
		case "title":
			out[f.alias] = pr.Title
		case "body":
			out[f.alias] = pr.Body
		case "headRefName":
			out[f.alias] = pr.HeadRef
		case "baseRefName":
			out[f.alias] = pr.BaseRef
		case "merged":
			out[f.alias] = pr.Merged
		case "state":
			if pr.Merged {
				out[f.alias] = "MERGED"
			} else {
				out[f.alias] = strings.ToUpper(pr.State)
			}
		case "mergeable":
			if pr.Merged {
				out[f.alias] = "UNKNOWN"
			} else {
				r.mu.RLock()
				baseOID, ok1 := r.Refs["refs/heads/"+pr.BaseRef]
				headOID, ok2 := r.Refs["refs/heads/"+pr.HeadRef]
				conflict := false
				if ok1 && ok2 {
					_, conflict = r.ThreeWayMergeLocked(baseOID, headOID)
				}
				r.mu.RUnlock()
				if conflict {
					out[f.alias] = "CONFLICTING"
				} else {
					out[f.alias] = "MERGEABLE"
				}
			}
		case "files":
			first := argInt(f.args, "first", 100)
			r.mu.RLock()
			baseOID, _ := parseOIDHex(pr.BaseSHA)
			headOID, _ := parseOIDHex(pr.HeadSHA)
			if liveHead, ok := r.Refs["refs/heads/"+pr.HeadRef]; ok && !pr.Merged {
				headOID = liveHead
			}
			diffs := r.DiffCommitsLocked(baseOID, headOID)
			r.mu.RUnlock()
			if len(diffs) > first {
				diffs = diffs[:first]
			}
			conn := make(map[string]any)
			for _, cf := range e.flatten(f.selections, "PullRequestChangedFileConnection") {
				if cf.name == "nodes" {
					nodes := make([]map[string]any, 0, len(diffs))
					for _, d := range diffs {
						node := make(map[string]any)
						for _, nf := range e.flatten(cf.selections, "PullRequestChangedFile") {
							switch nf.name {
							case "path":
								node[nf.alias] = d.Filename
							case "additions":
								node[nf.alias] = d.Additions
							case "deletions":
								node[nf.alias] = d.Deletions
							}
						}
						nodes = append(nodes, node)
					}
					conn[cf.alias] = nodes
				}
			}
			out[f.alias] = conn
		default:
			e.addErr(fmt.Sprintf("Field '%s' doesn't exist on type 'PullRequest'", f.name))
		}
	}
	return out
}

func (e *gqlExec) resolvePullsConnection(r *Repo, args map[string]any, sels []gqlSelection) map[string]any {
	first := argInt(args, "first", 100)
	r.mu.RLock()
	list := make([]*PullRequest, 0, len(r.Pulls))
	for _, pr := range r.Pulls {
		list = append(list, pr)
	}
	r.mu.RUnlock()
	if len(list) > first {
		list = list[:first]
	}
	out := make(map[string]any)
	for _, f := range e.flatten(sels, "PullRequestConnection") {
		if f.name == "nodes" {
			nodes := make([]map[string]any, 0, len(list))
			for _, pr := range list {
				nodes = append(nodes, e.resolvePull(r, pr, f.selections))
			}
			out[f.alias] = nodes
		}
	}
	return out
}

func (e *gqlExec) execMutation(sels []gqlSelection) map[string]any {
	out := make(map[string]any)
	for _, f := range e.flatten(sels, "Mutation") {
		input := argMap(f.args, "input")
		switch f.name {
		case "createIssue":
			repoID := argString(input, "repositoryId")
			title := argString(input, "title")
			body := argString(input, "body")
			e.srv.store.mu.RLock()
			r := e.srv.store.NodeRepos[repoID]
			e.srv.store.mu.RUnlock()
			if r == nil {
				e.addErr("Repository not found")
				continue
			}
			gid := e.srv.store.NextIssueGlobalID()
			r.mu.Lock()
			r.NextIssueNumber++
			num := r.NextIssueNumber
			iss := &Issue{
				ID:         gid,
				NodeID:     encodeNodeID("Issue", r.ID, num),
				Number:     num,
				Title:      title,
				Body:       body,
				State:      "open",
				CreatedSeq: num,
				CreatedAt:  "2025-01-01T00:00:00Z",
				UpdatedAt:  "2025-01-01T00:00:00Z",
			}
			r.Issues = append(r.Issues, iss)
			snap := r.Issues
			r.issuesSnap.Store(&snap)
			r.IssuesByNum[num] = iss
			iss.refreshCachedHTTP()
			r.mu.Unlock()
			e.srv.store.RegisterIssueNode(r, iss)
			payload := make(map[string]any)
			for _, pf := range e.flatten(f.selections, "CreateIssuePayload") {
				if pf.name == "issue" {
					payload[pf.alias] = e.resolveIssue(r, iss, pf.selections)
				}
			}
			out[f.alias] = payload

		case "closeIssue":
			issueID := argString(input, "issueId")
			r, iss := e.srv.store.ResolveIssueByNodeID(issueID)
			if r == nil || iss == nil {
				e.addErr("Issue not found")
				continue
			}
			r.mu.Lock()
			iss.State = "closed"
			iss.refreshCachedHTTP()
			r.mu.Unlock()
			payload := make(map[string]any)
			for _, pf := range e.flatten(f.selections, "CloseIssuePayload") {
				if pf.name == "issue" {
					payload[pf.alias] = e.resolveIssue(r, iss, pf.selections)
				}
			}
			out[f.alias] = payload

		case "createPullRequest":
			repoID := argString(input, "repositoryId")
			baseRef := argString(input, "baseRefName")
			headRef := argString(input, "headRefName")
			title := argString(input, "title")
			body := argString(input, "body")
			e.srv.store.mu.RLock()
			r := e.srv.store.NodeRepos[repoID]
			e.srv.store.mu.RUnlock()
			if r == nil {
				e.addErr("Repository not found")
				continue
			}
			pr, errMsg, status := e.srv.createPullInternal(r, title, body, headRef, baseRef)
			if status != 201 {
				e.addErr(errMsg)
				continue
			}
			payload := make(map[string]any)
			for _, pf := range e.flatten(f.selections, "CreatePullRequestPayload") {
				if pf.name == "pullRequest" {
					payload[pf.alias] = e.resolvePull(r, pr, pf.selections)
				}
			}
			out[f.alias] = payload

		case "mergePullRequest":
			prID := argString(input, "pullRequestId")
			e.srv.store.mu.RLock()
			ref, ok := e.srv.store.NodePulls[prID]
			e.srv.store.mu.RUnlock()
			if !ok {
				e.addErr("PullRequest not found")
				continue
			}
			_, status, msg := e.srv.mergePullInternal(ref.Repo, ref.Pull.Number)
			if status != 200 {
				e.addErr(msg)
				continue
			}
			payload := make(map[string]any)
			for _, pf := range e.flatten(f.selections, "MergePullRequestPayload") {
				if pf.name == "pullRequest" {
					payload[pf.alias] = e.resolvePull(ref.Repo, ref.Pull, pf.selections)
				}
			}
			out[f.alias] = payload

		case "addComment":
			subjectID := argString(input, "subjectId")
			cBody := argString(input, "body")
			r, iss := e.srv.store.ResolveIssueByNodeID(subjectID)
			if r == nil || iss == nil {
				e.addErr("Subject not found")
				continue
			}
			cid := e.srv.store.NextCommentGlobalID()
			r.mu.Lock()
			c := &Comment{
				ID:        cid,
				NodeID:    encodeNodeID("IssueComment", cid),
				Body:      cBody,
				Author:    e.srv.store.ViewerLogin,
				CreatedAt: "2025-01-01T00:00:00Z",
			}
			iss.Comments = append(iss.Comments, c)
			iss.refreshCachedHTTP()
			r.mu.Unlock()
			payload := make(map[string]any)
			for _, pf := range e.flatten(f.selections, "AddCommentPayload") {
				if pf.name == "commentEdge" {
					edge := make(map[string]any)
					for _, ef := range e.flatten(pf.selections, "IssueCommentEdge") {
						if ef.name == "node" {
							node := make(map[string]any)
							for _, nf := range e.flatten(ef.selections, "IssueComment") {
								switch nf.name {
								case "id":
									node[nf.alias] = c.NodeID
								case "body":
									node[nf.alias] = c.Body
								}
							}
							edge[ef.alias] = node
						}
					}
					payload[pf.alias] = edge
				}
			}
			out[f.alias] = payload

		default:
			e.addErr(fmt.Sprintf("Field '%s' doesn't exist on type 'Mutation'", f.name))
		}
	}
	return out
}
