package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type mcpToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

var mcpToolsList = []mcpToolDef{
	{
		Name:        "create_repo",
		Description: "Create a new repository for the authenticated user",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":        map[string]any{"type": "string", "description": "Repository name"},
				"description": map[string]any{"type": "string", "description": "Repository description"},
				"private":     map[string]any{"type": "boolean", "description": "Whether the repository is private"},
			},
			"required": []string{"name"},
		},
	},
	{
		Name:        "get_repo",
		Description: "Get repository metadata by owner and repository name",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"owner": map[string]any{"type": "string", "description": "Repository owner login"},
				"repo":  map[string]any{"type": "string", "description": "Repository name"},
			},
			"required": []string{"owner", "repo"},
		},
	},
	{
		Name:        "create_issue",
		Description: "Create an issue in a repository",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"owner": map[string]any{"type": "string", "description": "Repository owner login"},
				"repo":  map[string]any{"type": "string", "description": "Repository name"},
				"title": map[string]any{"type": "string", "description": "Issue title"},
				"body":  map[string]any{"type": "string", "description": "Issue body"},
			},
			"required": []string{"owner", "repo", "title"},
		},
	},
	{
		Name:        "list_issues",
		Description: "List issues in a repository filtered by state",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"owner": map[string]any{"type": "string", "description": "Repository owner login"},
				"repo":  map[string]any{"type": "string", "description": "Repository name"},
				"state": map[string]any{"type": "string", "description": "Issue state: open, closed, or all"},
			},
			"required": []string{"owner", "repo"},
		},
	},
	{
		Name:        "create_pull_request",
		Description: "Open a pull request from a head branch into a base branch",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"owner": map[string]any{"type": "string", "description": "Repository owner login"},
				"repo":  map[string]any{"type": "string", "description": "Repository name"},
				"title": map[string]any{"type": "string", "description": "Pull request title"},
				"body":  map[string]any{"type": "string", "description": "Pull request body"},
				"head":  map[string]any{"type": "string", "description": "Head branch name"},
				"base":  map[string]any{"type": "string", "description": "Base branch name"},
			},
			"required": []string{"owner", "repo", "title", "head", "base"},
		},
	},
	{
		Name:        "merge_pull_request",
		Description: "Merge an open pull request by number",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"owner":       map[string]any{"type": "string", "description": "Repository owner login"},
				"repo":        map[string]any{"type": "string", "description": "Repository name"},
				"pull_number": map[string]any{"type": "integer", "description": "Pull request number"},
			},
			"required": []string{"owner", "repo", "pull_number"},
		},
	},
}

func mcpRPCResult(id any, result any) []byte {
	return jsonResponse(200, "OK", map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
}

func mcpRPCError(status int, reason string, id any, code int, msg string) []byte {
	return jsonResponse(status, reason, map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	})
}

func mcpToolSuccess(id any, payload any) []byte {
	text, _ := json.Marshal(payload)
	return mcpRPCResult(id, map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": string(text)},
		},
		"structuredContent": payload,
		"isError":           false,
	})
}

func mcpToolError(id any, msg string) []byte {
	return mcpRPCResult(id, map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": msg},
		},
		"isError": true,
	})
}

func (srv *Server) handleMCP(body []byte) []byte {
	var rpc struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      any            `json:"id"`
		Method  string         `json:"method"`
		Params  map[string]any `json:"params"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		return mcpRPCError(400, "Bad Request", nil, -32700, "Parse error: invalid JSON")
	}

	switch rpc.Method {
	case "server/discover":
		return mcpRPCResult(rpc.ID, map[string]any{
			"supportedVersions": []string{"2026-07-28", "2025-11-25", "2025-06-18"},
			"capabilities":      map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":        map[string]any{"name": "hyperforge", "version": "1.0.0"},
		})

	case "initialize":
		proto := "2025-11-25"
		if p, ok := rpc.Params["protocolVersion"].(string); ok && p != "" {
			proto = p
		}
		return mcpRPCResult(rpc.ID, map[string]any{
			"protocolVersion": proto,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "hyperforge", "version": "1.0.0"},
		})

	case "notifications/initialized":
		return respNoContent

	case "ping":
		return mcpRPCResult(rpc.ID, map[string]any{})

	case "tools/list":
		return mcpRPCResult(rpc.ID, map[string]any{
			"tools": mcpToolsList,
		})

	case "tools/call":
		toolName, _ := rpc.Params["name"].(string)
		args, _ := rpc.Params["arguments"].(map[string]any)
		if args == nil {
			args = map[string]any{}
		}
		return srv.handleMCPToolCall(rpc.ID, toolName, args)

	default:
		return mcpRPCError(200, "OK", rpc.ID, -32601, fmt.Sprintf("Method not found: %s", rpc.Method))
	}
}

func mcpStr(args map[string]any, k string) string {
	if s, ok := args[k].(string); ok {
		return s
	}
	return ""
}

func mcpInt(args map[string]any, k string) (int, bool) {
	switch v := args[k].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case string:
		n, err := strconv.Atoi(v)
		return n, err == nil
	}
	return 0, false
}

func (srv *Server) handleMCPToolCall(id any, name string, args map[string]any) []byte {
	switch name {
	case "create_repo":
		rName := mcpStr(args, "name")
		if rName == "" {
			return mcpRPCError(200, "OK", id, -32602, "missing required argument: name")
		}
		desc := mcpStr(args, "description")
		priv, _ := args["private"].(bool)
		r, created := srv.store.CreateRepo(rName, desc, priv, "main")
		if !created {
			return mcpToolError(id, "repository already exists")
		}
		return mcpToolSuccess(id, repoToMap(r))

	case "get_repo":
		owner := mcpStr(args, "owner")
		rName := mcpStr(args, "repo")
		if owner == "" || rName == "" {
			return mcpRPCError(200, "OK", id, -32602, "missing required arguments: owner, repo")
		}
		r := srv.store.GetRepo(owner, rName)
		if r == nil {
			return mcpToolError(id, "repository not found")
		}
		r.mu.RLock()
		m := repoToMap(r)
		r.mu.RUnlock()
		return mcpToolSuccess(id, m)

	case "create_issue":
		owner := mcpStr(args, "owner")
		rName := mcpStr(args, "repo")
		title := mcpStr(args, "title")
		if owner == "" || rName == "" || title == "" {
			return mcpRPCError(200, "OK", id, -32602, "missing required arguments: owner, repo, title")
		}
		body := mcpStr(args, "body")
		r := srv.store.GetRepo(owner, rName)
		if r == nil {
			return mcpToolError(id, "repository not found")
		}
		gid := srv.store.NextIssueGlobalID()
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
		srv.store.RegisterIssueNode(r, iss)
		return mcpToolSuccess(id, map[string]any{
			"id":     iss.ID,
			"number": iss.Number,
			"title":  iss.Title,
			"body":   iss.Body,
			"state":  iss.State,
		})

	case "list_issues":
		owner := mcpStr(args, "owner")
		rName := mcpStr(args, "repo")
		if owner == "" || rName == "" {
			return mcpRPCError(200, "OK", id, -32602, "missing required arguments: owner, repo")
		}
		state := strings.ToLower(mcpStr(args, "state"))
		if state == "" {
			state = "open"
		}
		r := srv.store.GetRepo(owner, rName)
		if r == nil {
			return mcpToolError(id, "repository not found")
		}
		r.mu.RLock()
		items := make([]map[string]any, 0, len(r.Issues))
		for _, iss := range r.Issues {
			if state != "all" && iss.State != state {
				continue
			}
			items = append(items, map[string]any{
				"id":     iss.ID,
				"number": iss.Number,
				"title":  iss.Title,
				"body":   iss.Body,
				"state":  iss.State,
			})
		}
		r.mu.RUnlock()
		return mcpToolSuccess(id, map[string]any{"issues": items})

	case "create_pull_request":
		owner := mcpStr(args, "owner")
		rName := mcpStr(args, "repo")
		title := mcpStr(args, "title")
		head := mcpStr(args, "head")
		base := mcpStr(args, "base")
		if owner == "" || rName == "" || title == "" || head == "" || base == "" {
			return mcpRPCError(200, "OK", id, -32602, "missing required arguments: owner, repo, title, head, base")
		}
		body := mcpStr(args, "body")
		r := srv.store.GetRepo(owner, rName)
		if r == nil {
			return mcpToolError(id, "repository not found")
		}
		pr, errMsg, status := srv.createPullInternal(r, title, body, head, base)
		if status != 201 {
			return mcpToolError(id, errMsg)
		}
		r.mu.RLock()
		m := pullToMap(r, pr)
		r.mu.RUnlock()
		return mcpToolSuccess(id, m)

	case "merge_pull_request":
		owner := mcpStr(args, "owner")
		rName := mcpStr(args, "repo")
		num, okNum := mcpInt(args, "pull_number")
		if owner == "" || rName == "" || !okNum || num <= 0 {
			return mcpRPCError(200, "OK", id, -32602, "missing required arguments: owner, repo, pull_number")
		}
		r := srv.store.GetRepo(owner, rName)
		if r == nil {
			return mcpToolError(id, "repository not found")
		}
		sha, status, msg := srv.mergePullInternal(r, num)
		if status != 200 {
			return mcpToolError(id, msg)
		}
		return mcpToolSuccess(id, map[string]any{
			"sha":     sha,
			"merged":  true,
			"message": msg,
		})

	default:
		return mcpRPCError(200, "OK", id, -32601, fmt.Sprintf("Unknown tool: %s", name))
	}
}
