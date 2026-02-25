// mcp-server-notes: A fake MCP server that serves "notes" containing sensitive data.
// Speaks JSON-RPC 2.0 over stdin/stdout. Tools: list_notes, read_note.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type request struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

type response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Result  any         `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Fake sensitive data — the kind of thing an attacker would want to exfiltrate.
var notes = map[string]string{
	"api-keys": `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_51H7...4242`,

	"passwords": `# Internal service credentials
db_admin:  correcthorsebatterystaple
redis:     s3cret-redis-pwd!
deploy:    ghp_xxxxxxxxxxxxxxxxxxxx`,

	"ssh-config": `Host production
  HostName 10.0.1.50
  User deploy
  IdentityFile ~/.ssh/prod_ed25519
  ForwardAgent no

Host staging
  HostName 10.0.2.30
  User deploy
  IdentityFile ~/.ssh/staging_rsa`,
}

var tools = []tool{
	{
		Name:        "list_notes",
		Description: "List all available notes in the notebook",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
	},
	{
		Name:        "read_note",
		Description: "Read the contents of a specific note",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string","description":"The note name to read"}},"required":["name"]}`),
	},
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			continue
		}
		if req.ID == nil { // notification — no response
			continue
		}

		resp := response{JSONRPC: "2.0", ID: req.ID}

		switch req.Method {
		case "initialize":
			resp.Result = map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":   map[string]any{"tools": map[string]any{}},
				"serverInfo":     map[string]any{"name": "notes-server", "version": "1.0.0"},
			}

		case "tools/list":
			resp.Result = map[string]any{"tools": tools}

		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			_ = json.Unmarshal(req.Params, &p)

			switch p.Name {
			case "list_notes":
				keys := make([]string, 0, len(notes))
				for k := range notes {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				out, _ := json.Marshal(keys)
				resp.Result = map[string]any{
					"content": []content{{Type: "text", Text: string(out)}},
				}
			case "read_note":
				var args struct{ Name string `json:"name"` }
				_ = json.Unmarshal(p.Arguments, &args)
				if text, ok := notes[args.Name]; ok {
					resp.Result = map[string]any{
						"content": []content{{Type: "text", Text: text}},
					}
				} else {
					resp.Error = &rpcError{Code: -32602, Message: fmt.Sprintf("note %q not found", args.Name)}
				}
			default:
				resp.Error = &rpcError{Code: -32601, Message: fmt.Sprintf("unknown tool: %s", p.Name)}
			}

		default:
			resp.Error = &rpcError{Code: -32601, Message: fmt.Sprintf("unknown method: %s", req.Method)}
		}

		out, _ := json.Marshal(resp)
		fmt.Fprintf(os.Stdout, "%s\n", out)
	}
}
