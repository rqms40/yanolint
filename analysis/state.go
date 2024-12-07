package analysis

import (
	"fmt"
	"strings"

	"github.com/rqms40/yanolint/lsp"
)

type State struct {
	// Map of file names to contents
	Documents map[string]string
}

func NewState() State {
	return State{Documents: map[string]string{}}
}

func getDiagnosticsForFile(text string) []lsp.Diagnostic {
	diagnostics := []lsp.Diagnostic{}
	for row, line := range strings.Split(text, "\n") {
		for pattern, message := range VulnerabilityPatterns {
			if strings.Contains(line, pattern) {
				idx := strings.Index(line, pattern)
				cweInfo := GetCWEInfo(pattern)
				diagnostics = append(diagnostics, lsp.Diagnostic{
					Range:    LineRange(row, idx, idx+len(pattern)),
					Severity: 2, // 2 = Warning
					Source:   "YanoLint",
					Message:  fmt.Sprintf("%s\n%s", message, cweInfo),
				})
			}
		}
	}
	return diagnostics
}

func (s *State) OpenDocument(uri, text string) []lsp.Diagnostic {
	s.Documents[uri] = text

	return getDiagnosticsForFile(text)
}

func (s *State) UpdateDocument(uri, text string) []lsp.Diagnostic {
	s.Documents[uri] = text

	return getDiagnosticsForFile(text)
}

func (s *State) Hover(id int, uri string, position lsp.Position) lsp.HoverResponse {
	document := s.Documents[uri]

	return lsp.HoverResponse{
		Response: lsp.Response{
			RPC: "2.0",
			ID:  &id,
		},
		Result: lsp.HoverResult{
			Contents: fmt.Sprintf("File: %s, Characters: %d", uri, len(document)),
		},
	}
}

func (s *State) Definition(id int, uri string, position lsp.Position) lsp.DefinitionResponse {
	return lsp.DefinitionResponse{
		Response: lsp.Response{
			RPC: "2.0",
			ID:  &id,
		},
		Result: lsp.Location{
			URI: uri,
			Range: lsp.Range{
				Start: lsp.Position{
					Line:      position.Line - 1,
					Character: 0,
				},
				End: lsp.Position{
					Line:      position.Line - 1,
					Character: 0,
				},
			},
		},
	}
}

func (s *State) TextDocumentCodeAction(id int, uri string) lsp.TextDocumentCodeActionResponse {
	text := s.Documents[uri]

	actions := []lsp.CodeAction{}
	for row, line := range strings.Split(text, "\n") {
		for pattern := range VulnerabilityPatterns {
			idx := strings.Index(line, pattern)
			if idx >= 0 {
				replaceChange := map[string][]lsp.TextEdit{}
				replaceChange[uri] = []lsp.TextEdit{
					{
						Range:   LineRange(row, idx, idx+len(pattern)),
						NewText: "/* Consider safer code here */",
					},
				}

				actions = append(actions, lsp.CodeAction{
					Title: fmt.Sprintf("Secure usage of '%s'", pattern),
					Edit:  &lsp.WorkspaceEdit{Changes: replaceChange},
				})
			}
		}
	}

	response := lsp.TextDocumentCodeActionResponse{
		Response: lsp.Response{
			RPC: "2.0",
			ID:  &id,
		},
		Result: actions,
	}

	return response
}

func (s *State) TextDocumentCompletion(id int, uri string) lsp.CompletionResponse {
	items := []lsp.CompletionItem{
		{
			Label:         "YanoLint",
			Detail:        "Suggestions for writing secure code",
			Documentation: "Avoid risky code. YanoLint is here to guide you!",
		},
	}

	response := lsp.CompletionResponse{
		Response: lsp.Response{
			RPC: "2.0",
			ID:  &id,
		},
		Result: items,
	}

	return response
}

func LineRange(line, start, end int) lsp.Range {
	return lsp.Range{
		Start: lsp.Position{
			Line:      line,
			Character: start,
		},
		End: lsp.Position{
			Line:      line,
			Character: end,
		},
	}
}
