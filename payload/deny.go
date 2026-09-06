package payload

import "strings"

// DenyList decides which strings Walk leaves alone. It has two kinds of
// rules: leaf rules match the key of the string itself, subtree rules match
// an ancestor object and exclude everything below it.
type DenyList struct {
	// Keys are object keys whose string value is never visited, wherever the
	// key appears. Array indexes never match a key.
	Keys map[string]bool
	// Paths are dotted paths, without indexes, that are never visited; an
	// entry "metadata.user_id" matches Path{"metadata","user_id"}. Array
	// indexes in the actual path are skipped when matching, so
	// "messages.content" would match messages[3].content[0].
	Paths map[string]bool
	// BlockTypes are values of a "type" key that exclude the whole object
	// that carries them, for example "thinking" excludes the entire thinking
	// block with its text and signature.
	BlockTypes map[string]bool
	// ToolNameParents are object keys under which a "name" key is denied:
	// tools[].name, tool_use.name. A "name" elsewhere, such as in the text of
	// a message, is not a tool name and is visited.
	ToolNameParents map[string]bool
}

// DefaultDeny returns the deny list for the Anthropic Messages format. It
// covers, at least:
//
//	keys:        model, role, type, id, tool_use_id, signature, stop_reason,
//	             stop_sequence, cache_control, media_type
//	paths:       metadata.user_id, source.data (base64 image and document
//	             data), anthropic_version, service_tier
//	block types: thinking, redacted_thinking
//	tool names:  the "name" of tools[] entries and of tool_use,
//	             server_tool_use and mcp_tool_use blocks
//
// The system prompt, every message text, tool_result contents, tool_use
// input and tool descriptions are visited.
//
// One exception carves a hole into source.data: a document source may carry
// its content as plain text, {"type":"text","media_type":"text/plain",
// "data":"..."}, and that data is ordinary user text that must not leave the
// machine untouched. It is therefore visited when the source object's own
// "type" is "text"; a source of type "base64" stays denied.
func DefaultDeny() *DenyList {
	return &DenyList{
		Keys: map[string]bool{
			"model":         true,
			"role":          true,
			"type":          true,
			"id":            true,
			"tool_use_id":   true,
			"signature":     true,
			"stop_reason":   true,
			"stop_sequence": true,
			"cache_control": true,
			"media_type":    true,
		},
		Paths: map[string]bool{
			"metadata.user_id":  true,
			"source.data":       true,
			"anthropic_version": true,
			"service_tier":      true,
		},
		BlockTypes: map[string]bool{
			"thinking":          true,
			"redacted_thinking": true,
		},
		ToolNameParents: map[string]bool{
			"tools":           true,
			"tool_use":        true,
			"server_tool_use": true,
			"mcp_tool_use":    true,
		},
	}
}

// Denied reports whether the string at path inside a body is excluded.
// enclosingTypes are the "type" values of the objects on the way down, outer
// first, so a subtree rule can be applied without a second pass.
func (d *DenyList) Denied(path Path, enclosingTypes []string) bool {
	if d == nil || len(path) == 0 {
		return false
	}

	// Subtree rule: one block type anywhere above excludes everything below
	// it, text and signature alike.
	for _, t := range enclosingTypes {
		if d.BlockTypes[t] {
			return true
		}
	}

	leaf := path[len(path)-1]
	if !isIndex(leaf) && d.Keys[leaf] {
		return true
	}

	// A document source of type "text" carries user text in its "data", not
	// base64, so it is visited before the dotted rule can deny it. The
	// innermost enclosing type is the source object's own "type", which is
	// what tells this case from an image source of type "base64".
	if leaf == "data" && len(path) >= 2 && path[len(path)-2] == "source" &&
		len(enclosingTypes) > 0 && enclosingTypes[len(enclosingTypes)-1] == "text" {
		return false
	}

	// Dotted rule: the path with its array indexes removed, matched against
	// the entry and against every suffix of it at element boundaries. The
	// suffix is what lets a single entry "source.data" cover the image data
	// of any content block without naming the way down to it.
	if len(d.Paths) > 0 {
		parts := make([]string, 0, len(path))
		for _, elem := range path {
			if !isIndex(elem) {
				parts = append(parts, elem)
			}
		}
		for i := range parts {
			if d.Paths[strings.Join(parts[i:], ".")] {
				return true
			}
		}
	}

	// Tool names: either the enclosing collection says so, as in tools[].name,
	// or the enclosing object carries a block type that does, as in a tool_use
	// block. The second case only applies when the "name" sits directly in an
	// array element, which is where content blocks live; that keeps
	// tool_use.input.name, an ordinary argument, out of the deny list.
	if leaf == "name" && len(d.ToolNameParents) > 0 {
		for i := len(path) - 2; i >= 0; i-- {
			if isIndex(path[i]) {
				continue
			}
			if d.ToolNameParents[path[i]] {
				return true
			}
			break
		}
		if len(path) >= 2 && isIndex(path[len(path)-2]) && len(enclosingTypes) > 0 {
			if d.ToolNameParents[enclosingTypes[len(enclosingTypes)-1]] {
				return true
			}
		}
	}

	return false
}
