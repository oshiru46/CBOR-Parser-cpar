package format

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/oshiru/cbor-parser-cpar/internal/cbor"
	"github.com/oshiru/cbor-parser-cpar/internal/cose"
)

// RenderText renders the node tree as structured text.
func RenderText(node *cbor.Node, opts Options) string {
	var sb strings.Builder
	renderTextNode(&sb, node, 0, opts, labelContextNone)
	return sb.String()
}

type labelContext int

const (
	labelContextNone   labelContext = iota
	labelContextHeader             // COSE header map key
	labelContextKey                // COSE_Key map key
)

func indent(depth int) string {
	return strings.Repeat("  ", depth)
}

func renderTextNode(sb *strings.Builder, node *cbor.Node, depth int, opts Options, lctx labelContext) {
	if node == nil {
		sb.WriteString(indent(depth) + "null\n")
		return
	}

	// COSE overlay takes priority
	if node.COSE != nil {
		renderCOSENode(sb, node, depth, opts)
		return
	}

	switch node.Type {
	case cbor.TypeNull:
		sb.WriteString(indent(depth))
		if opts.ShowMetadata {
			sb.WriteString("null")
		} else {
			sb.WriteString("null")
		}
		sb.WriteString("\n")

	case cbor.TypeBool:
		sb.WriteString(indent(depth))
		if opts.ShowMetadata {
			sb.WriteString("bool ")
		}
		if node.Bool {
			sb.WriteString("true\n")
		} else {
			sb.WriteString("false\n")
		}

	case cbor.TypeUint:
		sb.WriteString(indent(depth))
		if opts.ShowMetadata {
			sb.WriteString("uint ")
		}
		sb.WriteString(fmt.Sprintf("%d\n", node.Uint))

	case cbor.TypeNint:
		sb.WriteString(indent(depth))
		if opts.ShowMetadata {
			sb.WriteString("nint ")
		}
		sb.WriteString(fmt.Sprintf("%d\n", node.Int))

	case cbor.TypeFloat:
		sb.WriteString(indent(depth))
		if opts.ShowMetadata {
			sb.WriteString("float ")
		}
		sb.WriteString(formatFloat(node.Float) + "\n")

	case cbor.TypeBigInt:
		sb.WriteString(indent(depth))
		if opts.ShowMetadata {
			sb.WriteString("bigint ")
		}
		sb.WriteString(node.BigInt.String() + "\n")

	case cbor.TypeBytes:
		sb.WriteString(indent(depth))
		if opts.ShowMetadata {
			sb.WriteString("bytes ")
		}
		sb.WriteString("h'" + hex.EncodeToString(node.Bytes) + "'\n")

	case cbor.TypeText:
		sb.WriteString(indent(depth))
		if opts.ShowMetadata {
			sb.WriteString("text ")
		}
		sb.WriteString(fmt.Sprintf("%q\n", node.Text))

	case cbor.TypeArray:
		sb.WriteString(indent(depth))
		if opts.ShowMetadata {
			if node.Indefinite {
				sb.WriteString("array (indefinite)\n")
			} else {
				sb.WriteString(fmt.Sprintf("array (len=%d)\n", len(node.Array)))
			}
		} else {
			sb.WriteString("array\n")
		}
		for _, child := range node.Array {
			renderTextNode(sb, child, depth+1, opts, labelContextNone)
		}

	case cbor.TypeMap:
		renderTextMap(sb, node, depth, opts, lctx)

	case cbor.TypeTag:
		renderTextTag(sb, node, depth, opts)

	case cbor.TypeUndef:
		sb.WriteString(indent(depth) + "undefined\n")
	}
}

func renderTextMap(sb *strings.Builder, node *cbor.Node, depth int, opts Options, lctx labelContext) {
	sb.WriteString(indent(depth))
	if opts.ShowMetadata {
		if node.Indefinite {
			sb.WriteString("map (indefinite)\n")
		} else {
			sb.WriteString(fmt.Sprintf("map (pairs=%d)\n", len(node.MapPairs)))
		}
	} else {
		sb.WriteString("map\n")
	}
	renderTextMapPairs(sb, node, depth+1, opts, lctx)
}

func renderTextMapPairs(sb *strings.Builder, node *cbor.Node, depth int, opts Options, lctx labelContext) {
	for _, pair := range node.MapPairs {
		k := pair.Key
		v := pair.Value
		prefix := indent(depth)

		intKey, label := intKeyLabel(k, lctx)
		if intKey != nil {
			var keyStr string
			if opts.ShowMetadata {
				if k.Type == cbor.TypeUint {
					keyStr = fmt.Sprintf("uint %d", k.Uint)
				} else {
					keyStr = fmt.Sprintf("nint %d", k.Int)
				}
			} else {
				if k.Type == cbor.TypeUint {
					keyStr = fmt.Sprintf("%d", k.Uint)
				} else {
					keyStr = fmt.Sprintf("%d", k.Int)
				}
			}
			if label != "" {
				keyStr += " (" + label + ")"
			}
			sb.WriteString(prefix + keyStr + ": ")
			renderTextValueInline(sb, v, depth, opts, labelContextNone)
		} else if k.Type == cbor.TypeText {
			if opts.ShowMetadata {
				sb.WriteString(prefix + "text " + fmt.Sprintf("%q", k.Text) + ": ")
			} else {
				sb.WriteString(prefix + fmt.Sprintf("%q", k.Text) + ": ")
			}
			renderTextValueInline(sb, v, depth, opts, labelContextNone)
		} else {
			renderTextNode(sb, k, depth, opts, labelContextNone)
			renderTextNode(sb, v, depth+1, opts, labelContextNone)
		}
	}
}

// renderTextValueInline tries to render the value on the same line as the key
// when it's a scalar, otherwise starts a new line and indents.
func renderTextValueInline(sb *strings.Builder, node *cbor.Node, depth int, opts Options, lctx labelContext) {
	if node == nil {
		sb.WriteString("null\n")
		return
	}
	if node.COSE != nil {
		sb.WriteString("\n")
		renderCOSENode(sb, node, depth+1, opts)
		return
	}
	switch node.Type {
	case cbor.TypeNull:
		sb.WriteString("null\n")
	case cbor.TypeBool:
		if node.Bool {
			sb.WriteString("true\n")
		} else {
			sb.WriteString("false\n")
		}
	case cbor.TypeUint:
		if opts.ShowMetadata {
			sb.WriteString(fmt.Sprintf("uint %d\n", node.Uint))
		} else {
			sb.WriteString(fmt.Sprintf("%d\n", node.Uint))
		}
	case cbor.TypeNint:
		if opts.ShowMetadata {
			sb.WriteString(fmt.Sprintf("nint %d\n", node.Int))
		} else {
			sb.WriteString(fmt.Sprintf("%d\n", node.Int))
		}
	case cbor.TypeFloat:
		if opts.ShowMetadata {
			sb.WriteString("float " + formatFloat(node.Float) + "\n")
		} else {
			sb.WriteString(formatFloat(node.Float) + "\n")
		}
	case cbor.TypeBigInt:
		sb.WriteString(node.BigInt.String() + "\n")
	case cbor.TypeBytes:
		if opts.ShowMetadata {
			sb.WriteString("bytes h'" + hex.EncodeToString(node.Bytes) + "'\n")
		} else {
			sb.WriteString("h'" + hex.EncodeToString(node.Bytes) + "'\n")
		}
	case cbor.TypeText:
		if opts.ShowMetadata {
			sb.WriteString("text " + fmt.Sprintf("%q\n", node.Text))
		} else {
			sb.WriteString(fmt.Sprintf("%q\n", node.Text))
		}
	case cbor.TypeArray:
		if opts.ShowMetadata {
			if node.Indefinite {
				sb.WriteString("array (indefinite)\n")
			} else {
				sb.WriteString(fmt.Sprintf("array (len=%d)\n", len(node.Array)))
			}
		} else {
			sb.WriteString("array\n")
		}
		for _, child := range node.Array {
			renderTextNode(sb, child, depth+1, opts, labelContextNone)
		}
	case cbor.TypeMap:
		if opts.ShowMetadata {
			if node.Indefinite {
				sb.WriteString("map (indefinite)\n")
			} else {
				sb.WriteString(fmt.Sprintf("map (pairs=%d)\n", len(node.MapPairs)))
			}
		} else {
			sb.WriteString("map\n")
		}
		renderTextMapPairs(sb, node, depth+1, opts, lctx)
	case cbor.TypeTag:
		if node.COSE != nil {
			sb.WriteString("\n")
			renderCOSENode(sb, node, depth+1, opts)
			return
		}
		sb.WriteString(fmt.Sprintf("tag %d", node.TagNumber))
		child := node.TagValue
		if child == nil {
			sb.WriteString("\n")
			return
		}
		if node.TagNumber == 24 && child.Type == cbor.TypeBytes {
			sb.WriteString(" h'" + hex.EncodeToString(child.Bytes) + "'\n")
			return
		}
		switch child.Type {
		case cbor.TypeNull, cbor.TypeBool, cbor.TypeUint, cbor.TypeNint,
			cbor.TypeFloat, cbor.TypeText, cbor.TypeBigInt:
			sb.WriteString(" ")
			renderTextValueInline(sb, child, depth, opts, labelContextNone)
		default:
			sb.WriteString("\n")
			renderTextNode(sb, child, depth+1, opts, labelContextNone)
		}
	default:
		sb.WriteString("\n")
		renderTextNode(sb, node, depth+1, opts, lctx)
	}
}

func renderTextTag(sb *strings.Builder, node *cbor.Node, depth int, opts Options) {
	// Non-COSE tag
	sb.WriteString(indent(depth) + fmt.Sprintf("tag %d", node.TagNumber))

	child := node.TagValue
	if child == nil {
		sb.WriteString("\n")
		return
	}

	// For tag-24 with disabled recursion, show bytes inline
	if node.TagNumber == 24 && child.Type == cbor.TypeBytes {
		sb.WriteString(" h'" + hex.EncodeToString(child.Bytes) + "'\n")
		return
	}

	// Scalar inline
	switch child.Type {
	case cbor.TypeNull, cbor.TypeBool, cbor.TypeUint, cbor.TypeNint,
		cbor.TypeFloat, cbor.TypeText, cbor.TypeBigInt:
		sb.WriteString(" ")
		renderTextValueInline(sb, child, depth, opts, labelContextNone)
	default:
		sb.WriteString("\n")
		renderTextNode(sb, child, depth+1, opts, labelContextNone)
	}
}

func renderCOSENode(sb *strings.Builder, node *cbor.Node, depth int, opts Options) {
	info := node.COSE
	typeName := cbor.COSETypeName(info.Type)

	if info.Inferred {
		sb.WriteString(indent(depth) + "untagged " + typeName + "\n")
	} else {
		tagNum := uint64(info.Type)
		sb.WriteString(indent(depth) + fmt.Sprintf("tag %d %s\n", tagNum, typeName))
	}

	d := depth + 1
	switch info.Type {
	case cbor.COSETypeSign1, cbor.COSETypeMac0, cbor.COSETypeSign1OrMac0:
		renderCOSEHeaderField(sb, "protected headers", info.ProtectedHeaders, info.ProtectedHeaderMap, d, opts)
		renderCOSEHeaderField(sb, "unprotected headers", info.UnprotectedHeaders, nil, d, opts)
		renderCOSEPayloadField(sb, node, d, opts)
		lastLabel := "signature"
		if info.Type == cbor.COSETypeMac0 {
			lastLabel = "tag"
		} else if info.Type == cbor.COSETypeSign1OrMac0 {
			lastLabel = "signature_or_tag"
		}
		renderCOSEField(sb, lastLabel, info.Signature, d, opts)

	case cbor.COSETypeEncrypt0:
		renderCOSEHeaderField(sb, "protected headers", info.ProtectedHeaders, info.ProtectedHeaderMap, d, opts)
		renderCOSEHeaderField(sb, "unprotected headers", info.UnprotectedHeaders, nil, d, opts)
		renderCOSEField(sb, "ciphertext", info.Ciphertext, d, opts)

	case cbor.COSETypeKey:
		// render the underlying map with key param labels
		var mapNode *cbor.Node
		if node.Type == cbor.TypeMap {
			mapNode = node
		} else if node.Type == cbor.TypeTag && node.TagValue != nil {
			mapNode = node.TagValue
		}
		if mapNode != nil {
			renderCOSEKeyMap(sb, mapNode, d, opts)
		}

	default:
		// Sign, Mac, Encrypt: render inner array
		var inner *cbor.Node
		if node.Type == cbor.TypeTag {
			inner = node.TagValue
		} else {
			inner = node
		}
		if inner != nil {
			renderTextNode(sb, inner, d, opts, labelContextNone)
		}
	}
}

func renderCOSEHeaderField(sb *strings.Builder, label string, raw, decoded *cbor.Node, depth int, opts Options) {
	sb.WriteString(indent(depth) + label)
	if opts.ShowMetadata && raw != nil && raw.Type == cbor.TypeBytes {
		sb.WriteString(fmt.Sprintf(" bytes (%d bytes)", len(raw.Bytes)))
	}
	sb.WriteString("\n")

	if decoded != nil {
		renderTextMapWithContext(sb, decoded, depth+1, opts, labelContextHeader)
	} else if raw != nil {
		renderTextNode(sb, raw, depth+1, opts, labelContextNone)
	}
}

func renderCOSEPayloadField(sb *strings.Builder, node *cbor.Node, depth int, opts Options) {
	info := node.COSE
	payload := info.Payload

	if payload == nil || payload.Type == cbor.TypeNull {
		sb.WriteString(indent(depth) + "payload\n")
		sb.WriteString(indent(depth+1) + "null\n")
		return
	}

	if info.PayloadEmbedded != nil {
		sb.WriteString(indent(depth) + "payload")
		if opts.ShowMetadata {
			sb.WriteString(" bytes (embedded CBOR)")
		} else {
			sb.WriteString(" (embedded CBOR)")
		}
		sb.WriteString("\n")
		renderTextNode(sb, info.PayloadEmbedded, depth+1, opts, labelContextNone)
		return
	}
	if info.PayloadEmbedFailed && opts.DecodeEmbeddedCBOR {
		sb.WriteString(indent(depth) + "payload\n")
		renderTextNode(sb, payload, depth+1, opts, labelContextNone)
		return
	}

	sb.WriteString(indent(depth) + "payload\n")
	renderTextNode(sb, payload, depth+1, opts, labelContextNone)
}

func renderCOSEField(sb *strings.Builder, label string, node *cbor.Node, depth int, opts Options) {
	sb.WriteString(indent(depth) + label + "\n")
	if node != nil {
		renderTextNode(sb, node, depth+1, opts, labelContextNone)
	}
}

func renderCOSEKeyMap(sb *strings.Builder, node *cbor.Node, depth int, opts Options) {
	for _, pair := range node.MapPairs {
		k := pair.Key
		v := pair.Value
		prefix := indent(depth)
		ik, _ := intKeyFromNode(k)
		if ik != nil {
			label := cose.KeyParamLabel(*ik)
			var keyStr string
			if opts.ShowMetadata {
				if k.Type == cbor.TypeUint {
					keyStr = fmt.Sprintf("uint %d", k.Uint)
				} else {
					keyStr = fmt.Sprintf("nint %d", k.Int)
				}
			} else {
				if k.Type == cbor.TypeUint {
					keyStr = fmt.Sprintf("%d", k.Uint)
				} else {
					keyStr = fmt.Sprintf("%d", k.Int)
				}
			}
			if label != "" {
				keyStr += " (" + label + ")"
			}
			sb.WriteString(prefix + keyStr + ": ")
			renderTextValueInline(sb, v, depth, opts, labelContextNone)
		} else {
			renderTextNode(sb, k, depth, opts, labelContextNone)
			renderTextNode(sb, v, depth+1, opts, labelContextNone)
		}
	}
}

func renderTextMapWithContext(sb *strings.Builder, node *cbor.Node, depth int, opts Options, lctx labelContext) {
	if node.Type != cbor.TypeMap {
		renderTextNode(sb, node, depth, opts, lctx)
		return
	}
	sb.WriteString(indent(depth))
	if opts.ShowMetadata {
		if node.Indefinite {
			sb.WriteString("map (indefinite)\n")
		} else {
			sb.WriteString(fmt.Sprintf("map (pairs=%d)\n", len(node.MapPairs)))
		}
	} else {
		sb.WriteString("map\n")
	}
	renderTextMapPairs(sb, node, depth+1, opts, lctx)
}

func intKeyLabel(n *cbor.Node, lctx labelContext) (*int64, string) {
	k, _ := intKeyFromNode(n)
	if k == nil {
		return nil, ""
	}
	var label string
	switch lctx {
	case labelContextHeader:
		label = cose.HeaderParamLabel(*k)
	case labelContextKey:
		label = cose.KeyParamLabel(*k)
	}
	return k, label
}

func intKeyFromNode(n *cbor.Node) (*int64, cbor.Type) {
	switch n.Type {
	case cbor.TypeUint:
		v := int64(n.Uint)
		return &v, cbor.TypeUint
	case cbor.TypeNint:
		return &n.Int, cbor.TypeNint
	}
	return nil, 0
}

func formatFloat(f float64) string {
	if math.IsInf(f, 1) {
		return "Infinity"
	}
	if math.IsInf(f, -1) {
		return "-Infinity"
	}
	if math.IsNaN(f) {
		return "NaN"
	}
	s := fmt.Sprintf("%g", f)
	return s
}
