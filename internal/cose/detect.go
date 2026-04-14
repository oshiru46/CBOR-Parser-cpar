// Package cose implements COSE type detection, inference, and payload processing.
package cose

import (
	"github.com/oshiru/cbor-parser-cpar/internal/cbor"
)

// Options controls COSE processing behaviour.
type Options struct {
	InferUntagged      bool
	DecodeEmbeddedCBOR bool
	DisableTag24       bool
}

// Process walks the node tree, attaches COSEInfo where applicable, and
// optionally decodes embedded CBOR payloads and tag-24 values.
func Process(node *cbor.Node, opts Options) {
	processNode(node, opts)
}

func processNode(node *cbor.Node, opts Options) {
	if node == nil {
		return
	}

	switch node.Type {
	case cbor.TypeTag:
		// ③ tagged COSE detection
		if ct, ok := cbor.COSETagMap[node.TagNumber]; ok {
			attachCOSE(node, ct, false, opts)
		}
		// ⑥ tag-24 recursive parse (after COSE/embed handling)
		if node.TagNumber == 24 && !opts.DisableTag24 {
			if node.TagValue != nil && node.TagValue.Type == cbor.TypeBytes {
				decoded, err := cbor.Decode(node.TagValue.Bytes)
				if err == nil {
					processNode(decoded, opts)
					node.TagValue = decoded
				}
			}
		} else {
			processNode(node.TagValue, opts)
		}

	case cbor.TypeArray:
		// ④ untagged COSE inference
		if opts.InferUntagged && node.COSE == nil {
			inferArray(node, opts)
		}
		if node.COSE == nil {
			for _, child := range node.Array {
				processNode(child, opts)
			}
		}

	case cbor.TypeMap:
		// ④ untagged COSE key inference
		if opts.InferUntagged && node.COSE == nil {
			inferMap(node, opts)
		}
		if node.COSE == nil {
			for _, pair := range node.MapPairs {
				processNode(pair.Key, opts)
				processNode(pair.Value, opts)
			}
		}
	}
}

// attachCOSE sets up COSEInfo on a tagged or inferred COSE node.
func attachCOSE(node *cbor.Node, ct cbor.COSEType, inferred bool, opts Options) {
	var inner *cbor.Node
	if node.Type == cbor.TypeTag {
		inner = node.TagValue
	} else {
		inner = node
	}

	switch ct {
	case cbor.COSETypeSign1, cbor.COSETypeMac0, cbor.COSETypeSign1OrMac0:
		attachArray4COSE(node, inner, ct, inferred, opts)
	case cbor.COSETypeEncrypt0:
		attachArray3COSE(node, inner, ct, inferred, opts)
	case cbor.COSETypeKey:
		attachKeyCOSE(node, inner, inferred)
	default:
		// Sign, Mac, Encrypt — attach minimal info, recurse children
		if inner != nil && inner.Type == cbor.TypeArray {
			node.COSE = &cbor.COSEInfo{Type: ct, Inferred: inferred}
		}
	}
}

func attachArray4COSE(node, inner *cbor.Node, ct cbor.COSEType, inferred bool, opts Options) {
	if inner == nil || inner.Type != cbor.TypeArray || len(inner.Array) != 4 {
		return
	}
	el := inner.Array
	info := &cbor.COSEInfo{
		Type:               ct,
		Inferred:           inferred,
		ProtectedHeaders:   el[0],
		UnprotectedHeaders: el[1],
		Payload:            el[2],
		Signature:          el[3],
	}
	// decode protected header bstr
	if el[0].Type == cbor.TypeBytes && len(el[0].Bytes) > 0 {
		if m, err := cbor.Decode(el[0].Bytes); err == nil {
			info.ProtectedHeaderMap = m
		}
	}
	// ⑤ embedded CBOR decode for payload
	if opts.DecodeEmbeddedCBOR && el[2] != nil && el[2].Type == cbor.TypeBytes {
		if decoded, err := cbor.Decode(el[2].Bytes); err == nil {
			processNode(decoded, opts)
			info.PayloadEmbedded = decoded
		} else {
			info.PayloadEmbedFailed = true
		}
	}
	node.COSE = info
}

func attachArray3COSE(node, inner *cbor.Node, ct cbor.COSEType, inferred bool, opts Options) {
	if inner == nil || inner.Type != cbor.TypeArray || len(inner.Array) != 3 {
		return
	}
	el := inner.Array
	info := &cbor.COSEInfo{
		Type:               ct,
		Inferred:           inferred,
		ProtectedHeaders:   el[0],
		UnprotectedHeaders: el[1],
		Ciphertext:         el[2],
	}
	if el[0].Type == cbor.TypeBytes && len(el[0].Bytes) > 0 {
		if m, err := cbor.Decode(el[0].Bytes); err == nil {
			info.ProtectedHeaderMap = m
		}
	}
	// Do NOT decode ciphertext with -e (encrypted payload)
	node.COSE = info
}

func attachKeyCOSE(node, inner *cbor.Node, inferred bool) {
	if inner == nil || inner.Type != cbor.TypeMap {
		return
	}
	node.COSE = &cbor.COSEInfo{Type: cbor.COSETypeKey, Inferred: inferred}
}
