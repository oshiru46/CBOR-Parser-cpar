package format

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"

	"github.com/oshiru/cbor-parser-cpar/internal/cbor"
	"github.com/oshiru/cbor-parser-cpar/internal/cose"
)

// RenderJSON renders the node as natural JSON (json mode).
func RenderJSON(node *cbor.Node, opts Options) ([]byte, error) {
	v := toJSONValue(node, opts)
	return json.MarshalIndent(v, "", "  ")
}

// RenderJSONVerbose renders the node as JSON AST (json-verbose mode).
func RenderJSONVerbose(node *cbor.Node, opts Options) ([]byte, error) {
	v := toJSONVerbose(node, opts)
	return json.MarshalIndent(v, "", "  ")
}

// ---- json mode ----

func toJSONValue(node *cbor.Node, opts Options) interface{} {
	if node == nil {
		return nil
	}
	if node.COSE != nil {
		return coseToJSON(node, opts)
	}
	switch node.Type {
	case cbor.TypeNull:
		return nil
	case cbor.TypeBool:
		return node.Bool
	case cbor.TypeUint:
		return node.Uint
	case cbor.TypeNint:
		return node.Int
	case cbor.TypeFloat:
		if math.IsInf(node.Float, 0) || math.IsNaN(node.Float) {
			return fmt.Sprintf("%g", node.Float)
		}
		return node.Float
	case cbor.TypeBigInt:
		return node.BigInt.String()
	case cbor.TypeBytes:
		return base64.StdEncoding.EncodeToString(node.Bytes)
	case cbor.TypeText:
		return node.Text
	case cbor.TypeArray:
		arr := make([]interface{}, len(node.Array))
		for i, child := range node.Array {
			arr[i] = toJSONValue(child, opts)
		}
		return arr
	case cbor.TypeMap:
		return mapToJSONNatural(node, opts)
	case cbor.TypeTag:
		// strip tag, return inner value
		if node.TagValue != nil {
			return toJSONValue(node.TagValue, opts)
		}
		return nil
	}
	return nil
}

func mapToJSONNatural(node *cbor.Node, opts Options) interface{} {
	m := make(map[string]interface{}, len(node.MapPairs))
	for _, pair := range node.MapPairs {
		key := jsonKeyString(pair.Key)
		m[key] = toJSONValue(pair.Value, opts)
	}
	return m
}

func coseToJSON(node *cbor.Node, opts Options) interface{} {
	info := node.COSE
	typeName := cbor.COSETypeName(info.Type)
	m := make(map[string]interface{})

	// For inferred/untagged types, include _type for identification
	if info.Inferred {
		m["_type"] = typeName
	}

	switch info.Type {
	case cbor.COSETypeSign1, cbor.COSETypeMac0, cbor.COSETypeSign1OrMac0:
		m["protected_headers"] = coseHeaderToJSON(info, opts)
		m["unprotected_headers"] = toJSONValue(info.UnprotectedHeaders, opts)
		m["payload"] = cosePayloadToJSON(info, opts)
		lastKey := "signature"
		if info.Type == cbor.COSETypeMac0 {
			lastKey = "tag"
		} else if info.Type == cbor.COSETypeSign1OrMac0 {
			lastKey = "signature_or_tag"
		}
		m[lastKey] = toJSONValue(info.Signature, opts)

	case cbor.COSETypeEncrypt0:
		m["protected_headers"] = coseHeaderToJSON(info, opts)
		m["unprotected_headers"] = toJSONValue(info.UnprotectedHeaders, opts)
		m["ciphertext"] = toJSONValue(info.Ciphertext, opts)

	case cbor.COSETypeKey:
		var mapNode *cbor.Node
		if node.Type == cbor.TypeMap {
			mapNode = node
		} else if node.Type == cbor.TypeTag && node.TagValue != nil {
			mapNode = node.TagValue
		}
		if mapNode != nil {
			for _, pair := range mapNode.MapPairs {
				key := jsonKeyString(pair.Key)
				m[key] = toJSONValue(pair.Value, opts)
			}
		}

	default:
		var inner *cbor.Node
		if node.Type == cbor.TypeTag {
			inner = node.TagValue
		} else {
			inner = node
		}
		return toJSONValue(inner, opts)
	}
	return m
}

func coseHeaderToJSON(info *cbor.COSEInfo, opts Options) interface{} {
	if info.ProtectedHeaderMap != nil {
		return toJSONValue(info.ProtectedHeaderMap, opts)
	}
	if info.ProtectedHeaders != nil && info.ProtectedHeaders.Type == cbor.TypeBytes {
		return base64.StdEncoding.EncodeToString(info.ProtectedHeaders.Bytes)
	}
	return nil
}

func cosePayloadToJSON(info *cbor.COSEInfo, opts Options) interface{} {
	if info.PayloadEmbedded != nil {
		return toJSONValue(info.PayloadEmbedded, opts)
	}
	return toJSONValue(info.Payload, opts)
}

// ---- json-verbose mode ----

func toJSONVerbose(node *cbor.Node, opts Options) interface{} {
	if node == nil {
		return nil
	}
	if node.COSE != nil {
		return coseToJSONVerbose(node, opts)
	}
	switch node.Type {
	case cbor.TypeNull:
		return map[string]interface{}{"_type": "null"}
	case cbor.TypeBool:
		return map[string]interface{}{"_type": "bool", "value": node.Bool}
	case cbor.TypeUint:
		return map[string]interface{}{"_type": "uint", "value": node.Uint}
	case cbor.TypeNint:
		return map[string]interface{}{"_type": "nint", "value": node.Int}
	case cbor.TypeFloat:
		var v interface{}
		if math.IsInf(node.Float, 0) || math.IsNaN(node.Float) {
			v = fmt.Sprintf("%g", node.Float)
		} else {
			v = node.Float
		}
		return map[string]interface{}{"_type": "float", "value": v}
	case cbor.TypeBigInt:
		return map[string]interface{}{"_type": "bigint", "value": node.BigInt.String()}
	case cbor.TypeBytes:
		return map[string]interface{}{
			"_type": "bytes",
			"value": base64.StdEncoding.EncodeToString(node.Bytes),
		}
	case cbor.TypeText:
		return map[string]interface{}{"_type": "text", "value": node.Text}
	case cbor.TypeArray:
		arr := make([]interface{}, len(node.Array))
		for i, child := range node.Array {
			arr[i] = toJSONVerbose(child, opts)
		}
		res := map[string]interface{}{"_type": "array", "value": arr}
		if node.Indefinite {
			res["_encoding"] = "indefinite"
		}
		return res
	case cbor.TypeMap:
		return mapToJSONVerbose(node, opts)
	case cbor.TypeTag:
		inner := toJSONVerbose(node.TagValue, opts)
		if m, ok := inner.(map[string]interface{}); ok {
			m["_tag"] = node.TagNumber
			return m
		}
		return map[string]interface{}{
			"_tag":   node.TagNumber,
			"_value": inner,
		}
	}
	return nil
}

func mapToJSONVerbose(node *cbor.Node, opts Options) interface{} {
	inner := make(map[string]interface{}, len(node.MapPairs))
	for _, pair := range node.MapPairs {
		key := jsonKeyString(pair.Key)
		inner[key] = toJSONVerbose(pair.Value, opts)
	}
	res := map[string]interface{}{"_type": "map", "value": inner}
	if node.Indefinite {
		res["_encoding"] = "indefinite"
	}
	return res
}

func coseToJSONVerbose(node *cbor.Node, opts Options) interface{} {
	info := node.COSE
	typeName := cbor.COSETypeName(info.Type)
	m := make(map[string]interface{})
	m["_type"] = typeName
	if !info.Inferred {
		m["_tag"] = uint64(info.Type)
	}

	switch info.Type {
	case cbor.COSETypeSign1, cbor.COSETypeMac0, cbor.COSETypeSign1OrMac0:
		m["protected_headers"] = coseHeaderToJSONVerbose(info, opts)
		m["unprotected_headers"] = mapPairsToJSONVerbose(info.UnprotectedHeaders, opts)
		m["payload"] = cosePayloadToJSONVerbose(info, opts)
		lastKey := "signature"
		if info.Type == cbor.COSETypeMac0 {
			lastKey = "tag"
		} else if info.Type == cbor.COSETypeSign1OrMac0 {
			lastKey = "signature_or_tag"
		}
		m[lastKey] = toJSONVerbose(info.Signature, opts)

	case cbor.COSETypeEncrypt0:
		m["protected_headers"] = coseHeaderToJSONVerbose(info, opts)
		m["unprotected_headers"] = mapPairsToJSONVerbose(info.UnprotectedHeaders, opts)
		m["ciphertext"] = toJSONVerbose(info.Ciphertext, opts)

	case cbor.COSETypeKey:
		var mapNode *cbor.Node
		if node.Type == cbor.TypeMap {
			mapNode = node
		} else if node.Type == cbor.TypeTag && node.TagValue != nil {
			mapNode = node.TagValue
		}
		if mapNode != nil {
			for _, pair := range mapNode.MapPairs {
				key := jsonKeyString(pair.Key)
				m[key] = toJSONVerbose(pair.Value, opts)
			}
		}

	default:
		var inner *cbor.Node
		if node.Type == cbor.TypeTag {
			inner = node.TagValue
		} else {
			inner = node
		}
		return toJSONVerbose(inner, opts)
	}
	return m
}

func coseHeaderToJSONVerbose(info *cbor.COSEInfo, opts Options) interface{} {
	if info.ProtectedHeaderMap != nil {
		return mapPairsToJSONVerbose(info.ProtectedHeaderMap, opts)
	}
	if info.ProtectedHeaders != nil {
		return toJSONVerbose(info.ProtectedHeaders, opts)
	}
	return nil
}

// mapPairsToJSONVerbose renders a map's key-value pairs with verbose values
// but without wrapping the map itself in {_type, value}.
func mapPairsToJSONVerbose(node *cbor.Node, opts Options) interface{} {
	if node == nil || node.Type != cbor.TypeMap {
		return toJSONVerbose(node, opts)
	}
	m := make(map[string]interface{}, len(node.MapPairs))
	for _, pair := range node.MapPairs {
		key := jsonKeyString(pair.Key)
		m[key] = toJSONVerbose(pair.Value, opts)
	}
	return m
}

func cosePayloadToJSONVerbose(info *cbor.COSEInfo, opts Options) interface{} {
	if info.Payload == nil || info.Payload.Type == cbor.TypeNull {
		return map[string]interface{}{"_type": "null"}
	}
	if info.PayloadEmbedded != nil {
		var embVal interface{}
		if info.PayloadEmbedded.Type == cbor.TypeMap {
			embVal = mapPairsToJSONVerbose(info.PayloadEmbedded, opts)
		} else {
			embVal = toJSONVerbose(info.PayloadEmbedded, opts)
		}
		return map[string]interface{}{
			"_type":          "bytes",
			"_embedded_cbor": true,
			"value":          embVal,
		}
	}
	if info.PayloadEmbedFailed {
		return map[string]interface{}{
			"_type":          "bytes",
			"_embedded_cbor": false,
			"_note":          "not valid CBOR",
			"value":          base64.StdEncoding.EncodeToString(info.Payload.Bytes),
		}
	}
	return toJSONVerbose(info.Payload, opts)
}

func jsonKeyString(n *cbor.Node) string {
	switch n.Type {
	case cbor.TypeText:
		return n.Text
	case cbor.TypeUint:
		return fmt.Sprintf("%d", n.Uint)
	case cbor.TypeNint:
		return fmt.Sprintf("%d", n.Int)
	default:
		return fmt.Sprintf("<%s>", cose.KeyParamLabel(0))
	}
}
