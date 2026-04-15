package cose

import (
	"github.com/oshiru/cbor-parser-cpar/internal/cbor"
)

// definedHeaderKeys lists IANA-registered COSE header parameter labels.
//   RFC 9052 §3.1 Table 2 : 1–7
//   RFC 8613 (OSCORE)      : 9
//   RFC 9360 §2            : 10–13, 33
//   RFC 9338               : 15
// Labels 8 (CounterSignature0, deprecated RFC 8152) and 14 (x5t_S256,
// draft-only, not in final RFC 9360) are intentionally excluded.
var definedHeaderKeys = map[int64]bool{
	1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true,
	9: true,
	10: true, 11: true, 12: true, 13: true,
	15: true,
	33: true,
}

// defined COSE_Key parameter keys (RFC 9052 Table 3 + curve params)
var definedKeyParams = map[int64]bool{
	1: true, 2: true, 3: true, 4: true, 5: true,
	-1: true, -2: true, -3: true, -4: true, -5: true, -6: true,
}

// kty required params per COSE_Key type value
var ktyRequiredParams = map[int64][]int64{
	1: {1, -1, -2},              // OKP
	2: {1, -1, -2, -3},          // EC2
	3: {1, -1, -2},              // RSA
	4: {1, -1},                  // Symmetric
}

// inferArray checks if node is an untagged COSE_Sign1_or_Mac0.
func inferArray(node *cbor.Node, opts Options) {
	if node.Type != cbor.TypeArray || len(node.Array) != 4 {
		return
	}
	el := node.Array
	// element 0: bstr (protected headers)
	if el[0].Type != cbor.TypeBytes {
		return
	}
	// element 1: map (unprotected headers)
	if el[1].Type != cbor.TypeMap {
		return
	}
	// element 2: bstr or null
	if el[2].Type != cbor.TypeBytes && el[2].Type != cbor.TypeNull {
		return
	}
	// element 3: bstr
	if el[3].Type != cbor.TypeBytes {
		return
	}
	// check protected header keys
	if len(el[0].Bytes) > 0 {
		m, err := cbor.Decode(el[0].Bytes)
		if err != nil || !allDefinedHeaderKeys(m) {
			return
		}
	}
	// check unprotected header keys
	if !allDefinedHeaderKeys(el[1]) {
		return
	}
	attachArray4COSE(node, node, cbor.COSETypeSign1OrMac0, true, opts)
}

// inferMap checks if node is an untagged COSE_Key.
func inferMap(node *cbor.Node, opts Options) {
	if node.Type != cbor.TypeMap {
		return
	}
	// Must have kty key (1)
	ktyNode := mapIntKey(node, 1)
	if ktyNode == nil {
		return
	}
	var kty int64
	switch ktyNode.Type {
	case cbor.TypeUint:
		kty = int64(ktyNode.Uint)
	case cbor.TypeNint:
		kty = ktyNode.Int
	default:
		return
	}
	required, ok := ktyRequiredParams[kty]
	if !ok {
		return // undefined kty
	}
	// check required keys present
	for _, req := range required {
		if mapIntKey(node, req) == nil {
			return
		}
	}
	// all keys must be defined
	for _, pair := range node.MapPairs {
		k := nodeIntKey(pair.Key)
		if k == nil {
			return
		}
		if !definedKeyParams[*k] {
			return
		}
	}
	attachKeyCOSE(node, node, true)
}

func allDefinedHeaderKeys(node *cbor.Node) bool {
	if node == nil || node.Type != cbor.TypeMap {
		return true // empty or nil = ok
	}
	for _, pair := range node.MapPairs {
		k := nodeIntKey(pair.Key)
		if k == nil {
			return false
		}
		if !definedHeaderKeys[*k] {
			return false
		}
	}
	return true
}

func mapIntKey(node *cbor.Node, key int64) *cbor.Node {
	for _, pair := range node.MapPairs {
		k := nodeIntKey(pair.Key)
		if k != nil && *k == key {
			return pair.Value
		}
	}
	return nil
}

func nodeIntKey(n *cbor.Node) *int64 {
	switch n.Type {
	case cbor.TypeUint:
		v := int64(n.Uint)
		return &v
	case cbor.TypeNint:
		return &n.Int
	}
	return nil
}
