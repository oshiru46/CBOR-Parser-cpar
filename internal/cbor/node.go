package cbor

import "math/big"

// Type represents a CBOR major type or special value.
type Type int

const (
	TypeUint    Type = iota // major 0
	TypeNint                // major 1 (negative int)
	TypeBytes               // major 2
	TypeText                // major 3
	TypeArray               // major 4
	TypeMap                 // major 5
	TypeTag                 // major 6
	TypeBool                // simple: true/false
	TypeNull                // simple: null
	TypeUndef               // simple: undefined
	TypeFloat               // float16/32/64
	TypeBigInt              // tag 2/3 bignums
)

// MapPair holds an ordered key-value pair (preserves CBOR map order).
type MapPair struct {
	Key   *Node
	Value *Node
}

// Node is a decoded CBOR value tree.
type Node struct {
	Type Type

	// Scalar values
	Uint    uint64
	Int     int64   // for Nint: actual negative value (e.g. -7)
	Float   float64
	Bool    bool
	Bytes   []byte
	Text    string
	BigInt  *big.Int

	// Container values
	Array    []*Node
	MapPairs []MapPair // ordered map entries

	// Tag
	TagNumber uint64
	TagValue  *Node

	// Encoding metadata
	Indefinite bool // true if encoded with indefinite length

	// COSE overlay (set by cose package)
	COSE *COSEInfo
}

// COSEInfo carries COSE-specific interpretation layered on top of the raw node.
type COSEInfo struct {
	Type     COSEType
	Inferred bool // true if type was inferred (untagged)

	ProtectedHeaders   *Node
	ProtectedHeaderMap *Node // decoded from protected bstr
	UnprotectedHeaders *Node
	Payload            *Node  // nil means detached
	PayloadEmbedded    *Node  // set by -e if payload decoded as CBOR
	PayloadEmbedFailed bool
	// Sign1 / Sign1_or_Mac0
	Signature *Node
	// Mac0 / Sign1_or_Mac0
	// (reuses Signature field; label depends on COSEType)
	// Encrypt0
	Ciphertext *Node
}

// COSEType identifies the COSE message type.
type COSEType int

const (
	COSETypeUnknown      COSEType = 0
	COSETypeSign1        COSEType = 18
	COSETypeMac0         COSEType = 17
	COSETypeEncrypt0     COSEType = 16
	COSETypeSign         COSEType = 98
	COSETypeMac          COSEType = 97
	COSETypeEncrypt      COSEType = 96
	COSETypeKey          COSEType = -1
	COSETypeSign1OrMac0  COSEType = -10 // inferred, ambiguous
)

// COSETagMap maps CBOR tag numbers to COSEType.
var COSETagMap = map[uint64]COSEType{
	16: COSETypeEncrypt0,
	17: COSETypeMac0,
	18: COSETypeSign1,
	96: COSETypeEncrypt,
	97: COSETypeMac,
	98: COSETypeSign,
}

// COSETypeName returns the display name for a COSE type.
func COSETypeName(t COSEType) string {
	switch t {
	case COSETypeSign1:
		return "COSE_Sign1"
	case COSETypeMac0:
		return "COSE_Mac0"
	case COSETypeEncrypt0:
		return "COSE_Encrypt0"
	case COSETypeSign:
		return "COSE_Sign"
	case COSETypeMac:
		return "COSE_Mac"
	case COSETypeEncrypt:
		return "COSE_Encrypt"
	case COSETypeKey:
		return "COSE_Key"
	case COSETypeSign1OrMac0:
		return "COSE_Sign1_or_Mac0"
	default:
		return ""
	}
}
