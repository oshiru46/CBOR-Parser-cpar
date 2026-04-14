package cbor

import (
	"fmt"
	"math/big"

	gocbor "github.com/fxamacker/cbor/v2"
)

// Decode parses raw CBOR bytes into a Node tree.
func Decode(data []byte) (*Node, error) {
	dm, err := gocbor.DecOptions{
		IndefLength:      gocbor.IndefLengthAllowed,
		IntDec:           gocbor.IntDecConvertNone,
		TagsMd:           gocbor.TagsAllowed,
		ExtraReturnErrors: gocbor.ExtraDecErrorNone,
	}.DecMode()
	if err != nil {
		return nil, err
	}

	var raw interface{}
	if err := dm.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("CBOR decode: %w", err)
	}
	return convertRaw(raw)
}

// DecodeAll decodes all CBOR items from data (for streams).
func DecodeAll(data []byte) ([]*Node, error) {
	dm, err := gocbor.DecOptions{
		IndefLength:      gocbor.IndefLengthAllowed,
		IntDec:           gocbor.IntDecConvertNone,
		TagsMd:           gocbor.TagsAllowed,
		ExtraReturnErrors: gocbor.ExtraDecErrorNone,
	}.DecMode()
	if err != nil {
		return nil, err
	}

	br := bytesReader(data)
	dec := dm.NewDecoder(&br)
	var nodes []*Node
	for {
		var raw interface{}
		if err := dec.Decode(&raw); err != nil {
			if err.Error() == "EOF" {
				break
			}
			// io.EOF check
			break
		}
		n, err := convertRaw(raw)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

func convertRaw(v interface{}) (*Node, error) {
	if v == nil {
		return &Node{Type: TypeNull}, nil
	}
	switch val := v.(type) {
	case bool:
		return &Node{Type: TypeBool, Bool: val}, nil
	case uint64:
		return &Node{Type: TypeUint, Uint: val}, nil
	case int64:
		n := &Node{Type: TypeNint, Int: val}
		return n, nil
	case float32:
		return &Node{Type: TypeFloat, Float: float64(val)}, nil
	case float64:
		return &Node{Type: TypeFloat, Float: val}, nil
	case []byte:
		return &Node{Type: TypeBytes, Bytes: val}, nil
	case string:
		return &Node{Type: TypeText, Text: val}, nil
	case *big.Int:
		return &Node{Type: TypeBigInt, BigInt: val}, nil
	case gocbor.Tag:
		child, err := convertRaw(val.Content)
		if err != nil {
			return nil, err
		}
		return &Node{Type: TypeTag, TagNumber: val.Number, TagValue: child}, nil
	case []interface{}:
		arr := make([]*Node, len(val))
		for i, item := range val {
			n, err := convertRaw(item)
			if err != nil {
				return nil, err
			}
			arr[i] = n
		}
		return &Node{Type: TypeArray, Array: arr}, nil
	case map[interface{}]interface{}:
		pairs := make([]MapPair, 0, len(val))
		for k, v := range val {
			kn, err := convertRaw(k)
			if err != nil {
				return nil, err
			}
			vn, err := convertRaw(v)
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, MapPair{Key: kn, Value: vn})
		}
		return &Node{Type: TypeMap, MapPairs: pairs}, nil
	case map[string]interface{}:
		pairs := make([]MapPair, 0, len(val))
		for k, v := range val {
			kn := &Node{Type: TypeText, Text: k}
			vn, err := convertRaw(v)
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, MapPair{Key: kn, Value: vn})
		}
		return &Node{Type: TypeMap, MapPairs: pairs}, nil
	default:
		return nil, fmt.Errorf("unsupported CBOR type %T", v)
	}
}

// bytesReader wraps a byte slice to implement io.Reader.
type bytesReader []byte

func (b *bytesReader) Read(p []byte) (int, error) {
	if len(*b) == 0 {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, *b)
	*b = (*b)[n:]
	return n, nil
}
