package cbor

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
)

// Decode parses raw CBOR bytes into a Node tree.
func Decode(data []byte) (*Node, error) {
	d := &cborDecoder{data: data}
	node, err := d.decode()
	if err != nil {
		return nil, fmt.Errorf("CBOR decode: %w", err)
	}
	return node, nil
}

// DecodeAll decodes all CBOR items from data (for streams).
func DecodeAll(data []byte) ([]*Node, error) {
	d := &cborDecoder{data: data}
	var nodes []*Node
	for d.pos < len(d.data) {
		node, err := d.decode()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

type cborDecoder struct {
	data []byte
	pos  int
}

func (d *cborDecoder) decode() (*Node, error) {
	if d.pos >= len(d.data) {
		return nil, io.EOF
	}

	b := d.data[d.pos]
	major := b >> 5
	info := b & 0x1f
	d.pos++

	switch major {
	case 0: // unsigned integer
		v, err := d.readArg(info)
		if err != nil {
			return nil, err
		}
		return &Node{Type: TypeUint, Uint: v}, nil

	case 1: // negative integer
		v, err := d.readArg(info)
		if err != nil {
			return nil, err
		}
		// Overflow guard: -1 - v where v > MaxInt64 doesn't fit in int64
		if v > math.MaxInt64 {
			n := new(big.Int).SetUint64(v)
			n.Add(n, big.NewInt(1))
			n.Neg(n)
			return &Node{Type: TypeBigInt, BigInt: n}, nil
		}
		return &Node{Type: TypeNint, Int: -1 - int64(v)}, nil

	case 2: // byte string
		return d.decodeBytes(info)

	case 3: // text string
		return d.decodeText(info)

	case 4: // array
		return d.decodeArray(info)

	case 5: // map
		return d.decodeMap(info)

	case 6: // tag
		if info == 31 {
			return nil, fmt.Errorf("CBOR: invalid additional info 31 for tag")
		}
		tagNum, err := d.readArg(info)
		if err != nil {
			return nil, err
		}
		return d.decodeTag(tagNum)

	case 7: // simple / float
		return d.decodeSimple(info)
	}

	return nil, fmt.Errorf("CBOR: unexpected major type %d", major)
}

// readArg reads the uint64 argument for the given additional info byte.
func (d *cborDecoder) readArg(info byte) (uint64, error) {
	switch {
	case info <= 23:
		return uint64(info), nil
	case info == 24:
		if d.pos >= len(d.data) {
			return 0, fmt.Errorf("CBOR: truncated 1-byte argument")
		}
		v := uint64(d.data[d.pos])
		d.pos++
		return v, nil
	case info == 25:
		if d.pos+2 > len(d.data) {
			return 0, fmt.Errorf("CBOR: truncated 2-byte argument")
		}
		v := uint64(binary.BigEndian.Uint16(d.data[d.pos : d.pos+2]))
		d.pos += 2
		return v, nil
	case info == 26:
		if d.pos+4 > len(d.data) {
			return 0, fmt.Errorf("CBOR: truncated 4-byte argument")
		}
		v := uint64(binary.BigEndian.Uint32(d.data[d.pos : d.pos+4]))
		d.pos += 4
		return v, nil
	case info == 27:
		if d.pos+8 > len(d.data) {
			return 0, fmt.Errorf("CBOR: truncated 8-byte argument")
		}
		v := binary.BigEndian.Uint64(d.data[d.pos : d.pos+8])
		d.pos += 8
		return v, nil
	}
	return 0, fmt.Errorf("CBOR: reserved or invalid additional info %d", info)
}

func (d *cborDecoder) decodeBytes(info byte) (*Node, error) {
	if info == 31 { // indefinite length
		var result []byte
		for {
			if d.pos >= len(d.data) {
				return nil, fmt.Errorf("CBOR: truncated indefinite-length byte string")
			}
			if d.data[d.pos] == 0xff {
				d.pos++
				break
			}
			b := d.data[d.pos]
			if b>>5 != 2 {
				return nil, fmt.Errorf("CBOR: non-bstr chunk in indefinite byte string")
			}
			d.pos++
			chunkLen, err := d.readArg(b & 0x1f)
			if err != nil {
				return nil, err
			}
			n := int(chunkLen)
			if d.pos+n > len(d.data) {
				return nil, fmt.Errorf("CBOR: truncated byte string chunk")
			}
			result = append(result, d.data[d.pos:d.pos+n]...)
			d.pos += n
		}
		return &Node{Type: TypeBytes, Bytes: result, Indefinite: true}, nil
	}

	length, err := d.readArg(info)
	if err != nil {
		return nil, err
	}
	n := int(length)
	if d.pos+n > len(d.data) {
		return nil, fmt.Errorf("CBOR: truncated byte string")
	}
	b := make([]byte, n)
	copy(b, d.data[d.pos:d.pos+n])
	d.pos += n
	return &Node{Type: TypeBytes, Bytes: b}, nil
}

func (d *cborDecoder) decodeText(info byte) (*Node, error) {
	if info == 31 { // indefinite length
		var result []byte
		for {
			if d.pos >= len(d.data) {
				return nil, fmt.Errorf("CBOR: truncated indefinite-length text string")
			}
			if d.data[d.pos] == 0xff {
				d.pos++
				break
			}
			b := d.data[d.pos]
			if b>>5 != 3 {
				return nil, fmt.Errorf("CBOR: non-tstr chunk in indefinite text string")
			}
			d.pos++
			chunkLen, err := d.readArg(b & 0x1f)
			if err != nil {
				return nil, err
			}
			n := int(chunkLen)
			if d.pos+n > len(d.data) {
				return nil, fmt.Errorf("CBOR: truncated text string chunk")
			}
			result = append(result, d.data[d.pos:d.pos+n]...)
			d.pos += n
		}
		return &Node{Type: TypeText, Text: string(result), Indefinite: true}, nil
	}

	length, err := d.readArg(info)
	if err != nil {
		return nil, err
	}
	n := int(length)
	if d.pos+n > len(d.data) {
		return nil, fmt.Errorf("CBOR: truncated text string")
	}
	s := string(d.data[d.pos : d.pos+n])
	d.pos += n
	return &Node{Type: TypeText, Text: s}, nil
}

func (d *cborDecoder) decodeArray(info byte) (*Node, error) {
	if info == 31 { // indefinite length
		var arr []*Node
		for {
			if d.pos >= len(d.data) {
				return nil, fmt.Errorf("CBOR: truncated indefinite-length array")
			}
			if d.data[d.pos] == 0xff {
				d.pos++
				break
			}
			child, err := d.decode()
			if err != nil {
				return nil, err
			}
			arr = append(arr, child)
		}
		return &Node{Type: TypeArray, Array: arr, Indefinite: true}, nil
	}

	length, err := d.readArg(info)
	if err != nil {
		return nil, err
	}
	arr := make([]*Node, int(length))
	for i := range arr {
		arr[i], err = d.decode()
		if err != nil {
			return nil, fmt.Errorf("CBOR: array item %d: %w", i, err)
		}
	}
	return &Node{Type: TypeArray, Array: arr}, nil
}

func (d *cborDecoder) decodeMap(info byte) (*Node, error) {
	if info == 31 { // indefinite length
		var pairs []MapPair
		for {
			if d.pos >= len(d.data) {
				return nil, fmt.Errorf("CBOR: truncated indefinite-length map")
			}
			if d.data[d.pos] == 0xff {
				d.pos++
				break
			}
			k, err := d.decode()
			if err != nil {
				return nil, err
			}
			v, err := d.decode()
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, MapPair{Key: k, Value: v})
		}
		return &Node{Type: TypeMap, MapPairs: pairs, Indefinite: true}, nil
	}

	length, err := d.readArg(info)
	if err != nil {
		return nil, err
	}
	pairs := make([]MapPair, int(length))
	for i := range pairs {
		var err2 error
		pairs[i].Key, err2 = d.decode()
		if err2 != nil {
			return nil, fmt.Errorf("CBOR: map key %d: %w", i, err2)
		}
		pairs[i].Value, err2 = d.decode()
		if err2 != nil {
			return nil, fmt.Errorf("CBOR: map value %d: %w", i, err2)
		}
	}
	return &Node{Type: TypeMap, MapPairs: pairs}, nil
}

func (d *cborDecoder) decodeTag(tagNum uint64) (*Node, error) {
	// Tag 2: positive bignum — bstr → *big.Int
	if tagNum == 2 {
		child, err := d.decode()
		if err != nil {
			return nil, err
		}
		if child.Type != TypeBytes {
			return nil, fmt.Errorf("CBOR: tag 2 bignum expects bstr")
		}
		return &Node{Type: TypeBigInt, BigInt: new(big.Int).SetBytes(child.Bytes)}, nil
	}

	// Tag 3: negative bignum — bstr → -(*big.Int)-1
	if tagNum == 3 {
		child, err := d.decode()
		if err != nil {
			return nil, err
		}
		if child.Type != TypeBytes {
			return nil, fmt.Errorf("CBOR: tag 3 bignum expects bstr")
		}
		n := new(big.Int).SetBytes(child.Bytes)
		n.Add(n, big.NewInt(1))
		n.Neg(n)
		return &Node{Type: TypeBigInt, BigInt: n}, nil
	}

	// All other tags (including tag 0/1 datetime): preserve original child as-is
	child, err := d.decode()
	if err != nil {
		return nil, err
	}
	return &Node{Type: TypeTag, TagNumber: tagNum, TagValue: child}, nil
}

func (d *cborDecoder) decodeSimple(info byte) (*Node, error) {
	switch info {
	case 20:
		return &Node{Type: TypeBool, Bool: false}, nil
	case 21:
		return &Node{Type: TypeBool, Bool: true}, nil
	case 22:
		return &Node{Type: TypeNull}, nil
	case 23:
		return &Node{Type: TypeUndef}, nil
	case 24: // 1-byte simple value (32–255): unassigned, treat as undefined
		if d.pos >= len(d.data) {
			return nil, fmt.Errorf("CBOR: truncated simple value")
		}
		d.pos++
		return &Node{Type: TypeUndef}, nil
	case 25: // float16
		if d.pos+2 > len(d.data) {
			return nil, fmt.Errorf("CBOR: truncated float16")
		}
		bits := binary.BigEndian.Uint16(d.data[d.pos : d.pos+2])
		d.pos += 2
		return &Node{Type: TypeFloat, Float: decodeFloat16(bits)}, nil
	case 26: // float32
		if d.pos+4 > len(d.data) {
			return nil, fmt.Errorf("CBOR: truncated float32")
		}
		bits := binary.BigEndian.Uint32(d.data[d.pos : d.pos+4])
		d.pos += 4
		return &Node{Type: TypeFloat, Float: float64(math.Float32frombits(bits))}, nil
	case 27: // float64
		if d.pos+8 > len(d.data) {
			return nil, fmt.Errorf("CBOR: truncated float64")
		}
		bits := binary.BigEndian.Uint64(d.data[d.pos : d.pos+8])
		d.pos += 8
		return &Node{Type: TypeFloat, Float: math.Float64frombits(bits)}, nil
	case 31:
		return nil, fmt.Errorf("CBOR: unexpected break code (0xff)")
	default:
		// Simple values 0–19: unassigned
		return &Node{Type: TypeUndef}, nil
	}
}

// decodeFloat16 converts a 16-bit IEEE 754 half-precision value to float64.
// exp=0:  subnormal  → value = mant × 2^(-24)
// exp=31: inf/NaN
// else:   normalized → value = (mant + 1024) × 2^(exp-25)
func decodeFloat16(bits uint16) float64 {
	sign := bits >> 15
	exp := int((bits >> 10) & 0x1f)
	mant := int(bits & 0x3ff)

	var f float64
	switch exp {
	case 0:
		f = float64(mant) * math.Pow(2, -24)
	case 31:
		if mant == 0 {
			f = math.Inf(1)
		} else {
			f = math.NaN()
		}
	default:
		f = float64(mant+1024) * math.Pow(2, float64(exp-25))
	}

	if sign == 1 {
		return -f
	}
	return f
}
