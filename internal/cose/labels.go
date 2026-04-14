package cose

// headerParamName returns the standard name for a COSE header parameter key.
func headerParamName(key int64) string {
	switch key {
	case 1:
		return "alg"
	case 2:
		return "crit"
	case 3:
		return "content_type"
	case 4:
		return "kid"
	case 5:
		return "IV"
	case 6:
		return "Partial_IV"
	case 7:
		return "counter_signature"
	case 8:
		return "CounterSignature0"
	case 9:
		return "kid_context"
	case 10:
		return "x5bag"
	case 11:
		return "x5chain"
	case 12:
		return "x5t"
	case 13:
		return "x5u"
	case 14:
		return "x5t_S256"
	case 15:
		return "Countersignature version 2"
	default:
		return ""
	}
}

// keyParamName returns the standard name for a COSE_Key parameter key.
func keyParamName(key int64) string {
	switch key {
	case 1:
		return "kty"
	case 2:
		return "kid"
	case 3:
		return "alg"
	case 4:
		return "key_ops"
	case 5:
		return "Base_IV"
	case -1:
		return "crv"
	case -2:
		return "x"
	case -3:
		return "y"
	case -4:
		return "d"
	case -5:
		return "k"
	case -6:
		return "e"
	default:
		return ""
	}
}

// IntKeyLabel returns the standard label for a CBOR integer map key,
// depending on context (header or key parameter).
func HeaderParamLabel(key int64) string { return headerParamName(key) }
func KeyParamLabel(key int64) string    { return keyParamName(key) }
