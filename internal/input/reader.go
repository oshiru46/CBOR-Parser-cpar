package input

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
)

type Format string

const (
	FormatAuto     Format = "auto"
	FormatBinary   Format = "binary"
	FormatHex      Format = "hex"
	FormatBase64   Format = "base64"
	FormatBase64URL Format = "base64url"
)

var hexRegexp     = regexp.MustCompile(`^[0-9a-fA-F]+$`)
var base64URLOnly = regexp.MustCompile(`^[A-Za-z0-9\-_]+$`)
var base64Std     = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)

// Read reads bytes from stdin and decodes according to the specified format.
func Read(format Format) ([]byte, error) {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	if format == FormatAuto {
		format = detect(raw)
	}

	return decode(raw, format)
}

// ReadString decodes CBOR data provided directly as a string argument.
func ReadString(data string, format Format) ([]byte, error) {
	raw := []byte(data)

	if format == FormatAuto {
		format = detect(raw)
	}

	return decode(raw, format)
}

// detect applies the priority rules from PLAN.md.
func detect(data []byte) Format {
	s := string(data)
	// Strip trailing newline for text-based formats
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}

	// 1. hex: even length, all [0-9a-fA-F]
	if len(s)%2 == 0 && len(s) > 0 && hexRegexp.MatchString(s) {
		return FormatHex
	}
	// 2. base64url: [A-Za-z0-9-_] only, no padding
	if base64URLOnly.MatchString(s) && len(s) > 0 {
		return FormatBase64URL
	}
	// 3. base64: [A-Za-z0-9+/] with optional padding
	if base64Std.MatchString(s) && len(s) > 0 {
		return FormatBase64
	}
	// 4. binary fallback
	return FormatBinary
}

func decode(data []byte, format Format) ([]byte, error) {
	s := string(data)
	// Strip trailing newline for text-based formats
	if format != FormatBinary && len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}

	switch format {
	case FormatBinary:
		return data, nil
	case FormatHex:
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("hex decode: %w", err)
		}
		return b, nil
	case FormatBase64:
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			// try without padding
			b, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return nil, fmt.Errorf("base64 decode: %w", err)
			}
		}
		return b, nil
	case FormatBase64URL:
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			// try with padding
			b, err = base64.URLEncoding.DecodeString(s)
			if err != nil {
				return nil, fmt.Errorf("base64url decode: %w", err)
			}
		}
		return b, nil
	default:
		return nil, fmt.Errorf("unknown format: %s", format)
	}
}
