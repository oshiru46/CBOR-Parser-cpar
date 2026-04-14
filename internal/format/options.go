package format

// Options holds rendering options.
type Options struct {
	ShowMetadata       bool
	DecodeEmbeddedCBOR bool
	DisableTag24       bool
	InferCOSEUntagged  bool
}
