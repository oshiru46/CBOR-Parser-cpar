package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/oshiru/cbor-parser-cpar/internal/cbor"
	"github.com/oshiru/cbor-parser-cpar/internal/cose"
	"github.com/oshiru/cbor-parser-cpar/internal/format"
	"github.com/oshiru/cbor-parser-cpar/internal/input"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "cpar: %v\n", err)
		os.Exit(1)
	}
}

type cliOptions struct {
	inputFormat       string
	outputFormat      string
	disableTag24      bool
	inferCOSEUntagged bool
	showMetadata      bool
	decodeEmbedded    bool
}

func newRootCmd() *cobra.Command {
	var opts cliOptions

	cmd := &cobra.Command{
		Use:   "cpar [options] [cbor-data]",
		Short: "CBOR parser and pretty printer",
		Long: `cpar parses CBOR data and outputs it in a human-readable or JSON format.

Input is read from stdin, or provided directly as an argument (e.g. a hex string).
Input format is detected automatically by default.`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := run(args, opts); err != nil {
				fmt.Fprintf(os.Stderr, "cpar: %v\n", err)
				return err
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&opts.inputFormat, "input-format", "i", "auto",
		"input format: binary, hex, base64, base64url, auto")
	f.StringVarP(&opts.outputFormat, "output-format", "o", "text",
		"output format: text, json, json-verbose")
	f.BoolVar(&opts.disableTag24, "disable-recursive-tag24", false,
		"disable recursive parsing of tag-24 embedded CBOR")
	f.BoolVarP(&opts.inferCOSEUntagged, "infer-cose-untagged", "c", false,
		"infer and parse untagged COSE structures (heuristic)")
	f.BoolVarP(&opts.showMetadata, "show-metadata", "m", false,
		"show type and length metadata (text output only)")
	f.BoolVarP(&opts.decodeEmbedded, "decode-embedded-cbor", "e", false,
		"decode embedded CBOR in COSE plaintext payload")

	return cmd
}

func run(args []string, opts cliOptions) error {
	// Validate options
	switch opts.inputFormat {
	case "auto", "binary", "hex", "base64", "base64url":
	default:
		return fmt.Errorf("unknown input format %q; use: binary, hex, base64, base64url, auto", opts.inputFormat)
	}
	switch opts.outputFormat {
	case "text", "json", "json-verbose":
	default:
		return fmt.Errorf("unknown output format %q; use: text, json, json-verbose", opts.outputFormat)
	}

	// ① read and decode input
	var (
		raw []byte
		err error
	)
	if len(args) > 0 {
		raw, err = input.ReadString(args[0], input.Format(opts.inputFormat))
	} else {
		raw, err = input.Read(input.Format(opts.inputFormat))
	}
	if err != nil {
		return fmt.Errorf("input: %w", err)
	}

	// ② CBOR decode
	node, err := cbor.Decode(raw)
	if err != nil {
		return fmt.Errorf("CBOR decode: %w", err)
	}

	// ③–⑥ COSE processing + tag-24 recursion
	coseOpts := cose.Options{
		InferUntagged:      opts.inferCOSEUntagged,
		DecodeEmbeddedCBOR: opts.decodeEmbedded,
		DisableTag24:       opts.disableTag24,
	}
	cose.Process(node, coseOpts)

	// ⑦ render
	fmtOpts := format.Options{
		ShowMetadata:       opts.showMetadata,
		DecodeEmbeddedCBOR: opts.decodeEmbedded,
		DisableTag24:       opts.disableTag24,
		InferCOSEUntagged:  opts.inferCOSEUntagged,
	}

	switch opts.outputFormat {
	case "text":
		out := format.RenderText(node, fmtOpts)
		fmt.Print(out)
	case "json":
		out, err := format.RenderJSON(node, fmtOpts)
		if err != nil {
			return fmt.Errorf("json render: %w", err)
		}
		fmt.Println(string(out))
	case "json-verbose":
		out, err := format.RenderJSONVerbose(node, fmtOpts)
		if err != nil {
			return fmt.Errorf("json-verbose render: %w", err)
		}
		fmt.Println(string(out))
	}
	return nil
}
