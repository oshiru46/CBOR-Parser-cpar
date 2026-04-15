package main_test

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Run with -update to regenerate golden stdout.txt files:
//
//	go test -run TestE2E -update
var updateFlag = flag.Bool("update", false, "update golden stdout.txt files")

var binaryPath string

func TestMain(m *testing.M) {
	flag.Parse()

	tmp, err := os.MkdirTemp("", "cpar-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mktemp: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	binaryPath = filepath.Join(tmp, "cpar")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// TestE2E iterates over every subdirectory under testdata/ and runs cpar against
// input.hex, optionally with extra flags from args.txt, then compares stdout to
// the golden file stdout.txt.
//
// Directory layout of each test case:
//
//	testdata/<name>/
//	  input.hex   — hex-encoded CBOR input (required)
//	  args.txt    — extra CLI flags, space-separated (optional)
//	  stdout.txt  — expected stdout output (golden file, auto-generated with -update)
func TestE2E(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		dir := filepath.Join("testdata", name)
		t.Run(name, func(t *testing.T) {
			runCase(t, dir)
		})
	}
}

func runCase(t *testing.T, dir string) {
	t.Helper()

	// --- input ---
	inputHex, err := os.ReadFile(filepath.Join(dir, "input.hex"))
	if err != nil {
		t.Fatalf("input.hex: %v", err)
	}

	// --- args: always start with -i hex ---
	args := []string{"-i", "hex"}
	if raw, err := os.ReadFile(filepath.Join(dir, "args.txt")); err == nil {
		for _, a := range strings.Fields(string(raw)) {
			args = append(args, a)
		}
	}
	args = append(args, strings.TrimSpace(string(inputHex)))

	// --- run ---
	cmd := exec.Command(binaryPath, args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatalf("cpar exited %d\nstderr:\n%s", exitErr.ExitCode(), exitErr.Stderr)
		}
		t.Fatal(err)
	}

	goldenPath := filepath.Join(dir, "stdout.txt")

	// --- update mode: write golden file and return ---
	if *updateFlag {
		if err := os.WriteFile(goldenPath, out, 0644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated %s", goldenPath)
		return
	}

	// --- compare with golden file ---
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("stdout.txt missing — regenerate with:\n  go test -run TestE2E -update\nerr: %v", err)
	}

	if string(out) != string(golden) {
		t.Errorf("output mismatch\n--- want ---\n%s\n--- got  ---\n%s", golden, out)
	}
}
