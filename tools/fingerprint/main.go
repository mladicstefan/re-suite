// Runs the Wappalyzer rule set on saved HTTP responses, never on a live site.
//
// Reads one JSON object per line on stdin: {"id": ..., "headers": {name: [values]}, "body": text}.
// Writes one per line on stdout: {"id": ..., "technologies": {name: {"version": ..., "categories": [...]}}}.
// With --version it prints the version of the rule set, which decides what it finds.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const ruleSet = "github.com/projectdiscovery/wappalyzergo"

func version() {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == ruleSet {
				fmt.Println("ledger-fingerprint", "wappalyzergo", dep.Version)
				return
			}
		}
	}
	fmt.Fprintln(os.Stderr, "the build does not say which rule set it holds")
	os.Exit(1)
}

type response struct {
	ID      string              `json:"id"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

type technology struct {
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories,omitempty"`
}

type detected struct {
	ID           string                `json:"id"`
	Technologies map[string]technology `json:"technologies"`
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		version()
		return
	}
	rules, err := wappalyzer.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "loading the rules:", err)
		os.Exit(1)
	}
	in := bufio.NewScanner(os.Stdin)
	// One response body per line; the caller bounds what it sends.
	in.Buffer(make([]byte, 1<<20), 64<<20)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var r response
		if err := json.Unmarshal(in.Bytes(), &r); err != nil {
			fmt.Fprintln(os.Stderr, "a line is not a response:", err)
			os.Exit(1)
		}
		found := detected{ID: r.ID, Technologies: map[string]technology{}}
		for name, info := range rules.FingerprintWithInfo(r.Headers, []byte(r.Body)) {
			// The library reports a version as a suffix of the name.
			name, version, _ := strings.Cut(name, ":")
			found.Technologies[name] = technology{Version: version, Categories: info.Categories}
		}
		if err := out.Encode(found); err != nil {
			os.Exit(1)
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading:", err)
		os.Exit(1)
	}
}
