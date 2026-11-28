// Runs the Wappalyzer rule set on the saved responses of one session, never on a live site.
//
// ledger-fingerprint --listed N <session>: <session> is a session record as the ledger
// stores it, and every exchange it names lies beside it, in the ledger's http_exchange
// JSON, under its evidence id. It prints one JSON object: every host that answered,
// with the technologies the rules read in its responses, each with the versions read,
// its categories and up to N of the exchanges it was read in.
// With --version it prints what decides what it finds: this program and the rule set.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const ruleSet = "github.com/projectdiscovery/wappalyzergo"

// Bump it when what this program reads or prints changes: the ledger reuses the output
// of a run at the same version on the same session.
const reading = "1"

func version() {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == ruleSet {
				fmt.Printf("fingerprint %s, wappalyzergo %s\n", reading, dep.Version)
				return
			}
		}
	}
	fail("the build does not say which rule set it holds")
}

func fail(why ...any) {
	fmt.Fprintln(os.Stderr, why...)
	os.Exit(1)
}

type session struct {
	Exchanges []struct {
		Exchange string `json:"exchange"`
	} `json:"exchanges"`
}

type header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type body struct {
	Text   *string `json:"text"`
	Base64 *string `json:"base64"`
}

type exchange struct {
	Request struct {
		URL string `json:"url"`
	} `json:"request"`
	Response *struct {
		Headers []header `json:"headers"`
		Body    *body    `json:"body"`
	} `json:"response"`
}

type technology struct {
	Versions   []string `json:"versions,omitempty"`
	Categories []string `json:"categories"`
	Exchanges  []string `json:"exchanges"`
}

func read(path string, into any) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		fail("reading", path, err)
	}
	if err := json.Unmarshal(bytes, into); err != nil {
		fail(path, "does not read:", err)
	}
}

// The host as a request address writes it, with its port, in lower case.
func hostOf(address string) string {
	parsed, err := url.Parse(address)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Host)
}

// The rules read a body as HTML, so only an HTML document's body is given to them, as
// the library itself does when it reads a page's title.
func document(headers map[string][]string, saved *body) []byte {
	html := slices.ContainsFunc(headers["content-type"], func(v string) bool {
		return strings.Contains(strings.ToLower(v), "html")
	})
	switch {
	case !html || saved == nil:
		return nil
	case saved.Text != nil:
		return []byte(*saved.Text)
	case saved.Base64 != nil:
		decoded, err := base64.StdEncoding.DecodeString(*saved.Base64)
		if err != nil {
			return nil
		}
		return decoded
	}
	return nil
}

func main() {
	showVersion := flag.Bool("version", false, "print the version")
	listed := flag.Int("listed", 8, "the most exchanges named per technology")
	flag.Parse()
	if *showVersion {
		version()
		return
	}
	if flag.NArg() != 1 {
		fail("give the path of one session record")
	}
	record := flag.Arg(0)
	var sent session
	read(record, &sent)
	rules, err := wappalyzer.New()
	if err != nil {
		fail("loading the rules:", err)
	}
	hosts := map[string]map[string]*technology{}
	for _, one := range sent.Exchanges {
		id := one.Exchange
		if id == "" || filepath.Base(id) != id {
			fail("the session names an exchange by something that is not an id")
		}
		var saved exchange
		read(filepath.Join(filepath.Dir(record), id), &saved)
		host := hostOf(saved.Request.URL)
		if saved.Response == nil || host == "" {
			continue
		}
		found := hosts[host]
		if found == nil {
			found = map[string]*technology{}
			hosts[host] = found
		}
		// Captures spell names in either case; the library would let one spelling overwrite another.
		headers := map[string][]string{}
		for _, h := range saved.Response.Headers {
			name := strings.ToLower(h.Name)
			headers[name] = append(headers[name], h.Value)
		}
		for named, info := range rules.FingerprintWithInfo(headers, document(headers, saved.Response.Body)) {
			// The library writes a version as a suffix of the name.
			name, version, _ := strings.Cut(named, ":")
			t := found[name]
			if t == nil {
				t = &technology{Categories: slices.Sorted(slices.Values(info.Categories)), Exchanges: []string{}}
				found[name] = t
			}
			if version != "" && !slices.Contains(t.Versions, version) {
				t.Versions = append(t.Versions, version)
				slices.Sort(t.Versions)
			}
			if len(t.Exchanges) < *listed && !slices.Contains(t.Exchanges, id) {
				t.Exchanges = append(t.Exchanges, id)
			}
		}
	}
	out := json.NewEncoder(os.Stdout)
	if err := out.Encode(map[string]any{"hosts": hosts}); err != nil {
		fail("writing:", err)
	}
}
