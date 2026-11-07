// Command wardn checks policy files and generates Go code from them.
//
//	wardn check [-f wardn.yaml]                     validate a policy (for CI)
//	wardn gen   [-f wardn.yaml] [-o perm/perm.go]   generate Go constants
//	wardn gen   -check ...                          fail if generated code is stale
//	wardn version
//
// Install with: go install github.com/MogRex-Limited/wardn/cmd/wardn@latest
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/MogRex-Limited/wardn"
)

// Exit codes.
const (
	exitOK      = 0
	exitFailed  = 1 // invalid policy, stale generated code, I/O error
	exitUsage   = 2
	defaultFile = wardn.DefaultPolicyFile
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `wardn checks policy files and generates Go code from them.

Usage:
  wardn check [-f wardn.yaml]
  wardn gen [-f wardn.yaml] [-o perm/perm.go] [-pkg perm] [-check]
  wardn version

Run "wardn <command> -h" for a command's flags.
`

func run(args []string, stdoutW, stderrW io.Writer) int {
	stdout, stderr := &output{w: stdoutW}, &output{w: stderrW}
	code := dispatch(args, stdout, stderr)
	if code == exitOK && stdout.err != nil {
		return exitFailed // e.g. a closed pipe: don't report success
	}
	return code
}

// output writes to w and remembers the first write error.
type output struct {
	w   io.Writer
	err error
}

func (o *output) Write(p []byte) (int, error) {
	if o.err != nil {
		return 0, o.err
	}
	n, err := o.w.Write(p)
	o.err = err
	return n, err
}

func (o *output) printf(format string, args ...any) { _, _ = fmt.Fprintf(o, format, args...) }

func (o *output) println(args ...any) { _, _ = fmt.Fprintln(o, args...) }

func dispatch(args []string, stdout, stderr *output) int {
	if len(args) == 0 {
		stderr.printf("%s", usage)
		return exitUsage
	}
	switch args[0] {
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "gen":
		return runGen(args[1:], stdout, stderr)
	case "version":
		stdout.println("wardn", version())
		return exitOK
	case "help", "-h", "-help", "--help":
		stdout.printf("%s", usage)
		return exitOK
	}
	stderr.printf("wardn: unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

func runCheck(args []string, stdout, stderr *output) int {
	fs := flag.NewFlagSet("wardn check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("f", defaultFile, "policy file")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	p, err := load(*file)
	if err != nil {
		stderr.println(err)
		return exitFailed
	}
	stdout.printf("%s is valid.\n", *file)
	if len(p.Scopes) > 0 {
		stdout.printf("  scopes:      %s\n", describeScopes(p))
	} else {
		stdout.println("  scopes:      none (global only)")
	}
	stdout.printf("  permissions: %d, plus 2 built in\n", len(p.Permissions))
	stdout.printf("  roles:       %s\n", strings.Join(slices.Sorted(maps.Keys(p.Roles)), ", "))
	return exitOK
}

func runGen(args []string, stdout, stderr *output) int {
	fs := flag.NewFlagSet("wardn gen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("f", defaultFile, "policy file")
	out := fs.String("o", filepath.Join("perm", "perm.go"), "output file")
	pkg := fs.String("pkg", "", "package name (default: the output directory's name)")
	check := fs.Bool("check", false, "don't write; fail if the output file is missing or out of date (for CI)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *pkg == "" {
		*pkg = filepath.Base(filepath.Dir(filepath.Clean(*out)))
	}
	p, err := load(*file)
	if err != nil {
		stderr.println(err)
		return exitFailed
	}
	src, err := generate(p, filepath.ToSlash(*file), *pkg)
	if err != nil {
		stderr.println("wardn gen:", err)
		return exitFailed
	}

	if *check {
		current, err := os.ReadFile(filepath.Clean(*out))
		if err != nil || !bytes.Equal(current, src) {
			stderr.printf("wardn gen: %s is out of date with %s; run \"wardn gen\" and commit the result\n", *out, *file)
			return exitFailed
		}
		stdout.printf("%s is up to date.\n", *out)
		return exitOK
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o750); err != nil {
		stderr.println("wardn gen:", err)
		return exitFailed
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil { //nolint:gosec // G306: generated source code is meant to be readable
		stderr.println("wardn gen:", err)
		return exitFailed
	}
	stdout.printf("wrote %s\n", *out)
	return exitOK
}

// load parses and validates a policy file.
func load(file string) (*wardn.Policy, error) {
	p, err := wardn.LoadPolicyFile(file)
	if err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// describeScopes renders the scope tree, e.g. "organisation › region › branch; team".
func describeScopes(p *wardn.Policy) string {
	children := map[string][]string{}
	for name, st := range p.Scopes {
		children[st.Parent] = append(children[st.Parent], name)
	}
	var paths []string
	var walk func(prefix, name string)
	walk = func(prefix, name string) {
		path := prefix + name
		kids := children[name]
		if len(kids) == 0 {
			paths = append(paths, path)
			return
		}
		slices.Sort(kids)
		for _, k := range kids {
			walk(path+" › ", k)
		}
	}
	roots := children[""]
	slices.Sort(roots)
	for _, r := range roots {
		walk("", r)
	}
	return strings.Join(paths, "; ")
}

// releaseVersion is set by the release workflow (-ldflags -X) for
// downloadable binaries; "go install" builds read the module version instead.
var releaseVersion string

func version() string {
	if releaseVersion != "" {
		return releaseVersion
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "(unknown version)"
	}
	return info.Main.Version
}
