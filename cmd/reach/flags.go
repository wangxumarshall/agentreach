package main

import (
	"flag"
	"fmt"
	"strings"
)

// parseFlags parses a flag set where flags may appear before, after or between
// positional arguments, and returns the positional arguments.
//
// The standard library stops parsing at the first non-flag argument, so
// `reach up ssh://host/path --name build` would silently ignore --name and
// create a session called "default". A flag that is quietly discarded is worse
// than one that errors: the operator believes they configured something they
// did not, and only finds out when a later command cannot find the session.
//
// Everything after a literal "--" is positional, so `reach exec -- ls -la`
// passes -la to the target rather than to reach.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var tail []string
	for i, a := range args {
		if a == "--" {
			// G602: i is an index into args from ranging over it, so both
			// args[i+1:] and args[:i] are in range by construction. gosec
			// does not follow that through the reassignment of args.
			tail = args[i+1:] //nolint:gosec // i came from range over args
			args = args[:i]   //nolint:gosec // i came from range over args
			break
		}
	}
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	return append(positional, tail...), nil
}

// newFlagSet builds a flag set that reports errors without exiting, so callers
// can produce their own message.
func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

// parseHarnessArgs extracts flags recognized by reach's FlagSet while preserving
// all remaining flags and arguments for the underlying harness (e.g. --dangerously-skip-permissions).
func parseHarnessArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var harnessArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			harnessArgs = append(harnessArgs, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") {
			harnessArgs = append(harnessArgs, a)
			continue
		}
		flagName := strings.TrimLeft(a, "-")
		if eq := strings.Index(flagName, "="); eq != -1 {
			flagName = flagName[:eq]
		}
		if f := fs.Lookup(flagName); f != nil {
			if strings.Contains(a, "=") {
				val := a[strings.Index(a, "=")+1:]
				if err := f.Value.Set(val); err != nil {
					return nil, err
				}
			} else {
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
					if err := f.Value.Set("true"); err != nil {
						return nil, err
					}
				} else if i+1 < len(args) {
					i++
					if err := f.Value.Set(args[i]); err != nil {
						return nil, err
					}
				} else {
					return nil, fmt.Errorf("flag needs an argument: %s", a)
				}
			}
		} else {
			harnessArgs = append(harnessArgs, a)
		}
	}
	return harnessArgs, nil
}
