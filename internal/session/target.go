// Package session owns reach's per-session state: which target a shell is
// bound to, where it is working, and what that target's userland supports.
package session

import (
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// Kind identifies a target family.
type Kind string

// The target families reach can reach.
const (
	KindSSH    Kind = "ssh"
	KindDocker Kind = "docker"
	KindPodman Kind = "podman"
	KindLocal  Kind = "local"
)

// Target is a parsed target specification.
type Target struct {
	Kind Kind   `json:"kind"`
	Host string `json:"host,omitempty"`
	User string `json:"user,omitempty"`
	Port int    `json:"port,omitempty"`
	// Container is the container name for container kinds.
	Container string `json:"container,omitempty"`
	// Workspace is the directory on the target that the session operates in.
	//
	// Between ParseTarget and Probe it holds what the operator wrote, which
	// for an ssh target may be relative to where a login lands or may begin
	// with a tilde. Probe resolves it against the target and overwrites it
	// with the absolute answer, so everything downstream of a probed session
	// sees an absolute path and nothing else.
	Workspace string `json:"workspace"`
	// LoginDir is where a plain login on this target lands, as the target
	// itself reported it during Probe.
	//
	// It is recorded rather than recomputed because a relative spec cannot be
	// compared against a session without it: `reach box:app claude`, run twice,
	// must find the session it made the first time instead of asking the host
	// again for a directory it has already answered for.
	LoginDir string `json:"login_dir,omitempty"`
	// Raw is the original specification, kept for diagnostics.
	Raw string `json:"raw"`
}

// ParseTarget accepts the forms:
//
//	[user@]host:path                 (scp's spelling)
//	ssh://[user@]host[:port]/path    (OpenSSH's URI spelling)
//	ssh://alias/path                 (alias resolved by the user's ssh config)
//	docker://container/path
//	podman://container/path
//	local:///abs/path                (this machine, mostly for testing)
//
// A path means what the tool the form is borrowed from means by it. reach
// invents no convention of its own, because an operator who knows what
// `scp box:app` copies should not have to learn what reach thinks it means.
//
// For ssh, both spellings resolve a path against the directory a login lands
// in unless it starts with a slash: `box:app` and `ssh://box/app` are both
// ~/app, while `box:/srv/app` and `ssh://box//srv/app` are both /srv/app. The
// second slash in the URI form is not a typo. OpenSSH's own parser consumes
// the slash that ends the host — hpdelim2 in misc.c does `*cp = s + 1` — so
// what reaches scp and sftp as the path has no leading slash, and a second one
// is what makes it absolute. curl reads sftp:// URLs the same way. git reads
// ssh:// the other way, absolute from the first slash; where the two disagree
// reach follows the ssh binary it is shelling out to.
//
// For containers, docker cp's rule holds: "container paths are relative to the
// container's / (root) directory ... supplying the initial forward slash is
// optional", so `docker://c/srv/app` and `docker://c//srv/app` are the same
// directory. podman cp copies docker here.
//
// The path may be left off any of them — `ssh://build-box`, `build-box:` —
// which means the directory the target's own login shell starts in, the way
// `sftp host:` does. Probe asks the target and records the answer, so the
// short spelling is a request for a real directory rather than a session with
// no workspace.
//
// Host is deliberately passed through to the ssh client untouched, so entries
// in ~/.ssh/config — ProxyJump, IdentityFile, Match blocks, hardware tokens —
// keep working exactly as they do outside reach.
func ParseTarget(spec string) (*Target, error) {
	if spec == "" {
		return nil, fmt.Errorf("empty target")
	}
	if !strings.Contains(spec, "://") {
		return parseHostColonPath(spec)
	}
	return parseURI(spec)
}

// parseHostColonPath reads scp's spelling, e.g. root@box:/srv/app or box:app.
func parseHostColonPath(spec string) (*Target, error) {
	host, wsPath, ok := strings.Cut(spec, ":")
	if !ok {
		return nil, fmt.Errorf("target %q: expected scheme://... or [user@]host:path", spec)
	}
	// A Windows drive letter is a single character, a colon and a path, which
	// is this form exactly. Reading C:\src\app as a host named C used to be
	// caught by the rule that a workspace had to be absolute; now that a
	// relative one is legitimate, nothing else would notice.
	if len(host) == 1 && strings.HasPrefix(wsPath, `\`) {
		return nil, fmt.Errorf("target %q: that is a path on this machine, not a target.\n"+
			"A target names the machine first, as in build-box:/srv/app", spec)
	}
	t := &Target{Kind: KindSSH, Raw: spec, Workspace: wsPath}
	if u, h, has := strings.Cut(host, "@"); has {
		t.User, t.Host = u, h
	} else {
		t.Host = host
	}
	return t, validate(t)
}

// parseURI reads the scheme://... spellings.
func parseURI(spec string) (*Target, error) {
	u, err := url.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("target %q: %w", spec, err)
	}
	t := &Target{Raw: spec}

	switch u.Scheme {
	case "ssh":
		t.Kind = KindSSH
		t.Host = u.Hostname()
		if u.User != nil {
			t.User = u.User.Username()
		}
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil, fmt.Errorf("target %q: bad port %q", spec, p)
			}
			t.Port = n
		}
		// The slash that ends the host is a delimiter, not part of the path.
		// See the note on ParseTarget: this is what OpenSSH does with its own
		// URIs, and it is why an absolute path here carries two slashes.
		t.Workspace = strings.TrimPrefix(u.Path, "/")
	case "docker", "podman":
		t.Kind = Kind(u.Scheme)
		t.Container = u.Host
		t.Workspace = containerPath(u.Path)
	case "local":
		if u.Host != "" {
			return nil, fmt.Errorf("target %q: local names no machine; write local:///abs/path", spec)
		}
		t.Kind = KindLocal
		t.Workspace = u.Path
	default:
		return nil, fmt.Errorf("target %q: unsupported scheme %q (want ssh, docker, podman or local)", spec, u.Scheme)
	}
	return t, validate(t)
}

// containerPath applies docker cp's rule that a container path is relative to
// the container's root, which makes the leading slash optional.
func containerPath(p string) string {
	p = strings.TrimLeft(p, "/")
	if p == "" {
		return ""
	}
	return "/" + p
}

func validate(t *Target) error {
	switch t.Kind {
	case KindSSH:
		if t.Host == "" {
			return fmt.Errorf("target %q: missing host", t.Raw)
		}
	case KindDocker, KindPodman:
		if t.Container == "" {
			return fmt.Errorf("target %q: missing container name", t.Raw)
		}
	case KindLocal:
		// Nothing resolves a relative path here: this machine has no login
		// reach can ask, and the shell's own directory is whatever the
		// operator happened to be in when they typed the command.
		if t.Workspace != "" && !path.IsAbs(t.Workspace) {
			return fmt.Errorf("target %q: a local workspace must be an absolute path", t.Raw)
		}
	}
	// An absent workspace is not an error. It means "wherever a login on this
	// target lands", which Probe asks the target for and records. Requiring
	// the path up front made the short forms — `reach build-box claude`,
	// `reach up ssh://build-box` — impossible to type, in exchange for a
	// directory the operator almost always spelled out as the one ssh would
	// have put them in anyway.
	return nil
}

// NeedsLoginDir reports whether resolving this workspace requires asking the
// target where a login lands.
func (t *Target) NeedsLoginDir() bool {
	return t.Workspace == "" ||
		(!path.IsAbs(t.Workspace) && !strings.HasPrefix(t.Workspace, "~"))
}

// ResolveLike resolves a workspace the operator just wrote the way Probe
// resolved this target's own, using the login directory the target reported.
//
// ok is false when the answer would be a guess: a session recorded before
// reach kept the login directory, or a tilde only the target can expand. A
// caller that cannot get an answer must ask the target rather than assume one.
func (t *Target) ResolveLike(ws string) (string, bool) {
	switch {
	case ws == "":
		return "", false
	case strings.HasPrefix(ws, "~"):
		return "", false
	case path.IsAbs(ws):
		return path.Clean(ws), true
	case t.LoginDir == "":
		return "", false
	default:
		return path.Clean(t.LoginDir + "/" + ws), true
	}
}

// Describe renders a short identity for diagnostics.
//
// What it prints has to parse back to the same place, so it follows the same
// rules it reads: scp's spelling, which needs no second slash and is the one
// most operators have in their fingers, and the URI spelling when a port has
// to be carried, which scp's has nowhere to put.
func (t *Target) Describe() string {
	switch t.Kind {
	case KindSSH:
		h := t.DescribeHost()
		if t.Port != 0 {
			ws := t.Workspace
			if ws != "" {
				ws = "/" + ws
			}
			return "ssh://" + h + ws
		}
		// `build-box:` rather than a bare `build-box`, because only the
		// first is a target on its own terms: a bare word is a target when
		// this machine's ssh configuration happens to name it, and a string
		// reach prints must not depend on that to mean what it said.
		return h + ":" + t.Workspace
	case KindDocker, KindPodman:
		return string(t.Kind) + "://" + t.Container + t.Workspace
	default:
		return "local://" + t.Workspace
	}
}

// DescribeHost names the machine without the directory, for messages that
// already say which path they are talking about.
func (t *Target) DescribeHost() string {
	switch t.Kind {
	case KindSSH:
		h := t.Host
		if t.User != "" {
			h = t.User + "@" + h
		}
		if t.Port != 0 {
			h = fmt.Sprintf("%s:%d", h, t.Port)
		}
		return h
	case KindDocker, KindPodman:
		return string(t.Kind) + "://" + t.Container
	default:
		return "this machine"
	}
}
