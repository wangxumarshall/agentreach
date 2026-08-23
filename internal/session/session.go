package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bojieli/agentreach/internal/fileops"
	"github.com/bojieli/agentreach/internal/reach"
	"github.com/bojieli/agentreach/internal/transport"
)

// Mode selects how much of the harness's tool surface reach redirects.
type Mode string

const (
	// ModeExec redirects command execution only. Harnesses whose file tools
	// cannot be redirected must have those tools denied in this mode, because
	// a native Read or Write would silently act on the local filesystem while
	// the agent believes it is working on the target.
	ModeExec Mode = "exec"

	// ModeMirror additionally materialises the workspace as real local files
	// so native file tools operate at native speed.
	ModeMirror Mode = "mirror"
)

// Session is the persisted binding between a shell and a target.
//
// State lives in a file rather than a daemon. Connection reuse — the only thing
// a daemon would have bought — is already provided by SSH's ControlMaster,
// measured against real hosts at 4-5x faster per command than reconnecting
// (171ms against 772ms on one, 557ms against 2.85s on another). A daemon would
// add a lifecycle, a socket, crash recovery and orphaned processes in exchange
// for nothing.
type Session struct {
	// Version is the schema version of this document. See SchemaVersion.
	Version  int        `json:"version"`
	Name     string     `json:"name"`
	Target   *Target    `json:"target"`
	Mode     Mode       `json:"mode"`
	Tier     reach.Tier `json:"-"`
	TierName string     `json:"tier"`
	// Pinned records that the operator named this tier with --fileops. A pinned
	// tier is an instruction, not a preference: reach fails rather than quietly
	// giving them a different one.
	Pinned bool `json:"pinned,omitempty"`
	// MultiplexNote explains why multiplexing is unavailable, and is empty when
	// it is available.
	MultiplexNote string `json:"multiplex_note,omitempty"`
	// TierReason explains a tier that is lower than the one asked for, and is
	// empty when nothing was degraded.
	TierReason string                `json:"tier_reason,omitempty"`
	Caps       *fileops.Capabilities `json:"caps"`
	Created    time.Time             `json:"created"`
	// Multiplex records whether the local ssh client proved it can hold a
	// multiplexed master to this target. It is the difference between ~7 ms and
	// ~130 ms per command, and it is recorded rather than assumed because
	// Win32-OpenSSH does not implement the feature.
	Multiplex bool `json:"multiplex"`
	// A session written by 0.1.0 or 0.1.1 may carry an "untrusted" field. It is ignored
	// rather than migrated, and the schema version does not move for it: what
	// the field promised is now unconditional — no credential goes to any
	// target, no agent is forwarded to any target, and nothing is installed on
	// one unless the operator names the helper tier by hand — so there is no
	// policy left for it to have meant, and a document written by either build
	// loads identically in the other.
	// Timeout bounds an individual command.
	Timeout time.Duration `json:"timeout"`
}

// SchemaVersion is the version of the session document this build writes.
//
// A session file outlives the binary that wrote it: it sits in ~/.reach until
// `reach down`, across upgrades, and more than one reach may be on PATH at once
// — a package-managed install and a `go install` build are the usual pair.
// encoding/json discards fields it does not recognise without a word, so an
// older binary reading a newer document does not fail, it succeeds with a
// session it has partly understood. For a tool whose entire job is being
// certain which machine a command runs on, that is the worst available
// outcome.
//
// Raise this whenever the meaning of an existing field changes, and teach
// migrate what the old meaning was. Adding a field that is correct when absent
// does not need a bump; that is what the zero value is for.
const SchemaVersion = 1

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Dir returns reach's state directory.
func Dir() (string, error) {
	base := os.Getenv("REACH_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}
		base = filepath.Join(home, ".reach")
	}
	dir := filepath.Join(base, "sessions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	return dir, nil
}

// ConfDir holds files reach generates for harnesses, such as settings
// documents.
//
// These are kept out of the sessions directory deliberately. Session discovery
// enumerates that directory, and a generated file that happens to parse as
// JSON would otherwise be loaded as a session with no target — which crashed
// `reach status` with a nil dereference until this separation existed.
func ConfDir() (string, error) {
	base := os.Getenv("REACH_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}
		base = filepath.Join(home, ".reach")
	}
	dir := filepath.Join(base, "conf")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	return dir, nil
}

func pathFor(name string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".json"), nil
}

func cwdPathFor(name string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".cwd"), nil
}

// Save writes the session atomically.
func (s *Session) Save() error {
	if !nameRE.MatchString(s.Name) {
		return fmt.Errorf("invalid session name %q: use letters, digits, dot, dash or underscore", s.Name)
	}
	s.TierName = s.Tier.String()
	s.Version = SchemaVersion
	p, err := pathFor(s.Name)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Load reads a session by name.
func Load(name string) (*Session, error) {
	p, err := pathFor(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &noSuchSessionError{name: name}
		}
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("session %q is corrupt (%w); remove %s and start it again", name, err, p)
	}
	// Defence in depth: a document that parses as JSON but is not a session
	// must not produce a Session with nil fields that callers will dereference.
	if s.Target == nil || s.Name == "" {
		return nil, fmt.Errorf("%s %w", p, ErrNotSession)
	}
	if err := migrate(&s); err != nil {
		return nil, fmt.Errorf("session %q: %w", name, err)
	}
	return &s, nil
}

// migrate brings a loaded document up to the current schema, or explains why it
// cannot.
//
// Refusing to load is the right failure here. Every alternative — guessing at a
// field, falling back to a default — produces a session that runs commands
// somewhere, and the operator's only evidence about where is the file reach has
// just decided not to trust.
func migrate(s *Session) error {
	if s.Version > SchemaVersion {
		return fmt.Errorf("this session was created by a newer reach (schema v%d, this build understands v%d).\n"+
			"Upgrade reach, or run `reach down %s` and start the session again with this build.\n"+
			"Loading it anyway would mean ignoring settings this build cannot see, on a session whose\n"+
			"whole purpose is being certain which machine your commands run on.",
			s.Version, SchemaVersion, s.Name)
	}
	// Version 0 predates this field. Its shape is version 1's, so it loads as
	// written; Save stamps the current version the next time anything writes.
	if s.Version == 0 {
		s.Version = SchemaVersion
	}

	// An absent tier is "nothing was recorded", which is different from a
	// recorded name this build cannot honour. Nothing was pinned, so posix — the
	// floor, which installs nothing and needs only a shell — is the honest
	// reading rather than a guess.
	if s.TierName == "" {
		s.TierName, s.Tier = reach.TierPOSIX.String(), reach.TierPOSIX
		return nil
	}

	// The tier name is the one field whose vocabulary has actually changed:
	// `sftp` was removed and `agent` renamed to `helper`. Swallowing the parse
	// error left Tier at its zero value, so a session created with
	// `--fileops=sftp` loaded as a *pinned* posix session — reach silently
	// running a tier other than the one it was instructed to use, and reporting
	// the tier it was told. ParseTier's error explains each removal; the
	// operator should read it rather than have it discarded.
	t, err := reach.ParseTier(s.TierName)
	if err != nil {
		return fmt.Errorf("%w\nRun `reach up %s --name %s` to recreate this session.",
			err, s.Target.Raw, s.Name)
	}
	s.Tier = t
	return nil
}

// ErrNotSession marks a file that is not reach's to interpret.
//
// It separates "this is not a session" from "this is a session I cannot
// honour". The first is an unrelated .json file sitting in the directory and
// deserves silence; the second is the operator's session and deserves an
// explanation.
var ErrNotSession = errors.New("is not a reach session file")

// noSuchSessionError reports a session that is simply not there.
//
// It unwraps to os.ErrNotExist so a caller can tell "there is nothing here"
// from "there is something here I cannot read". `reach down` needs exactly that
// distinction: it must refuse the first and proceed with the second. The
// wrapping is done with a type rather than a %w in the message so that the
// sentinel does not appear in text an operator reads.
type noSuchSessionError struct{ name string }

func (e *noSuchSessionError) Error() string {
	return fmt.Sprintf("no reach session named %q. Start one with:\n"+
		"  reach up host:/srv/app --name %s\n"+
		"or point the command straight at a target, which names the session for you:\n"+
		"  reach host:/srv/app claude",
		e.name, e.name)
}

func (e *noSuchSessionError) Unwrap() error { return os.ErrNotExist }

// Broken describes a session file that exists but could not be loaded.
type Broken struct {
	Name string
	Err  error
}

// List returns all known sessions, and separately the ones that would not load.
//
// The unreadable ones are returned rather than skipped. A session file that
// cannot be loaded is still configured in somebody's harness, and dropping it
// from the listing means `reach ls` prints "no reach sessions" to an operator
// whose agent is at that moment pointed at one. The reason it will not load is
// the single most useful thing reach knows at that point.
func List() ([]*Session, []Broken, error) {
	dir, err := Dir()
	if err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var out []*Session
	var broken []Broken
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		s, err := Load(name)
		if err != nil {
			if !errors.Is(err, ErrNotSession) {
				broken = append(broken, Broken{Name: name, Err: err})
			}
			continue
		}
		out = append(out, s)
	}
	return out, broken, nil
}

// SharesConnectionWith names the other sessions whose commands travel over the
// same connection as this one's.
//
// The control socket is keyed on the destination rather than on the session, so
// two sessions pointed at one host — a different directory, a different agent,
// a second terminal — authenticate once and share a connection. That is worth
// having: an extra authentication per session is exactly the cost multiplexing
// exists to remove, and on a host with a hardware token it is a second touch.
//
// It does mean the connection is not any one session's to close. `reach down`
// asks this before tearing the master down, because ending a connection another
// session is working over turns that session's next tool call into a full
// reconnect — and on a host that needs a password or a token, into a failure,
// since every connection after `reach up` runs in batch mode.
func (s *Session) SharesConnectionWith() []string {
	if s.Target == nil || s.Target.Kind != KindSSH {
		return nil
	}
	all, _, err := List()
	if err != nil {
		// Nothing readable to go on. Reporting no sharers would mean tearing
		// down a connection that may well be in use; the cost of being wrong
		// the other way is a master that expires on its own ControlPersist.
		return []string{"(other sessions could not be read)"}
	}
	var names []string
	for _, other := range all {
		if other.Name == s.Name || other.Target == nil || other.Target.Kind != KindSSH {
			continue
		}
		if other.Target.Host == s.Target.Host &&
			other.Target.User == s.Target.User &&
			other.Target.Port == s.Target.Port {
			names = append(names, other.Name)
		}
	}
	return names
}

// Remove deletes a session's state.
func Remove(name string) error {
	p, err := pathFor(name)
	if err != nil {
		return err
	}
	c, _ := cwdPathFor(name)
	_ = os.Remove(c)
	return os.Remove(p)
}

// Cwd returns the session's current working directory on the target,
// defaulting to the workspace root.
func (s *Session) Cwd() string {
	p, err := cwdPathFor(s.Name)
	if err != nil {
		return s.Target.Workspace
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return s.Target.Workspace
	}
	if cwd := strings.TrimSpace(string(data)); cwd != "" {
		return cwd
	}
	return s.Target.Workspace
}

// SetCwd records the working directory.
//
// This is kept in its own small file rather than inside the session JSON: it
// changes on almost every command, and rewriting the whole session document
// each time would make concurrent commands race over unrelated fields.
func (s *Session) SetCwd(cwd string) error {
	cwd = strings.TrimSpace(cwd)
	if cwd == "" {
		return nil
	}
	p, err := cwdPathFor(s.Name)
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", p, os.Getpid())
	if err := os.WriteFile(tmp, []byte(cwd+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Transport builds the transport this session's target needs, in batch mode:
// no interactive prompts, so an expired credential fails fast instead of
// hanging a tool call on a password prompt the agent cannot see or answer.
func (s *Session) Transport() (transport.Transport, error) {
	return s.transport(true)
}

// InteractiveTransport allows ssh to prompt.
//
// The first connection to a host may legitimately need a passphrase, a
// password or a 2FA touch. That has to be possible somewhere, and `reach up`
// is the one moment an operator is present to answer. Afterwards ControlMaster
// keeps the authenticated connection alive, so later tool calls never prompt.
func (s *Session) InteractiveTransport() (transport.Transport, error) {
	return s.transport(false)
}

func (s *Session) transport(batch bool) (transport.Transport, error) {
	switch s.Target.Kind {
	case KindSSH:
		return transport.NewSSH(transport.SSHConfig{
			Host: s.Target.Host,
			User: s.Target.User,
			Port: s.Target.Port,
			// Whether the local ssh client can multiplex was settled during
			// `reach up` by establishing one and asking the client to confirm
			// it. Assuming it here would mean sending options that a client
			// without the feature may refuse outright.
			Multiplex: s.Multiplex,
			// Agent forwarding is refused for every target, and no flag turns
			// it on: a forwarded agent socket lets root on that host
			// authenticate as the operator against every other system they can
			// reach, and no target reach connects to is trusted with that.
			ForwardAgent: false,
			BatchMode:    batch,
		})
	case KindDocker, KindPodman:
		return transport.NewContainer(transport.ContainerConfig{
			Runtime:   string(s.Target.Kind),
			Container: s.Target.Container,
		})
	case KindLocal:
		return transport.NewLocal()
	}
	return nil, fmt.Errorf("unsupported target kind %q", s.Target.Kind)
}

// defaultOperationTimeout bounds a file operation when a session predates the
// Timeout field or was written with a zero.
const defaultOperationTimeout = 2 * time.Minute

// OperationContext bounds one file operation with the session's timeout.
//
// Without this, a target that accepts a request and never answers leaves the
// tool call blocked forever, which is precisely the failure this project exists
// to eliminate: an agent cannot reason about a process that has stopped
// responding, but it can reason about a timeout. Applying it here covers every
// tier at once rather than relying on each strategy to remember.
func (s *Session) OperationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultOperationTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

// workspaceQuestions returns the shell that settles this session's workspace,
// for splicing into the capability probe, and the relative path the operator
// wrote when they wrote one.
//
// The join happens on the target because two of the three spellings are
// questions only the target can answer: where a plain login lands, and where
// somebody's home directory is. The operator's own home directory is no answer
// to either — on a container it may not exist at all. reach's reading of the
// path is unchanged; the shell joins what was written, and Go still cleans and
// records the result.
//
// wrote only matters on the failure path: a relative path that is missing under
// the login directory but present at the root is almost always someone spelling
// a target the way reach read them before it followed scp. That twin is asked
// about here rather than after the failure, because a diagnostic that costs a
// round trip is one this probe has just spent a whole script avoiding.
func (s *Session) workspaceQuestions() (script string, wrote string, err error) {
	ws := s.Target.Workspace
	var b strings.Builder
	b.WriteString("printf 'LOGINDIR=%s\\n' \"$(pwd)\"\n")

	switch {
	case ws == "":
		b.WriteString("__reach_ws=$(pwd)\n")
	case strings.HasPrefix(ws, "~"):
		word, rest, _ := strings.Cut(ws, "/")
		if !tildeWord.MatchString(word) {
			return "", "", fmt.Errorf("workspace %q: reach expands ~ and ~user, and %q is neither", ws, word)
		}
		// The word is unquoted because that is the only way a shell will
		// expand a tilde, and tildeWord is what makes sending it unquoted
		// safe. Everything after the first slash is quoted as usual.
		b.WriteString("__reach_ws=" + word)
		if rest != "" {
			b.WriteString("/" + transport.ShellQuote(rest))
		}
		b.WriteString("\n")
	case path.IsAbs(ws):
		b.WriteString("__reach_ws=" + transport.ShellQuote(path.Clean(ws)) + "\n")
	default:
		wrote = ws
		b.WriteString("__reach_ws=\"$(pwd)\"/" + transport.ShellQuote(path.Clean(ws)) + "\n")
	}

	b.WriteString("printf 'WORKSPACE=%s\\n' \"$__reach_ws\"\n")
	b.WriteString("if [ -d \"$__reach_ws\" ]; then printf 'WSOK=1\\n'; else printf 'WSOK=0\\n'; fi\n")
	if wrote != "" {
		rooted := "/" + strings.TrimLeft(wrote, "/")
		b.WriteString("if [ -d " + transport.ShellQuote(rooted) +
			" ]; then printf 'ROOTED=1\\n'; else printf 'ROOTED=0\\n'; fi\n")
	}
	return b.String(), wrote, nil
}

// settleWorkspace reads the workspace back out of one probe's answers and
// writes it into the session.
//
// The workspace is settled once, here, and recorded. Asking the target every
// time would leave two commands in one session disagreeing about where they are
// working if the home directory ever moved, and the whole point of a session is
// that they cannot.
func (s *Session) settleWorkspace(a map[string]string, wrote string) error {
	// Recorded whenever the target answered, not only when the spelling needed
	// it: it is what lets a later `reach box:app claude` recognise the session
	// this one made without asking the host for a directory it has already
	// answered for.
	if login := a["LOGINDIR"]; strings.HasPrefix(login, "/") {
		s.Target.LoginDir = login
	}

	ws := a["WORKSPACE"]
	if strings.HasPrefix(s.Target.Workspace, "~") {
		// A shell that cannot expand a tilde leaves it alone rather than
		// failing, so the word coming back unchanged is how "no such user"
		// arrives.
		word, _, _ := strings.Cut(s.Target.Workspace, "/")
		if ws == "" || strings.HasPrefix(ws, "~") {
			return fmt.Errorf("the target did not expand %s; there may be no such user there", word)
		}
	}
	if ws == "" || !strings.HasPrefix(ws, "/") {
		// Only reachable when the target could not say where a login lands,
		// since the other spellings are absolute before they are sent.
		return fmt.Errorf(
			"the target did not say where a login starts, so reach does not know where to work.\n" +
				"Name the directory instead, as in host:/srv/app")
	}
	s.Target.Workspace = path.Clean(ws)

	// Confirm the workspace is really there. Without this, `reach up` succeeds
	// against any reachable host and then *every* command fails with a `cd`
	// error from the target — which reads as reach being broken rather than as
	// a path being wrong, and does so once per tool call rather than once, in
	// front of the operator who typed the path.
	if a["WSOK"] == "1" {
		return nil
	}
	return fmt.Errorf(
		"%s is not a directory on %s.\n"+
			"reach will not create it: making directories on a machine you pointed at is\n"+
			"not something this tool should do uninvited. Create it there, or point reach\n"+
			"at a path that exists.%s", s.Target.Workspace, s.Target.DescribeHost(),
		s.rootedTwin(a, wrote))
}

// rootedTwin returns the sentence to add to a missing-workspace failure when
// the directory the operator may have meant is really there.
//
// A path in a target is relative unless it starts with a slash, which is what
// scp, sftp and curl do with the same spellings. reach used to read the URI
// form the other way round, so `ssh://box/srv/app` moved from /srv/app to
// ~/srv/app, and this is the one failure that change can produce.
func (s *Session) rootedTwin(a map[string]string, wrote string) string {
	if wrote == "" || a["ROOTED"] != "1" {
		return ""
	}
	rooted := "/" + strings.TrimLeft(wrote, "/")
	why := fmt.Sprintf("\n\n"+
		"%s does exist. A path is relative to where a login lands unless it starts with\n"+
		"a slash, the way scp and sftp read the same spellings. For the one at the root,\n",
		rooted)
	host := s.Target.DescribeHost()
	// scp's spelling has nowhere to put a port, so a target that carries one
	// can only be offered the URI form.
	if s.Target.Port != 0 {
		return why + fmt.Sprintf("write ssh://%s/%s.", host, rooted)
	}
	return why + fmt.Sprintf("write %s:%s or ssh://%s/%s.", host, rooted, host, rooted)
}

// tildeWord is what may appear before the first slash of a tilde path. It is a
// whitelist because the word is handed to the target's shell unquoted — that
// is the only way to get a tilde expanded — and anything outside this set
// would be the shell's to interpret rather than a username.
var tildeWord = regexp.MustCompile(`^~[A-Za-z0-9._-]*$`)

// FileOps builds the file-operation strategy for this session's tier.
//
// A pinned tier — one the operator named with --fileops — is never silently
// replaced. An autonegotiated one steps down to whatever works and says so on
// stderr, because a host that stopped answering on its usual tier should keep
// working, but not without the operator being able to see that it changed.
func (s *Session) FileOps(ctx context.Context, t transport.Transport) (fileops.Selection, error) {
	warn := func(msg string) { fmt.Fprintln(os.Stderr, msg) }
	return fileops.New(ctx, s.Tier, t, s.Caps, s.Pinned, warn)
}

// Probe connects to the target, records its capabilities, and settles which
// file-operation tier this session will use.
//
// The chosen tier is *built* here, not merely selected. Recording a tier that
// turns out to be unusable would move the failure from `reach up`, where an
// operator is present and can act on it, into the middle of an agent's turn,
// where it surfaces as a broken tool.
func (s *Session) Probe(ctx context.Context) error {
	// Multiplexing is settled before anything else is asked, because it decides
	// what asking costs. Every question below is a network round trip, and on a
	// host 285 ms away a cold connection is ~5 s against ~0.6 s for a channel on
	// an established master. Settling it last, as this used to, meant the probe
	// opened a separate authenticated connection for each of its own questions
	// and then proved that the rest of the session would not have to: 33 s of
	// connecting to establish that connecting was cheap.
	//
	// It is also still the right moment for it. The master is established with
	// the operator present, so a host that wants a passphrase, a password or a
	// hardware token asks here rather than inside a tool call that runs in batch
	// mode and cannot prompt.
	if s.Target.Kind == KindSSH {
		ok, why := transport.DetectMultiplexing(ctx, transport.SSHConfig{
			Host: s.Target.Host,
			User: s.Target.User,
			Port: s.Target.Port,
		})
		s.Multiplex = ok
		s.MultiplexNote = why
	}

	t, err := s.InteractiveTransport()
	if err != nil {
		return err
	}
	// A multiplexed transport is deliberately not closed. Close tears down the
	// master, and that master holds the authentication just performed in front
	// of the operator; throwing it away would hand the first tool call a
	// reconnect it cannot complete. `reach down` is what ends a connection.
	// Without multiplexing there is a connection per command and nothing to
	// keep, so it is closed as before.
	if !s.Multiplex {
		defer func() { _ = t.Close() }()
	}

	// One round trip asks the target everything: what its userland provides,
	// what PATH the operator really has, whether binary content survives in
	// each direction, where a login lands, and whether the workspace is there.
	// They used to be four commands, and four commands are four channel
	// handshakes — which multiplexing does not remove, and which cost more
	// between them than any single answer is worth.
	questions, wrote, err := s.workspaceQuestions()
	if err != nil {
		return err
	}
	caps, answers, err := fileops.ProbeWith(ctx, t, questions)
	if err != nil {
		return err
	}
	s.Caps = caps

	if err := s.settleWorkspace(answers, wrote); err != nil {
		return err
	}

	if !s.Pinned {
		// Autonegotiation deliberately stops below TierHelper: that tier writes
		// a binary to the target, and reach never makes that choice on the
		// operator's behalf.
		s.Tier = caps.BestTier()
	}

	sel, err := s.FileOps(ctx, t)
	if err != nil {
		return err
	}
	defer func() { _ = sel.Ops.Close() }()
	s.Tier = sel.Effective
	s.TierReason = sel.Reason
	return nil
}
