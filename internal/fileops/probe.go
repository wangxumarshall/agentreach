package fileops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/bojieli/agentreach/internal/reach"
	"github.com/bojieli/agentreach/internal/transport"
)

// Capabilities records what a target's userland actually provides.
//
// reach probes once per session instead of guessing per command. Targets are
// not uniform — GNU coreutils, BSD, busybox and toybox differ on exactly the
// utilities file operations depend on, and a wrong guess produces corrupted
// data rather than a clean error. One round trip buys deterministic behaviour
// for the rest of the session, and `reach doctor` prints the result so a
// surprising host is visible rather than mysterious.
type Capabilities struct {
	// StatFlavor is "gnu", "bsd" or "" when no usable stat exists.
	StatFlavor string
	// Base64Decode is the command that decodes base64 from stdin. GNU uses
	// -d, BSD/macOS uses -D, and openssl is the fallback when neither exists.
	Base64Decode string
	// Base64Encode is the command that encodes stdin.
	Base64Encode string
	// HasFind, HasXargs gate the listing and glob strategies.
	HasFind  bool
	HasXargs bool
	// Ripgrep is the rg binary name if present. Search is dramatically faster
	// and more accurate with it.
	Ripgrep string
	// SHA256 is the command producing a sha256 digest on stdin.
	SHA256 string
	// Python3 gates the pipe tier.
	Python3 bool
	// FindPrintf reports GNU find's -printf support, which allows NUL-safe
	// directory listing. Without it, listing cannot represent filenames
	// containing newlines.
	FindPrintf bool
	// GrepSkipBinary is the flag that makes the target's grep ignore binary
	// files, or empty when it has none. GNU, BSD and busybox all accept -I;
	// only GNU and BSD accept --binary-files=without-match, and busybox rejects
	// the whole command when given it.
	GrepSkipBinary string
	// CacheDir is where the target keeps per-user caches, resolved once so the
	// helper tier does not spend a round trip asking on every tool call.
	CacheDir string
	// HelperPath and HelperDigest record a helper binary this session has
	// already verified, so the verification costs one round trip per session
	// rather than one per tool call.
	HelperPath   string
	HelperDigest string
	// RawStdin and RawStdout report that binary content survives the transport
	// unencoded, in each direction, proven by a round trip rather than assumed.
	// When they hold, file content skips base64 and costs a third less to move.
	RawStdin  bool
	RawStdout bool
	// LoginPath is the PATH the target's own login shell would give the
	// operator, when it differs from the one a non-interactive command gets.
	// Empty means they matched and nothing needs overriding.
	LoginPath string
	// Shell is the target's /bin/sh identity, informational.
	Uname string
}

// probeScript is intentionally a single POSIX-sh program with no pipelines
// that depend on the very utilities it is testing for. It prints KEY=VALUE
// lines and must never fail: an absent tool is a value, not an error.
//
// It is one program because every command reach sends is a round trip, and a
// round trip is expensive even on a connection that is already open: measured
// against a host 200 ms away, ~0.5 s for a channel on an established master
// against ~0.2 s for a command on a channel that is already running. The cost
// is the channel handshake, which multiplexing does not remove. Asking these
// questions one at a time cost four of those to learn what one shell answers
// in 0.69 s.
//
// Order matters in three places. Stdin is put aside on fd 3 before anything
// runs, because the raw-stdin measurement is the only thing entitled to read
// it and a login profile that reads stdin would otherwise eat it. The login
// PATH is settled next and applied to the rest of the program, so what reach
// finds here is what reach can run later. And the raw-stdout measurement is
// last, because it is binary: anything printed after it would have to be
// recovered from inside it.
const probeScript = `
exec 3<&0 </dev/null
w_has() { command -v "$1" >/dev/null 2>&1; }
printf 'PLAINPATH=%s\n' "$PATH"

# A profile that hangs must cost reach the login PATH, not the whole probe.
# There is no portable timeout, so this is best-effort by design.
__reach_to=''
if w_has timeout; then __reach_to='timeout 10'; fi
w_login_path() {
  # Prefer the operator's own shell; fall back to sh. Either may be absent or
  # may refuse to be a login shell, and neither is worth failing the probe over.
  for s in "$SHELL" /bin/bash /bin/sh; do
    [ -n "$s" ] && [ -x "$s" ] || continue
    p=$($__reach_to "$s" -lc 'printf %s "$PATH"' 2>/dev/null) || continue
    [ -n "$p" ] && { printf '%s' "$p"; return 0; }
  done
  return 1
}
__reach_lp=$(w_login_path 2>/dev/null)
printf 'LOGINPATH=%s\n' "$__reach_lp"
if [ -n "$__reach_lp" ]; then PATH=$__reach_lp; fi

printf 'UNAME=%s\n' "$(uname -sm 2>/dev/null || echo unknown)"

if stat -c '%s' / >/dev/null 2>&1; then printf 'STAT=gnu\n'
elif stat -f '%z' / >/dev/null 2>&1; then printf 'STAT=bsd\n'
else printf 'STAT=\n'; fi

if w_has base64; then
  if printf 'eA==' | base64 -d >/dev/null 2>&1; then printf 'B64D=base64 -d\nB64E=base64\n'
  elif printf 'eA==' | base64 -D >/dev/null 2>&1; then printf 'B64D=base64 -D\nB64E=base64\n'
  else printf 'B64D=\nB64E=\n'; fi
elif w_has openssl; then printf 'B64D=openssl base64 -d -A\nB64E=openssl base64 -A\n'
else printf 'B64D=\nB64E=\n'; fi

w_has find  && printf 'FIND=1\n'  || printf 'FIND=0\n'
if find . -maxdepth 0 -printf '' >/dev/null 2>&1; then printf 'FINDPF=1\n'; else printf 'FINDPF=0\n'; fi
w_has xargs && printf 'XARGS=1\n' || printf 'XARGS=0\n'
w_has python3 && printf 'PY3=1\n' || printf 'PY3=0\n'

if w_has rg; then printf 'RG=rg\n'; else printf 'RG=\n'; fi

printf 'CACHE=%s\n' "${XDG_CACHE_HOME:-$HOME/.cache}"

# Which flag suppresses binary files? busybox grep accepts -I but rejects
# --binary-files=..., and rejects the *entire command* when it sees it — which
# turned every search on an Alpine target into a confident "no matches".
if printf 'x\n' | grep -I x >/dev/null 2>&1; then printf 'GREPI=-I\n'
else printf 'GREPI=\n'; fi

if w_has sha256sum; then __reach_sha='sha256sum'
elif w_has shasum; then __reach_sha='shasum -a 256'
elif w_has openssl; then __reach_sha='openssl dgst -sha256 -r'
else __reach_sha=''; fi
printf 'SHA=%s\n' "$__reach_sha"
`

// The login PATH deserves its own note, since the probe reads as though it
// asks the same question twice.
//
// `ssh host command` runs a non-interactive shell, which on Debian and Ubuntu
// returns from ~/.bashrc before reaching anything that edits PATH. So reach saw
// /usr/bin and friends while the operator's own shell had ~/.local/bin, ~/bin
// and ~/.cargo/bin as well — measured on a real host, where the two differed by
// five directories.
//
// That gap is not cosmetic. `cargo install ripgrep` is how most people get rg,
// and it lands in ~/.cargo/bin, so reach would report "no ripgrep on the
// target" and quietly fall back to grep on a machine that has it. Reporting a
// capability as absent when it is present, and degrading on that basis, is the
// failure this project exists to avoid.
//
// Both PATHs are reported because only their difference matters: a login shell
// that adds nothing is not worth overriding anything for, and the override is
// what every later command carries.

// rawProbeBlob is every byte value, plus the sequences a transport is most
// likely to mangle: a lone CR, a lone LF, CRLF, and a trailing newline that a
// naive `$(...)` capture would eat.
func rawProbeBlob() []byte {
	b := make([]byte, 0, 300)
	for i := 0; i < 256; i++ {
		b = append(b, byte(i))
	}
	return append(b, '\r', '\n', '\r', '\n', 0x00, 0xff, '\n')
}

// rawProbeMark separates the two raw-I/O answers, which share the probe's one
// round trip.
//
// It cannot occur in either half, which is what lets each be read without
// reference to the other: the first half is a digest command's output, hex and
// a filename, and the second is rawProbeBlob, which never repeats a byte
// adjacently — so a marker containing a doubled character is not a substring of
// it. A transport that garbles one half therefore still gives an honest answer
// about the other.
//
// reach has always base64-framed file content, which is unconditionally safe
// and costs a third of the bandwidth in both directions. Whether it is
// *necessary* is a property of the transport, and transports differ: an ssh
// session with no pty is 8-bit clean, while a pty translates newlines, and
// Windows ssh clients have historically translated on their own. So it is
// measured per target instead of assumed either way, and neither direction
// writes anything to the target: stdin fidelity is checked by piping the blob
// into the target's own digest command, stdout fidelity by having the target
// print it back. A target that garbles either simply keeps base64.
const rawProbeMark = "__reach_raw__"

// rawIOTail measures both directions of transport fidelity and must be the
// last thing the probe prints. See probeScript for why, and rawProbeMark for
// how the two answers stay independent.
const rawIOTail = `
printf 'DIGEST='
if [ -n "$__reach_sha" ]; then
  # Unquoted on purpose: the value is one of the fixed set chosen above, and
  # two of those are a command plus an argument.
  $__reach_sha <&3 2>/dev/null
else
  printf '\n'
fi
printf %s ` + "'" + rawProbeMark + `'
printf `

// Probe inspects a target's userland.
func Probe(ctx context.Context, t transport.Transport) (*Capabilities, error) {
	c, _, err := ProbeWith(ctx, t, "")
	return c, err
}

// ProbeWith inspects a target's userland and answers the caller's own
// questions in the same round trip.
//
// extra is POSIX sh spliced in after the login PATH has been applied and
// before the binary tail. It must print KEY=VALUE lines, must not fail, and
// must not read stdin, which belongs to the raw-stdin measurement; its answers
// come back in the returned map alongside the ones reach reads itself. It
// exists because the workspace check is a question about the same target
// asked at the same moment, and a second round trip for it would cost more
// than everything this probe measures.
func ProbeWith(ctx context.Context, t transport.Transport, extra string) (*Capabilities, map[string]string, error) {
	res, err := t.Run(ctx, probeRequest(extra))
	if err != nil {
		return nil, nil, fmt.Errorf("probe target: %w", err)
	}
	if res.Code != 0 {
		return nil, nil, fmt.Errorf("probe target: shell exited %d: %s",
			res.Code, strings.TrimSpace(string(res.Stderr)))
	}
	return parseProbe(res.Stdout)
}

// probeTimeout is a backstop, not a budget. Every question the probe asks is
// individually bounded or cannot block; this is here so that a target which
// accepts the command and then says nothing at all fails rather than hanging
// the operator's terminal.
const probeTimeout = 2 * time.Minute

// probeRequest renders the whole probe as one command and the stdin it reads.
func probeRequest(extra string) reach.ExecRequest {
	blob := rawProbeBlob()
	// printf with octal escapes is POSIX and needs nothing installed.
	var esc strings.Builder
	for _, b := range blob {
		fmt.Fprintf(&esc, "\\%03o", b)
	}
	var cmd strings.Builder
	cmd.WriteString(probeScript)
	if extra != "" {
		cmd.WriteString("\n")
		cmd.WriteString(extra)
		cmd.WriteString("\n")
	}
	cmd.WriteString(rawIOTail)
	cmd.WriteString(transport.ShellQuote(esc.String()))
	cmd.WriteString("\n")
	return reach.ExecRequest{
		Command:   cmd.String(),
		Stdin:     blob,
		MaxOutput: 256 << 10,
		Timeout:   probeTimeout,
	}
}

// parseProbe reads one probe's answers.
//
// The returned map is every KEY=VALUE line the target printed, so a caller
// that spliced its own questions in reads its own answers from the same
// output without this package having to know what they were.
func parseProbe(out []byte) (*Capabilities, map[string]string, error) {
	text, echoed, marked := bytes.Cut(out, []byte(rawProbeMark))
	answers := map[string]string{}
	for _, line := range strings.Split(string(text), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			answers[k] = v
		}
	}

	c := &Capabilities{
		Uname:          answers["UNAME"],
		StatFlavor:     answers["STAT"],
		Base64Decode:   answers["B64D"],
		Base64Encode:   answers["B64E"],
		HasFind:        answers["FIND"] == "1",
		FindPrintf:     answers["FINDPF"] == "1",
		HasXargs:       answers["XARGS"] == "1",
		Python3:        answers["PY3"] == "1",
		Ripgrep:        answers["RG"],
		GrepSkipBinary: answers["GREPI"],
		CacheDir:       answers["CACHE"],
		SHA256:         answers["SHA"],
	}
	if c.Base64Decode == "" || c.Base64Encode == "" {
		return c, answers, fmt.Errorf(
			"target has no base64 and no openssl: reach cannot move file content safely.\n"+
				"Binary-safe transfer needs one of them; without it, content would have to be\n"+
				"passed through the shell unencoded, which corrupts any file containing NUL or\n"+
				"invalid UTF-8. Target reports: %s", c.Uname)
	}

	// A login shell that adds nothing is not worth overriding anything for.
	if login := answers["LOGINPATH"]; login != answers["PLAINPATH"] && strings.Contains(login, "/") {
		c.LoginPath = login
	}

	blob := rawProbeBlob()
	sum := sha256.Sum256(blob)
	if fields := strings.Fields(answers["DIGEST"]); len(fields) > 0 {
		c.RawStdin = strings.TrimPrefix(fields[0], "\\") == hex.EncodeToString(sum[:])
	}
	c.RawStdout = marked && bytes.Equal(echoed, blob)
	return c, answers, nil
}

// pathEnv renders a PATH override, or nothing when there is none to apply.
func pathEnv(loginPath string) map[string]string {
	if loginPath == "" {
		return nil
	}
	return map[string]string{"PATH": loginPath}
}

// Env returns the environment every command on this target should carry.
func (c *Capabilities) Env() map[string]string {
	if c == nil {
		return nil
	}
	return pathEnv(c.LoginPath)
}

// Qualifies reports whether a target can support a tier, and why not when it
// cannot. The reason is shown by `reach doctor`, so an operator can see that a
// host is on tier 0 because it lacks python3 rather than because reach decided
// so for no visible reason.
func (c *Capabilities) Qualifies(tier reach.Tier) (bool, string) {
	switch tier {
	case reach.TierPOSIX:
		if c.Base64Decode == "" || c.Base64Encode == "" {
			return false, "no base64 and no openssl"
		}
		if c.StatFlavor == "" {
			return false, "no usable stat command"
		}
		return true, ""
	case reach.TierPipe:
		if !c.Python3 {
			return false, "no python3"
		}
		return true, ""
	case reach.TierHelper:
		if _, _, err := platformOf(c.Uname); err != nil {
			return false, err.Error()
		}
		return true, "writes a binary to the target; never chosen automatically"
	}
	return false, "unknown tier"
}

// negotiationOrder is the order autonegotiation prefers tiers in, most
// preferred first.
//
// Every remaining tier answers one file operation in one network round trip:
// the shell tier sends a command and reads its output, the pipe and helper
// tiers send a request and read a response. That is the property that decides
// this list, and the reason a since-removed SFTP tier is not on it: SFTP hands
// out a handle before it will read, so its floor was two.
//
// Between the survivors it is round trips and startup cost. Measured against a
// host 171 ms away, median of three runs:
//
//	                15x1KiB read   8MiB read   8MiB write
//	posix                  5.83s       6.39s        6.79s
//	pipe                   4.08s       5.19s        5.43s
//	helper                 3.93s       5.16s        5.53s
//
// pipe and helper are close, because they are the same protocol with a
// different program on the far end. posix trails on bulk because it pipes
// content through a shell, and on small reads because it spawns processes per
// operation — a gap that widens sharply on a macOS target, where process
// creation is expensive.
//
// TierHelper is deliberately absent, and no longer for performance reasons —
// it is now the fastest tier for small reads. It is absent because it writes a
// binary to a machine the operator may not own, and that is a decision reach
// does not make for them. Speed is not the argument that would justify it.
var negotiationOrder = []reach.Tier{reach.TierPipe}

// BestTier reports the tier autonegotiation would choose for this target.
func (c *Capabilities) BestTier() reach.Tier {
	for _, tier := range negotiationOrder {
		if ok, _ := c.Qualifies(tier); ok {
			return tier
		}
	}
	return reach.TierPOSIX
}
