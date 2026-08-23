package session

import (
	"context"
	"strings"
	"testing"

	"github.com/bojieli/agentreach/internal/reach"
	"github.com/bojieli/agentreach/internal/transport"
)

// scriptedTransport answers commands from a table and records what it was
// asked, which is how these tests check the round trips reach did not take as
// well as the answers it got.
type scriptedTransport struct {
	answers map[string]string // substring of the command -> stdout
	fail    map[string]bool   // substring of the command -> exit 1
	ran     []string
}

func (s *scriptedTransport) Run(_ context.Context, req reach.ExecRequest) (reach.ExecResult, error) {
	s.ran = append(s.ran, req.Command)
	for pat, ok := range s.fail {
		if strings.Contains(req.Command, pat) && ok {
			return reach.ExecResult{Code: 1}, nil
		}
	}
	for pat, out := range s.answers {
		if strings.Contains(req.Command, pat) {
			return reach.ExecResult{Stdout: []byte(out)}, nil
		}
	}
	// Anything unlisted succeeds with no output: the tests say which commands
	// fail, so a missing entry must not read as a failure by accident.
	return reach.ExecResult{}, nil
}

func (s *scriptedTransport) Open(context.Context, string) (transport.Stream, error) {
	return transport.Stream{}, nil
}
func (s *scriptedTransport) Describe() string { return "scripted" }
func (s *scriptedTransport) Close() error     { return nil }

func targetSession(t *testing.T, spec string) *Session {
	t.Helper()
	tgt, err := ParseTarget(spec)
	if err != nil {
		t.Fatal(err)
	}
	return &Session{Name: "t", Target: tgt, Mode: ModeExec, Tier: reach.TierPOSIX}
}

// A path with no leading slash is resolved against the directory a login lands
// in, which is what scp does with the same spelling and what an operator who
// typed `box:app` is asking for.
func TestResolveWorkspaceIsRelativeToTheLoginDir(t *testing.T) {
	for _, spec := range []string{"box:srv/app", "ssh://box/srv/app"} {
		s := targetSession(t, spec)
		tr := &scriptedTransport{answers: map[string]string{"pwd": "/home/me\n"}}

		wrote, err := s.resolveWorkspace(context.Background(), tr)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if s.Target.Workspace != "/home/me/srv/app" {
			t.Errorf("%s resolved to %q, want /home/me/srv/app", spec, s.Target.Workspace)
		}
		// Recorded so a second `reach box:srv/app claude` can tell it is the
		// same place without asking the host again.
		if s.Target.LoginDir != "/home/me" {
			t.Errorf("%s left LoginDir %q", spec, s.Target.LoginDir)
		}
		if wrote != "srv/app" {
			t.Errorf("%s reported %q as the relative spelling", spec, wrote)
		}
	}
}

// An absolute path is already an answer, and asking the target for one costs a
// round trip on every session that names its directory in full.
func TestResolveWorkspaceAsksNothingForAnAbsolutePath(t *testing.T) {
	for _, spec := range []string{"box:/srv/app", "ssh://box//srv/app"} {
		s := targetSession(t, spec)
		tr := &scriptedTransport{}

		wrote, err := s.resolveWorkspace(context.Background(), tr)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if s.Target.Workspace != "/srv/app" || wrote != "" {
			t.Errorf("%s resolved to %q (wrote %q)", spec, s.Target.Workspace, wrote)
		}
		if len(tr.ran) != 0 {
			t.Errorf("%s asked the target %v", spec, tr.ran)
		}
	}
}

func TestResolveWorkspaceWithNoPathIsTheLoginDir(t *testing.T) {
	s := targetSession(t, "box:")
	tr := &scriptedTransport{answers: map[string]string{"pwd": "/home/me\n"}}

	if _, err := s.resolveWorkspace(context.Background(), tr); err != nil {
		t.Fatal(err)
	}
	if s.Target.Workspace != "/home/me" {
		t.Errorf("workspace is %q, want the login directory", s.Target.Workspace)
	}
}

// Only the target can expand a tilde: ~ is its home directory and ~someone is
// a question about its passwd database.
func TestResolveWorkspaceExpandsATilde(t *testing.T) {
	for _, tc := range []struct{ spec, expand, want string }{
		{"box:~/app", "/home/me\n", "/home/me/app"},
		{"box:~", "/home/me\n", "/home/me"},
		{"box:~deploy/app", "/srv/deploy\n", "/srv/deploy/app"},
	} {
		s := targetSession(t, tc.spec)
		tr := &scriptedTransport{answers: map[string]string{"printf": tc.expand}}

		if _, err := s.resolveWorkspace(context.Background(), tr); err != nil {
			t.Fatalf("%s: %v", tc.spec, err)
		}
		if s.Target.Workspace != tc.want {
			t.Errorf("%s resolved to %q, want %q", tc.spec, s.Target.Workspace, tc.want)
		}
	}
}

// A shell that cannot expand a tilde leaves it alone rather than failing, so
// the word coming back unchanged is the only sign that there is no such user.
func TestResolveWorkspaceRefusesATildeTheTargetLeftAlone(t *testing.T) {
	s := targetSession(t, "box:~nobody/app")
	tr := &scriptedTransport{answers: map[string]string{"printf": "~nobody\n"}}

	_, err := s.resolveWorkspace(context.Background(), tr)
	if err == nil || !strings.Contains(err.Error(), "no such user") {
		t.Fatalf("error is %v, want it to say the target did not expand the tilde", err)
	}
}

// The tilde word is handed to the target's shell unquoted, because that is the
// only way to get it expanded. Anything that is not a username must be refused
// here rather than sent.
func TestResolveWorkspaceRefusesAShellConstructBeforeSendingIt(t *testing.T) {
	s := targetSession(t, "box:~$(id)/app")
	tr := &scriptedTransport{answers: map[string]string{"printf": "/tmp\n"}}

	_, err := s.resolveWorkspace(context.Background(), tr)
	if err == nil {
		t.Fatal("a shell construct was accepted as a username")
	}
	if len(tr.ran) != 0 {
		t.Errorf("it was sent to the target anyway: %v", tr.ran)
	}
}

// The failure this change can produce: a target spelled the way reach read it
// before it followed scp now names a directory under the login directory, and
// the one the operator meant is still at the root.
func TestCheckWorkspaceNamesTheDirectoryAtTheRoot(t *testing.T) {
	s := targetSession(t, "ssh://box/srv/app")
	tr := &scriptedTransport{
		answers: map[string]string{"pwd": "/home/me\n"},
		fail:    map[string]bool{"test -d /home/me/srv/app": true},
	}
	wrote, err := s.resolveWorkspace(context.Background(), tr)
	if err != nil {
		t.Fatal(err)
	}

	err = s.checkWorkspace(context.Background(), tr, wrote)
	if err == nil {
		t.Fatal("a missing workspace was accepted")
	}
	for _, want := range []string{"/home/me/srv/app is not a directory", "/srv/app does exist",
		"box:/srv/app", "ssh://box//srv/app"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

// scp's spelling has nowhere to put a port, so a target that carries one can
// only be told about the spelling that does.
func TestCheckWorkspaceOffersOnlyTheURIWhenAPortIsCarried(t *testing.T) {
	s := targetSession(t, "ssh://box:2222/srv/app")
	tr := &scriptedTransport{
		answers: map[string]string{"pwd": "/home/me\n"},
		fail:    map[string]bool{"test -d /home/me/srv/app": true},
	}
	wrote, err := s.resolveWorkspace(context.Background(), tr)
	if err != nil {
		t.Fatal(err)
	}

	err = s.checkWorkspace(context.Background(), tr, wrote)
	if err == nil {
		t.Fatal("a missing workspace was accepted")
	}
	if !strings.Contains(err.Error(), "ssh://box:2222//srv/app") {
		t.Errorf("error does not offer the URI spelling:\n%v", err)
	}
	if strings.Contains(err.Error(), "box:2222:/srv/app") {
		t.Errorf("error offers a spelling that cannot carry the port:\n%v", err)
	}
}

// The hint is only true when the other directory is really there. Offering it
// unconditionally would send an operator to a path that does not exist either.
func TestCheckWorkspaceStaysQuietWhenThereIsNoOtherDirectory(t *testing.T) {
	s := targetSession(t, "ssh://box/srv/app")
	tr := &scriptedTransport{
		answers: map[string]string{"pwd": "/home/me\n"},
		fail:    map[string]bool{"test -d": true},
	}
	wrote, err := s.resolveWorkspace(context.Background(), tr)
	if err != nil {
		t.Fatal(err)
	}

	err = s.checkWorkspace(context.Background(), tr, wrote)
	if err == nil {
		t.Fatal("a missing workspace was accepted")
	}
	if strings.Contains(err.Error(), "does exist") {
		t.Errorf("offered a directory that is not there either:\n%v", err)
	}
}
