package session

import (
	"strings"
	"testing"

	"github.com/bojieli/agentreach/internal/reach"
)

func targetSession(t *testing.T, spec string) *Session {
	t.Helper()
	tgt, err := ParseTarget(spec)
	if err != nil {
		t.Fatal(err)
	}
	return &Session{Name: "t", Target: tgt, Mode: ModeExec, Tier: reach.TierPOSIX}
}

// settle runs the two halves of workspace resolution the way Probe does: the
// shell reach splices into the capability probe, and the answers it reads back
// out of that one round trip.
//
// answers stands in for what the target printed. The tests supply it directly
// rather than through a transport because the interesting behaviour is what
// reach asks and what it makes of the reply, and both are now on this side of
// a single command.
func settle(t *testing.T, s *Session, answers map[string]string) (string, error) {
	t.Helper()
	script, wrote, err := s.workspaceQuestions()
	if err != nil {
		return script, err
	}
	return script, s.settleWorkspace(answers, wrote)
}

// A path with no leading slash is resolved against the directory a login lands
// in, which is what scp does with the same spelling and what an operator who
// typed `box:app` is asking for.
func TestResolveWorkspaceIsRelativeToTheLoginDir(t *testing.T) {
	for _, spec := range []string{"box:srv/app", "ssh://box/srv/app"} {
		s := targetSession(t, spec)
		script, wrote, err := s.workspaceQuestions()
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		// The join is the target's, because only the target knows where a
		// login lands — and asking it separately would cost a round trip.
		if !strings.Contains(script, `__reach_ws="$(pwd)"/srv/app`) {
			t.Errorf("%s does not join against the login directory:\n%s", spec, script)
		}
		if wrote != "srv/app" {
			t.Errorf("%s reported %q as the relative spelling", spec, wrote)
		}

		err = s.settleWorkspace(map[string]string{
			"LOGINDIR": "/home/me", "WORKSPACE": "/home/me/srv/app", "WSOK": "1",
		}, wrote)
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
	}
}

// An absolute path is already an answer. It is sent as a literal rather than
// assembled from anything the target has to be asked for first, which is what
// used to make it the one spelling that cost no extra round trip — and now
// makes it the one spelling that needs nothing from the reply but a yes.
func TestResolveWorkspaceAsksNothingForAnAbsolutePath(t *testing.T) {
	for _, spec := range []string{"box:/srv/app", "ssh://box//srv/app"} {
		s := targetSession(t, spec)
		script, wrote, err := s.workspaceQuestions()
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if !strings.Contains(script, "__reach_ws=/srv/app\n") {
			t.Errorf("%s did not send the path as written:\n%s", spec, script)
		}
		if wrote != "" {
			t.Errorf("%s reported %q as a relative spelling", spec, wrote)
		}

		if err := s.settleWorkspace(map[string]string{
			"LOGINDIR": "/home/me", "WORKSPACE": "/srv/app", "WSOK": "1",
		}, wrote); err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if s.Target.Workspace != "/srv/app" {
			t.Errorf("%s resolved to %q", spec, s.Target.Workspace)
		}
	}
}

func TestResolveWorkspaceWithNoPathIsTheLoginDir(t *testing.T) {
	s := targetSession(t, "box:")
	if _, err := settle(t, s, map[string]string{
		"LOGINDIR": "/home/me", "WORKSPACE": "/home/me", "WSOK": "1",
	}); err != nil {
		t.Fatal(err)
	}
	if s.Target.Workspace != "/home/me" {
		t.Errorf("workspace is %q, want the login directory", s.Target.Workspace)
	}
}

// Only the target can expand a tilde: ~ is its home directory and ~someone is
// a question about its passwd database. So the word goes over unquoted and the
// target's shell does the expanding.
func TestResolveWorkspaceExpandsATilde(t *testing.T) {
	for _, tc := range []struct{ spec, send, answer, want string }{
		{"box:~/app", "__reach_ws=~/app", "/home/me/app", "/home/me/app"},
		{"box:~", "__reach_ws=~\n", "/home/me", "/home/me"},
		{"box:~deploy/app", "__reach_ws=~deploy/app", "/srv/deploy/app", "/srv/deploy/app"},
	} {
		s := targetSession(t, tc.spec)
		script, err := settle(t, s, map[string]string{
			"LOGINDIR": "/home/me", "WORKSPACE": tc.answer, "WSOK": "1",
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.spec, err)
		}
		if !strings.Contains(script, tc.send) {
			t.Errorf("%s does not hand the tilde to the target's shell:\n%s", tc.spec, script)
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
	_, err := settle(t, s, map[string]string{
		"LOGINDIR": "/home/me", "WORKSPACE": "~nobody/app", "WSOK": "0",
	})
	if err == nil || !strings.Contains(err.Error(), "no such user") {
		t.Fatalf("error is %v, want it to say the target did not expand the tilde", err)
	}
}

// The tilde word is handed to the target's shell unquoted, because that is the
// only way to get it expanded. Anything that is not a username must be refused
// here rather than sent.
func TestResolveWorkspaceRefusesAShellConstructBeforeSendingIt(t *testing.T) {
	s := targetSession(t, "box:~$(id)/app")
	script, _, err := s.workspaceQuestions()
	if err == nil {
		t.Fatal("a shell construct was accepted as a username")
	}
	if strings.Contains(script, "id") {
		t.Errorf("it was put in the script anyway:\n%s", script)
	}
}

// A target that cannot say where a login lands is not a target reach can work
// on, and saying so beats resolving to something that is not a path.
func TestResolveWorkspaceRefusesATargetWithNoLoginDirectory(t *testing.T) {
	s := targetSession(t, "box:srv/app")
	_, err := settle(t, s, map[string]string{"WORKSPACE": "/srv/app", "WSOK": "1"})
	if err != nil {
		t.Fatalf("a target that answered with a path was refused: %v", err)
	}

	s = targetSession(t, "box:srv/app")
	_, err = settle(t, s, map[string]string{"WORKSPACE": "srv/app", "WSOK": "1"})
	if err == nil || !strings.Contains(err.Error(), "where a login starts") {
		t.Fatalf("error is %v, want it to say the target would not name a directory", err)
	}
}

// The failure this change can produce: a target spelled the way reach read it
// before it followed scp now names a directory under the login directory, and
// the one the operator meant is still at the root. The twin is asked about in
// the same round trip, so the diagnosis costs nothing when it is not needed.
func TestCheckWorkspaceNamesTheDirectoryAtTheRoot(t *testing.T) {
	s := targetSession(t, "ssh://box/srv/app")
	script, err := settle(t, s, map[string]string{
		"LOGINDIR": "/home/me", "WORKSPACE": "/home/me/srv/app", "WSOK": "0", "ROOTED": "1",
	})
	if err == nil {
		t.Fatal("a missing workspace was accepted")
	}
	if !strings.Contains(script, "if [ -d /srv/app ]") {
		t.Errorf("the twin was not asked about in the same round trip:\n%s", script)
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
	_, err := settle(t, s, map[string]string{
		"LOGINDIR": "/home/me", "WORKSPACE": "/home/me/srv/app", "WSOK": "0", "ROOTED": "1",
	})
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
	_, err := settle(t, s, map[string]string{
		"LOGINDIR": "/home/me", "WORKSPACE": "/home/me/srv/app", "WSOK": "0", "ROOTED": "0",
	})
	if err == nil {
		t.Fatal("a missing workspace was accepted")
	}
	if strings.Contains(err.Error(), "does exist") {
		t.Errorf("offered a directory that is not there either:\n%v", err)
	}
}

// An absolute spelling has no twin at the root — it *is* the one at the root —
// so nothing is asked about and nothing is offered.
func TestCheckWorkspaceAsksAboutNoTwinForAnAbsolutePath(t *testing.T) {
	s := targetSession(t, "box:/srv/app")
	script, err := settle(t, s, map[string]string{
		"LOGINDIR": "/home/me", "WORKSPACE": "/srv/app", "WSOK": "0",
	})
	if err == nil {
		t.Fatal("a missing workspace was accepted")
	}
	if strings.Contains(script, "ROOTED") {
		t.Errorf("asked about a twin that cannot exist:\n%s", script)
	}
	if strings.Contains(err.Error(), "does exist") {
		t.Errorf("offered a twin for a path that was already absolute:\n%v", err)
	}
}
