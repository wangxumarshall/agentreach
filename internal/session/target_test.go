package session

import "testing"

func TestParseTargetForms(t *testing.T) {
	cases := []struct {
		spec      string
		kind      Kind
		host      string
		user      string
		port      int
		container string
		workspace string
	}{
		// scp's spelling, which is where the rules come from: a path is
		// relative to where a login lands unless it starts with a slash.
		{"box:srv/app", KindSSH, "box", "", 0, "", "srv/app"},
		{"box:/srv/app", KindSSH, "box", "", 0, "", "/srv/app"},
		{"root@box:/srv/app", KindSSH, "box", "root", 0, "", "/srv/app"},
		{"box:~/src/app", KindSSH, "box", "", 0, "", "~/src/app"},
		{"box:~deploy/app", KindSSH, "box", "", 0, "", "~deploy/app"},
		// OpenSSH's URI spelling reads the same way, because its own parser
		// consumes the slash that ends the host. A second slash is what makes
		// a path in it absolute — see the note on ParseTarget.
		{"ssh://box/srv/app", KindSSH, "box", "", 0, "", "srv/app"},
		{"ssh://box//srv/app", KindSSH, "box", "", 0, "", "/srv/app"},
		{"ssh://root@box:2222//srv/app", KindSSH, "box", "root", 2222, "", "/srv/app"},
		{"ssh://root@box:2222/srv/app", KindSSH, "box", "root", 2222, "", "srv/app"},
		// An ssh_config alias must survive untouched, since reach delegates
		// destination resolution to the user's ssh client.
		{"ssh://my-alias//srv/app", KindSSH, "my-alias", "", 0, "", "/srv/app"},
		// docker cp's rule: container paths are relative to the container's
		// root, so the leading slash is optional and both spellings are one
		// directory.
		{"docker://mycontainer/work", KindDocker, "", "", 0, "mycontainer", "/work"},
		{"docker://mycontainer//work", KindDocker, "", "", 0, "mycontainer", "/work"},
		{"podman://c1/work", KindPodman, "", "", 0, "c1", "/work"},
		{"local:///tmp/x", KindLocal, "", "", 0, "", "/tmp/x"},
		// No path: the session works wherever a login on that target lands,
		// which Probe resolves and records. The short spellings are what make
		// `reach build-box claude` typable.
		{"ssh://build-box", KindSSH, "build-box", "", 0, "", ""},
		{"ssh://build-box/", KindSSH, "build-box", "", 0, "", ""},
		{"ssh://root@build-box:2222", KindSSH, "build-box", "root", 2222, "", ""},
		{"build-box:", KindSSH, "build-box", "", 0, "", ""},
		{"docker://c1", KindDocker, "", "", 0, "c1", ""},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.spec)
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", c.spec, err)
			continue
		}
		if got.Kind != c.kind || got.Host != c.host || got.User != c.user ||
			got.Port != c.port || got.Container != c.container || got.Workspace != c.workspace {
			t.Errorf("ParseTarget(%q) = %+v, want workspace %q", c.spec, got, c.workspace)
		}
	}
}

// The two ssh spellings are the same grammar with a different delimiter, and
// an operator who switches between them must not land somewhere else.
func TestSSHSpellingsAgree(t *testing.T) {
	for _, c := range []struct{ colon, uri string }{
		{"box:srv/app", "ssh://box/srv/app"},
		{"box:/srv/app", "ssh://box//srv/app"},
		{"box:", "ssh://box"},
		{"root@box:app", "ssh://root@box/app"},
	} {
		a, err := ParseTarget(c.colon)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", c.colon, err)
		}
		b, err := ParseTarget(c.uri)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", c.uri, err)
		}
		if a.Workspace != b.Workspace || a.Host != b.Host || a.User != b.User {
			t.Errorf("%q and %q disagree: %+v against %+v", c.colon, c.uri, a, b)
		}
	}
}

func TestParseTargetRejectsBadInput(t *testing.T) {
	for _, spec := range []string{
		"",                 // empty
		"ftp://box/srv",    // unsupported scheme
		"docker:///srv",    // no container name
		"ssh:///srv/app",   // no host
		"justastring",      // no scheme and no colon
		"local://box/tmp",  // local names no machine
		"local://relative", // ... and its path must be absolute
		`C:\src\app`,       // a Windows path, not a host called C
	} {
		if _, err := ParseTarget(spec); err == nil {
			t.Errorf("ParseTarget(%q) should have failed", spec)
		}
	}
}

// Describe is printed in messages an operator may copy back onto the command
// line, so whatever it prints has to name the same directory when it is read
// again. The port case is the interesting one: scp's spelling has nowhere to
// put a port, so Describe falls back to the URI form and has to remember that
// an absolute path there carries two slashes.
func TestDescribeRoundTrips(t *testing.T) {
	for _, spec := range []string{
		"box:srv/app",
		"box:/srv/app",
		"root@box:/srv/app",
		"ssh://box/srv/app",
		"ssh://box//srv/app",
		"ssh://root@box:2222//srv/app",
		"ssh://root@box:2222/srv/app",
		"ssh://build-box",
		"docker://c1/work",
		"podman://c1/work",
		"local:///tmp/x",
	} {
		first, err := ParseTarget(spec)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", spec, err)
		}
		again, err := ParseTarget(first.Describe())
		if err != nil {
			t.Errorf("Describe() of %q gave %q, which does not parse: %v", spec, first.Describe(), err)
			continue
		}
		if again.Kind != first.Kind || again.Host != first.Host || again.User != first.User ||
			again.Port != first.Port || again.Container != first.Container ||
			again.Workspace != first.Workspace {
			t.Errorf("%q describes as %q, which reads back as %+v", spec, first.Describe(), again)
		}
	}
}

func TestDescribeIsStable(t *testing.T) {
	for _, c := range []struct{ spec, want string }{
		// A port has to be carried, so this one keeps the URI spelling.
		{"ssh://root@box:2222//srv/app", "ssh://root@box:2222//srv/app"},
		// Everything else is rendered the way most operators type it.
		{"ssh://box//srv/app", "box:/srv/app"},
		{"root@box:/srv/app", "root@box:/srv/app"},
		{"ssh://build-box", "build-box:"},
		{"docker://c1/work", "docker://c1/work"},
		{"local:///tmp/x", "local:///tmp/x"},
	} {
		got, err := ParseTarget(c.spec)
		if err != nil {
			t.Fatal(err)
		}
		if d := got.Describe(); d != c.want {
			t.Errorf("ParseTarget(%q).Describe() = %q, want %q", c.spec, d, c.want)
		}
	}
}

// Only a path that has to be resolved against the target should cost the round
// trip that resolving it takes.
func TestNeedsLoginDir(t *testing.T) {
	for _, c := range []struct {
		spec string
		want bool
	}{
		{"box:", true},
		{"box:srv/app", true},
		{"box:/srv/app", false},
		{"box:~/app", false},
		{"ssh://box/app", true},
		{"ssh://box//app", false},
	} {
		got, err := ParseTarget(c.spec)
		if err != nil {
			t.Fatal(err)
		}
		if got.NeedsLoginDir() != c.want {
			t.Errorf("ParseTarget(%q).NeedsLoginDir() = %v, want %v", c.spec, !c.want, c.want)
		}
	}
}

// ResolveLike is how a second `reach box:app claude` finds the session the
// first one made. It must answer only when it knows, because the alternative
// to an answer is a probe, and the alternative to a right answer is a session
// bound to the wrong directory.
func TestResolveLike(t *testing.T) {
	probed := &Target{Kind: KindSSH, Host: "box", Workspace: "/home/me/app", LoginDir: "/home/me"}
	for _, c := range []struct {
		ws   string
		want string
		ok   bool
	}{
		{"app", "/home/me/app", true},
		{"./app", "/home/me/app", true},
		{"other", "/home/me/other", true},
		{"/home/me/app", "/home/me/app", true},
		{"~/app", "", false}, // only the target can expand it
		{"", "", false},
	} {
		got, ok := probed.ResolveLike(c.ws)
		if ok != c.ok || got != c.want {
			t.Errorf("ResolveLike(%q) = %q, %v; want %q, %v", c.ws, got, ok, c.want, c.ok)
		}
	}

	// A session recorded before reach kept the login directory cannot answer
	// for a relative path, and must say so rather than guess.
	old := &Target{Kind: KindSSH, Host: "box", Workspace: "/home/me/app"}
	if _, ok := old.ResolveLike("app"); ok {
		t.Error("resolved a relative path with no recorded login directory")
	}
}
