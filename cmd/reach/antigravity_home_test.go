package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bojieli/agentreach/internal/session"
)

func TestManagedAntigravityHome(t *testing.T) {
	s := &session.Session{
		Name: "test-sess",
		Target: &session.Target{
			Kind:      session.KindSSH,
			Host:      "test-box",
			Workspace: "/srv/app",
		},
	}
	dir, err := managedAntigravityHome(s)
	if err != nil {
		t.Fatalf("managedAntigravityHome: %v", err)
	}
	defer os.RemoveAll(dir)

	settingsPath := filepath.Join(dir, ".gemini", "settings.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}

	var st struct {
		Reach        string   `json:"_reach"`
		ExcludeTools []string `json:"excludeTools"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("unmarshal settings.json: %v", err)
	}
	if st.Reach != reachAntigravitySettingsMarker {
		t.Errorf("expected marker %q, got %q", reachAntigravitySettingsMarker, st.Reach)
	}
	if len(st.ExcludeTools) == 0 {
		t.Errorf("expected excludeTools to be populated")
	}

	geminiMDPath := filepath.Join(dir, ".gemini", "GEMINI.md")
	mdData, err := os.ReadFile(geminiMDPath)
	if err != nil {
		t.Fatalf("read GEMINI.md: %v", err)
	}
	if len(mdData) == 0 {
		t.Errorf("expected GEMINI.md to be populated")
	}
}
