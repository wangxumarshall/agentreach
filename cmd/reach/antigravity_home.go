package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bojieli/agentreach/internal/session"
)

// reachAntigravitySettingsMarker is written into settings.json so doctor can
// confirm the file was written by reach.
const reachAntigravitySettingsMarker = "reach-managed"

// managedAntigravityHome creates (or refreshes) the managed HOME directory reach
// launches Antigravity (agy) with.
func managedAntigravityHome(s *session.Session) (string, error) {
	base := os.Getenv("REACH_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}
		base = filepath.Join(home, ".reach")
	}
	sessName := s.Name
	dir := filepath.Join(base, "antigravity-home", sessName)
	geminiDir := filepath.Join(dir, ".gemini")
	agyDir := filepath.Join(geminiDir, "antigravity-cli")
	antigravityDir := filepath.Join(geminiDir, "antigravity")
	rulesDir := filepath.Join(geminiDir, "rules")
	configRulesDir := filepath.Join(geminiDir, "config", "rules")
	for _, d := range []string{agyDir, antigravityDir, rulesDir, configRulesDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", fmt.Errorf("create %s: %w", d, err)
		}
	}

	// Write controlled settings.json in both .gemini and .gemini/antigravity-cli
	if err := writeManagedAntigravitySettings(geminiDir); err != nil {
		return "", err
	}
	if err := writeManagedAntigravitySettings(agyDir); err != nil {
		return "", err
	}

	// Write remote workspace guidance into GEMINI.md and rule files in all locations
	if err := writeRemoteGuidance(dir, geminiDir, agyDir, antigravityDir, rulesDir, configRulesDir, s); err != nil {
		return "", err
	}

	// Link credential files from the real ~/.gemini
	realHome, err := os.UserHomeDir()
	if err != nil {
		realHome = os.Getenv("HOME")
	}
	realGeminiDir := filepath.Join(realHome, ".gemini")
	for _, f := range []string{
		"google-accounts.json",
		"installation_id",
	} {
		src := filepath.Join(realGeminiDir, f)
		dst := filepath.Join(geminiDir, f)
		if _, err := os.Lstat(src); err != nil {
			continue
		}
		if _, err := os.Lstat(dst); err == nil {
			continue
		}
		_ = os.Symlink(src, dst)
	}

	return dir, nil
}

func writeRemoteGuidance(dir, geminiDir, agyDir, antigravityDir, rulesDir, configRulesDir string, s *session.Session) error {
	remoteCwd := s.Cwd()
	targetDesc := s.Target.Describe()
	hostDesc := s.Target.DescribeHost()

	content := fmt.Sprintf(`<!-- agentreach-remote:start -->
# CRITICAL OVERRIDE: REMOTE LINUX DEVELOPMENT ENVIRONMENT (AGENTREACH)

YOU ARE WORKING DIRECTLY ON A REMOTE LINUX SERVER OVER SSH.
- Remote Target Host: %s
- Remote Target Spec: %s
- Remote Operating System: Linux (POSIX Environment)
- Remote Working Directory: %s

## MANDATORY OPERATING RULES:
1. **LINUX / POSIX COMMANDS ONLY**: The remote target is a real Linux server. You MUST ALWAYS write standard Linux bash commands (e.g. ls -la, cat, grep -rn, find, sed, git, make, python3, tar, etc.).
2. **NEVER USE WINDOWS / POWERSHELL / CMD COMMANDS**: Do NOT use Get-ChildItem, Get-Content, dir, type, cls, Select-String, etc. They will FAIL on Linux.
3. **NEVER REFERENCE LOCAL WINDOWS PATHS**: Do not use drive letters (C:\) or backslashes. All paths are Linux paths relative to '%s' or absolute Linux paths ('/home/sdc/...').
4. **ALL OPERATIONS VIA REMOTE SHELL**:
   - List files: ls -la / find . -maxdepth 2
   - Read files: cat <path> / sed -n '1,100p' <path> / head -n 50 <path>
   - Search code: grep -rn "pattern" . (or rg "pattern" .)
   - Edit / Write files: cat << 'EOF' > <path>, sed -i, python3 -c "...", or patch
   - Git & Build: git status, git diff, make, pytest, etc.
5. **EVERY COMMAND EXECUTES REMOTELY**: Every shell command you issue executes 100%% directly on the remote Linux machine in '%s'.
<!-- agentreach-remote:end -->
`, hostDesc, targetDesc, remoteCwd, remoteCwd, remoteCwd)

	for _, d := range []string{dir, geminiDir, agyDir, antigravityDir} {
		p := filepath.Join(d, "GEMINI.md")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
	}
	for _, d := range []string{rulesDir, configRulesDir} {
		p := filepath.Join(d, "remote-linux.md")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
	}
	return nil
}

func writeManagedAntigravitySettings(dir string) error {
	settings := map[string]any{
		"_reach":     reachAntigravitySettingsMarker,
		"mcpServers": map[string]any{},
		"excludeTools": []string{
			"Read", "ListDir", "Write", "Edit", "Glob", "Grep", "ViewFile",
			"ListDirectory", "ReadFile", "WriteFile", "ReplaceFileContent", "WriteToFile",
			"GrepSearch", "FindByName", "ReadUrlContent", "SearchWeb", "GenerateImage",
			"AskQuestion", "InvokeSubagent", "DefineSubagent", "ManageSubagents",
			"read_file", "write_file", "replace", "replace_file_content", "write_to_file",
			"view_file", "glob", "grep_search", "find_by_name", "list_directory", "list_dir",
			"read_many_files", "web_fetch", "read_url_content", "google_web_search", "search_web",
			"generate_image", "ask_question", "invoke_agent", "invoke_subagent", "define_subagent",
			"manage_subagents", "read_mcp_resource", "list_mcp_resources",
		},
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal antigravity settings.json: %w", err)
	}
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
