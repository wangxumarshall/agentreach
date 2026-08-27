package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bojieli/agentreach/internal/harnessprobe"
	"github.com/bojieli/agentreach/internal/session"
)

// cmdAntigravity launches Antigravity CLI (agy) against the session's target.
func cmdAntigravity(ctx context.Context, args []string) int {
	fs := newFlagSet("antigravity")
	name := fs.String("session", "", "session name (default $REACH_SESSION)")
	force := fs.Bool("force", false,
		"launch without verifying the shell seam (the agent's commands may run LOCALLY)")
	pos, err := parseHarnessArgs(fs, args)
	if err != nil {
		return 2
	}

	sessName := sessionNameFromEnv(*name)

	s, err := session.Load(sessName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reach:", err)
		return 1
	}

	binPath, err := lookHarnessPath("agy")
	if err != nil {
		binPath, err = lookHarnessPath("antigravity")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "reach: agy / antigravity is not installed or not in PATH")
		return 1
	}

	shimDir, err := ensurePathShim()
	if err != nil {
		fmt.Fprintln(os.Stderr, "reach:", err)
		return 1
	}

	agyHome, err := managedAntigravityHome(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reach:", err)
		return 1
	}

	// REACH_EXEC_WORKSPACE tells the PATH shim where the operator's project
	// root is so it can rewrite embedded `cd '<local-cwd>' && ...` prefix
	// to the session's target workspace.
	cwd, _ := os.Getwd()

	if *force {
		fmt.Fprintln(os.Stderr,
			"reach: WARNING: --force skips the antigravity seam verification.\n"+
				"reach: If the PATH shim fails to intercept antigravity's shell calls,\n"+
				"reach: its commands will run on the LOCAL machine while appearing remote.")
	} else if rc := guardHarnessSeam(ctx, harnessprobe.HarnessAntigravity, sessName); rc != 0 {
		return rc
	}

	env := replaceEnv(os.Environ(), "HOME", agyHome)
	env = replaceEnv(env, "USERPROFILE", agyHome)
	if vol := filepath.VolumeName(agyHome); vol != "" {
		env = replaceEnv(env, "HOMEDRIVE", vol)
		env = replaceEnv(env, "HOMEPATH", strings.TrimPrefix(agyHome, vol))
	}
	env = replaceEnv(env, "ANTIGRAVITY_HOME", agyHome)
	env = replaceEnv(env, "GEMINI_HOME", agyHome)
	env = replaceEnv(env, "REACH_SESSION", sessName)
	env = append(env, "REACH_EXEC_WORKSPACE="+cwd)
	env = prependPath(env, shimDir)

	fmt.Fprintf(os.Stderr,
		"reach: Antigravity -> %s (shell via PATH shim; file tools excluded)\n",
		s.Target.Describe())

	argv := append([]string{binPath}, pos...)
	return replaceProcessInDir(ctx, binPath, argv, env, agyHome)
}

// cmdAgy is an alias for cmdAntigravity.
func cmdAgy(ctx context.Context, args []string) int {
	return cmdAntigravity(ctx, args)
}
