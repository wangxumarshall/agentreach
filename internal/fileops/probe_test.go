package fileops_test

import (
	"context"
	"sync"
	"testing"

	"github.com/bojieli/agentreach/internal/fileops"
	"github.com/bojieli/agentreach/internal/reach"
	"github.com/bojieli/agentreach/internal/transport"
)

// countingTransport records how many commands were sent, and passes each on to
// a real transport so the answers stay real.
type countingTransport struct {
	transport.Transport
	mu  sync.Mutex
	run int
}

func (c *countingTransport) Run(ctx context.Context, req reach.ExecRequest) (reach.ExecResult, error) {
	c.mu.Lock()
	c.run++
	c.mu.Unlock()
	return c.Transport.Run(ctx, req)
}

func (c *countingTransport) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.run
}

// maxProbeRoundTrips is what a capability probe is allowed to cost.
//
// One. Everything reach needs to know about a target — what PATH the operator
// really has, what the userland provides, whether binary content survives in
// each direction, and whatever the caller spliced in — is answered by a single
// shell program. A second command here is a second round trip, and this number
// is what makes adding one a decision rather than an accident.
const maxProbeRoundTrips = 1

// TestProbeCostsOneRoundTrip is a performance property with a correctness
// consequence, so it is asserted rather than measured by hand.
//
// A probe question is a network round trip, and against a real host that is
// ~0.5 s on an established connection and several seconds on a new one. The
// probe used to ask five, which on a link with any latency made `reach
// <target>` feel broken — half a minute before the agent started — and an
// operator who thinks a tool is hung reaches for the one thing that definitely
// works, which is installing the agent on the target.
func TestProbeCostsOneRoundTrip(t *testing.T) {
	tr := &countingTransport{Transport: localTransport(t)}
	if _, err := fileops.Probe(context.Background(), tr); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if n := tr.count(); n > maxProbeRoundTrips {
		t.Errorf("the capability probe cost %d round trips, and may cost %d.\n"+
			"Fold the new question into the probe script, or raise the limit and say why.",
			n, maxProbeRoundTrips)
	}
}

// TestProbeWithAnswersTheCallersQuestionsToo: the whole point of splicing is
// that a caller's question costs nothing, so it must come back from the same
// command rather than quietly earning a second one.
func TestProbeWithAnswersTheCallersQuestionsToo(t *testing.T) {
	tr := &countingTransport{Transport: localTransport(t)}
	caps, answers, err := fileops.ProbeWith(context.Background(), tr,
		"printf 'MINE=%s\\n' spliced")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if answers["MINE"] != "spliced" {
		t.Errorf("the caller's own answer is %q, want %q", answers["MINE"], "spliced")
	}
	if caps.Uname == "" {
		t.Error("splicing a question cost the capabilities")
	}
	if n := tr.count(); n > maxProbeRoundTrips {
		t.Errorf("a spliced question cost %d round trips, want %d", n, maxProbeRoundTrips)
	}
}

// TestProbeLeavesStdinToTheDigest: everything before the raw-stdin measurement
// runs with stdin on /dev/null, because a login profile that reads stdin would
// otherwise eat the blob and reach would record a clean transport as dirty.
func TestProbeLeavesStdinToTheDigest(t *testing.T) {
	tr := localTransport(t)
	caps, answers, err := fileops.ProbeWith(context.Background(), tr,
		"printf 'ATE=%s\\n' \"$(cat)\"")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if answers["ATE"] != "" {
		t.Errorf("a spliced command read the raw-stdin blob: %q", answers["ATE"])
	}
	if caps.SHA256 != "" && !caps.RawStdin {
		t.Error("the digest did not get the blob it was supposed to measure")
	}
}

// TestProbeStillAnswersBothRawIODirections: the two raw-I/O questions now share
// a command, so a mistake in splitting its output would silently report a
// perfectly clean transport as needing base64 — a third more bandwidth in both
// directions, on every file the agent touches, with nothing to see.
//
// The local transport is a pipe to a shell with no pty, so it is 8-bit clean in
// both directions and both answers must be true.
func TestProbeStillAnswersBothRawIODirections(t *testing.T) {
	caps, err := fileops.Probe(context.Background(), localTransport(t))
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if caps.SHA256 == "" {
		t.Skip("no digest command here, so stdin fidelity cannot be measured")
	}
	if !caps.RawStdin {
		t.Error("a local pipe garbled stdin, which it cannot have done")
	}
	if !caps.RawStdout {
		t.Error("a local pipe garbled stdout, which it cannot have done")
	}
}
