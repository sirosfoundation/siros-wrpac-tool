//go:build softhsm

package keyref

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// softHSM is a throwaway SoftHSM token for one test.
//
// Each test gets its own token directory and SOFTHSM2_CONF, so tests neither
// see each other's keys nor depend on whatever the developer has installed.
type softHSM struct {
	dir    string
	label  string
	pin    string
	soPIN  string
	module string
}

// modulePaths are where libsofthsm2.so lands across the distributions we build on.
var modulePaths = []string{
	"/usr/lib/softhsm/libsofthsm2.so",
	"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	"/usr/lib64/softhsm/libsofthsm2.so",
	"/usr/local/lib/softhsm/libsofthsm2.so",
}

func findModule() string {
	for _, p := range modulePaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// newSoftHSM initialises a token and registers cleanup.
func newSoftHSM(t *testing.T) *softHSM {
	t.Helper()

	module := findModule()
	if module == "" {
		t.Skip("libsofthsm2.so not found; install softhsm2 to run these tests")
	}
	for _, bin := range []string{"softhsm2-util", "pkcs11-tool"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH; install softhsm2 and opensc to run these tests", bin)
		}
	}

	h := &softHSM{
		dir:    t.TempDir(),
		label:  "wrpac-test",
		pin:    "1234",
		soPIN:  "5678",
		module: module,
	}

	conf := filepath.Join(h.dir, "softhsm2.conf")
	body := fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n", h.dir)
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatalf("write softhsm config: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", conf)

	out, err := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", h.label, "--so-pin", h.soPIN, "--pin", h.pin).CombinedOutput()
	if err != nil {
		t.Fatalf("init token: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "The token has been initialized") {
		t.Fatalf("unexpected init output: %s", out)
	}
	return h
}

// generateEC creates a P-256 keypair on the token under the given label.
func (h *softHSM) generateEC(t *testing.T, label string) {
	t.Helper()
	out, err := exec.Command("pkcs11-tool",
		"--module", h.module,
		"--token-label", h.label,
		"--login", "--pin", h.pin,
		"--keypairgen", "--key-type", "EC:prime256v1",
		"--label", label, "--id", fmt.Sprintf("%02x", len(label)),
	).CombinedOutput()
	if err != nil {
		t.Fatalf("generate key %q: %v\n%s", label, err, out)
	}
}

// ref returns a Ref pointing at a key on this token, with the PIN supplied
// through the environment as the real tool requires.
func (h *softHSM) ref(t *testing.T, keyLabel string) Ref {
	t.Helper()
	t.Setenv("SIROS_WRPAC_TEST_PIN", h.pin)
	return Ref{PKCS11: &PKCS11{
		Module:     h.module,
		TokenLabel: h.label,
		KeyLabel:   keyLabel,
		PINEnv:     "SIROS_WRPAC_TEST_PIN",
	}}
}
