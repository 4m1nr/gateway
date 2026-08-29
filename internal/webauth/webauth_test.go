package webauth

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The stored format is wire-format: a web-auth.json written by the Python
// implementation has to keep working, or upgrading the gateway silently locks
// the owner out of their own dashboard.
func TestScryptMatchesThePythonImplementation(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	salt, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	const password = "correct horse battery staple"

	_, goHash, err := HashPassword(password, salt)
	if err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("python3", "-c", `
import hashlib, sys
salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
dk = hashlib.scrypt(b"correct horse battery staple", salt=salt,
                    n=2**15, r=8, p=1, dklen=32, maxmem=96*1024*1024)
sys.stdout.write(dk.hex())
`).Output()
	if err != nil {
		t.Fatalf("running the reference implementation: %v", err)
	}
	if goHash != string(out) {
		t.Errorf("scrypt output differs from the Python implementation:\n go     %s\n python %s",
			goHash, out)
	}
}

func TestVerifyPassword(t *testing.T) {
	salt, hash, err := HashPassword("hunter2hunter2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("hunter2hunter2", salt, hash) {
		t.Error("the correct password was rejected")
	}
	if VerifyPassword("hunter2hunter3", salt, hash) {
		t.Error("a wrong password was accepted")
	}
	if VerifyPassword("hunter2hunter2", "not hex", hash) {
		t.Error("a corrupt salt was accepted")
	}
}

// The hash file must never be created readable and then tightened: a hash
// briefly world-readable is a hash leaked.
func TestSavePasswordIsAlwaysRestricted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "web-auth.json")
	if err := SavePassword(path, "a-long-enough-password"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("the hash file is %04o, want 0600", st.Mode().Perm())
	}
	stored := LoadPassword(path)
	if stored == nil {
		t.Fatal("the saved password could not be read back")
	}
	if !VerifyPassword("a-long-enough-password", stored.Salt, stored.Hash) {
		t.Error("the round-tripped password does not verify")
	}
	// The plaintext must appear nowhere in the file.
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "a-long-enough-password") {
		t.Error("the password was stored in clear text")
	}
}

func TestLoadPasswordAbsentOrCorrupt(t *testing.T) {
	dir := t.TempDir()
	if LoadPassword(filepath.Join(dir, "nope.json")) != nil {
		t.Error("a missing file reported a password")
	}
	corrupt := filepath.Join(dir, "corrupt.json")
	os.WriteFile(corrupt, []byte(`{"salt":"","hash":""}`), 0o600)
	if LoadPassword(corrupt) != nil {
		t.Error("an empty record reported a password")
	}
}

// ---------------------------------------------------------------- sessions --

// A session is bound to the address that created it, so a stolen cookie is not
// portable to another host.
func TestSessionIsBoundToItsAddress(t *testing.T) {
	s := NewSessions(12)
	token, sess := s.Create("192.168.1.50")
	if s.Get(token, "192.168.1.50") == nil {
		t.Fatal("the creating address cannot use its own session")
	}
	if s.Get(token, "192.168.1.99") != nil {
		t.Error("a session was accepted from a different address")
	}
	if sess.CSRF == "" {
		t.Error("no CSRF token was issued")
	}
	// Tokens must not be guessable or repeated.
	other, _ := s.Create("192.168.1.50")
	if other == token {
		t.Error("two sessions were issued the same token")
	}
	if len(token) < 32 {
		t.Errorf("token is only %d characters", len(token))
	}
}

func TestSessionExpires(t *testing.T) {
	s := NewSessions(12)
	token, sess := s.Create("192.168.1.50")
	sess.Expires = time.Now().Add(-time.Minute)
	if s.Get(token, "192.168.1.50") != nil {
		t.Error("an expired session is still valid")
	}
}

func TestSessionDestroy(t *testing.T) {
	s := NewSessions(12)
	token, _ := s.Create("192.168.1.50")
	s.Destroy(token)
	if s.Get(token, "192.168.1.50") != nil {
		t.Error("a destroyed session is still valid")
	}

	a, _ := s.Create("192.168.1.50")
	b, _ := s.Create("192.168.1.51")
	s.DestroyAll()
	if s.Get(a, "192.168.1.50") != nil || s.Get(b, "192.168.1.51") != nil {
		t.Error("DestroyAll left a session behind")
	}
}

// ----------------------------------------------------------------- lockout --

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	l := NewLockout(3, 15)
	peer := "192.168.1.50"
	for i := 0; i < 2; i++ {
		l.RecordFailure(peer)
		if d := l.LockedFor(peer); d != 0 {
			t.Fatalf("locked out after %d failures", i+1)
		}
	}
	l.RecordFailure(peer)
	if d := l.LockedFor(peer); d <= 0 {
		t.Fatal("not locked out after reaching the limit")
	}
	// The lockout is per address: one attacker must not lock out everyone else.
	if d := l.LockedFor("192.168.1.51"); d != 0 {
		t.Error("a different address was locked out too")
	}
	l.Clear(peer)
	if d := l.LockedFor(peer); d != 0 {
		t.Error("a successful login did not clear the lockout")
	}
}

// ------------------------------------------------------------------- peer --

func TestPeerAllowed(t *testing.T) {
	allow := []string{"192.168.1.0/24", "100.64.0.0/10"}
	for _, tc := range []struct {
		peer string
		want bool
	}{
		{"192.168.1.50", true},
		{"100.101.102.103", true},
		{"192.168.2.50", false},
		{"8.8.8.8", false},
		{"", false},
		{"not-an-address", false},
		// A dual-stack listener reports an IPv4 peer as IPv4-mapped IPv6.
		// Without unmapping, an IPv4 allow_cidrs entry never matches the
		// connection it was written for and the dashboard refuses everyone.
		{"::ffff:192.168.1.50", true},
		{"::ffff:8.8.8.8", false},
	} {
		if got := PeerAllowed(tc.peer, allow); got != tc.want {
			t.Errorf("PeerAllowed(%q) = %v, want %v", tc.peer, got, tc.want)
		}
	}
}

// A malformed entry must not silently widen the list.
func TestPeerAllowedIgnoresBadCIDRs(t *testing.T) {
	if PeerAllowed("8.8.8.8", []string{"nonsense", "192.168.1.0/24"}) {
		t.Error("a malformed allow_cidrs entry let an outside address through")
	}
}
