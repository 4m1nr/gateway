// Package webauth holds the dashboard's authentication primitives: password
// hashing, sessions, the failed-login lockout, and the source-address check.
//
// It sits on its own because both sides of the privilege boundary need it. The
// unprivileged web server owns sessions and the lockout; the root helper owns
// the password file, which the web process must never read.
package webauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// AuthFile holds the dashboard password hash. 0600 root:root, and never read by
// the web process — logins are verified across the sudo boundary.
const AuthFile = "/etc/gateway/web-auth.json"

// scrypt parameters. ~64 MB and ~100 ms per attempt on thin-client hardware:
// slow enough that the lockout does the real work, fast enough that a
// legitimate login still feels instant.
//
// These values are wire-format. An /etc/gateway/web-auth.json written by the
// Python implementation must keep working, so they match lib/webauth.py exactly
// and cannot be changed without a migration.
const (
	scryptN      = 1 << 15
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	saltLen      = 16
)

// Stored is the on-disk password record.
type Stored struct {
	Salt    string `json:"salt"`
	Hash    string `json:"hash"`
	Updated int64  `json:"updated"`
}

// HashPassword derives a hash and returns it with its salt, both hex.
func HashPassword(password string, salt []byte) (saltHex, hashHex string, err error) {
	if salt == nil {
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return "", "", err
		}
	}
	dk, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(salt), hex.EncodeToString(dk), nil
}

// VerifyPassword checks a password against a stored salt and hash.
func VerifyPassword(password, saltHex, hashHex string) bool {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	_, got, err := HashPassword(password, salt)
	if err != nil {
		return false
	}
	// Constant time: a timing oracle on the hash is a slow but real way to
	// confirm a guess.
	return subtle.ConstantTimeCompare([]byte(got), []byte(hashHex)) == 1
}

// LoadPassword reads the stored record, or nil when none is set.
func LoadPassword(path string) *Stored {
	if path == "" {
		path = AuthFile
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var s Stored
	if json.Unmarshal(raw, &s) != nil || s.Salt == "" || s.Hash == "" {
		return nil
	}
	return &s
}

// SavePassword writes the record 0600, creating it that way rather than
// tightening it afterwards — a hash briefly world-readable is a hash leaked.
func SavePassword(path, password string) error {
	if path == "" {
		path = AuthFile
	}
	salt, hash, err := HashPassword(password, nil)
	if err != nil {
		return err
	}
	body, err := json.Marshal(Stored{Salt: salt, Hash: hash, Updated: time.Now().Unix()})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// ---------------------------------------------------------------- sessions --

// Session is one signed-in browser.
type Session struct {
	// Peer is the address that created the session. A session is bound to it,
	// so a stolen cookie is not portable to another host.
	Peer    string
	Expires time.Time
	CSRF    string
}

// Sessions is an in-memory session store.
//
// A restart signs everyone out, which is the right trade for a box whose whole
// job is to be restarted when things break.
type Sessions struct {
	ttl   time.Duration
	mu    sync.Mutex
	store map[string]*Session
}

func NewSessions(ttlHours int) *Sessions {
	if ttlHours <= 0 {
		ttlHours = 12
	}
	return &Sessions{
		ttl:   time.Duration(ttlHours) * time.Hour,
		store: map[string]*Session{},
	}
}

// Create issues a session bound to peer and returns its token.
func (s *Sessions) Create(peer string) (string, *Session) {
	token := randomToken(32)
	sess := &Session{
		Peer:    peer,
		Expires: time.Now().Add(s.ttl),
		CSRF:    randomToken(24),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[token] = sess
	return token, sess
}

// Get returns the session for a token, but only for the address that created
// it. An expired or foreign-address session is treated as absent.
func (s *Sessions) Get(token, peer string) *Session {
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()

	sess, ok := s.store[token]
	if !ok {
		return nil
	}
	if sess.Peer != peer {
		return nil
	}
	return sess
}

// Destroy invalidates a token.
func (s *Sessions) Destroy(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, token)
}

// DestroyAll signs everyone out, used when the password changes.
func (s *Sessions) DestroyAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = map[string]*Session{}
}

func (s *Sessions) reapLocked() {
	now := time.Now()
	for token, sess := range s.store {
		if sess.Expires.Before(now) {
			delete(s.store, token)
		}
	}
}

// ----------------------------------------------------------------- lockout --

// Lockout throttles failed logins per source address.
type Lockout struct {
	max    int
	window time.Duration
	mu     sync.Mutex
	fails  map[string][]time.Time
}

func NewLockout(maxFailures, minutes int) *Lockout {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if minutes <= 0 {
		minutes = 15
	}
	return &Lockout{
		max:    maxFailures,
		window: time.Duration(minutes) * time.Minute,
		fails:  map[string][]time.Time{},
	}
}

// LockedFor returns how long this address must wait, or zero.
func (l *Lockout) LockedFor(peer string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	var recent []time.Time
	for _, t := range l.fails[peer] {
		if now.Sub(t) < l.window {
			recent = append(recent, t)
		}
	}
	l.fails[peer] = recent
	if len(recent) >= l.max {
		return l.window - now.Sub(recent[0])
	}
	return 0
}

// RecordFailure notes a wrong password from this address.
func (l *Lockout) RecordFailure(peer string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[peer] = append(l.fails[peer], time.Now())
}

// Clear forgets an address's failures, after a successful login.
func (l *Lockout) Clear(peer string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, peer)
}

// ------------------------------------------------------------------- peer --

// PeerAllowed reports whether an address may reach the dashboard at all.
//
// peer must come from the socket. Never pass a value derived from a header:
// nothing proxies this service, so an X-Forwarded-For claiming otherwise can
// only be a forgery.
func PeerAllowed(peer string, allowCIDRs []string) bool {
	addr, err := netip.ParseAddr(peer)
	if err != nil {
		return false
	}
	// An IPv4-mapped IPv6 address (::ffff:192.168.1.5) arrives when the
	// listener is dual-stack. Unmapping it is what lets an IPv4 allow_cidrs
	// entry match the connection it was written for.
	addr = addr.Unmap()

	for _, cidr := range allowCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not survivable for a session token: a
		// predictable token is an unauthenticated dashboard.
		panic(fmt.Sprintf("crypto/rand is unavailable: %v", err))
	}
	return hex.EncodeToString(b)
}
