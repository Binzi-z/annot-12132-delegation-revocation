// Package auth provides deterministic signing keys for the reference protocol.
//
// In a deployment each issuer would publish an asymmetric public key per
// credential generation.  This reference implementation derives a symmetric
// per-(issuer, generation) key from a shared seed so that any node (and any
// independent verifier) can check the same proofs.  The canonical inputs are
// deliberately explicit so the substitution with real signatures is local.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Registry derives and checks keyed proofs. A Registry is immutable and safe
// for concurrent use.
type Registry struct {
	seed []byte
}

// NewRegistry builds a registry from a seed. All participants in the protocol
// must use the same seed (or, with real PKI, the same public key directory).
func NewRegistry(seed string) *Registry {
	sum := sha256.Sum256([]byte("ccrevoke/registry/v1|" + seed))
	return &Registry{seed: sum[:]}
}

func (r *Registry) key(issuer string, gen int) []byte {
	m := hmac.New(sha256.New, r.seed)
	fmt.Fprintf(m, "key|%s|%d", issuer, gen)
	return m.Sum(nil)
}

// Sign returns a hex HMAC over msg under the issuer's generation key.
func (r *Registry) Sign(issuer string, gen int, msg []byte) string {
	m := hmac.New(sha256.New, r.key(issuer, gen))
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil))
}

// Verify checks a hex HMAC under the issuer's generation key.
func (r *Registry) Verify(issuer string, gen int, msg []byte, proof string) bool {
	want := r.Sign(issuer, gen, msg)
	return subtle.ConstantTimeCompare([]byte(want), []byte(proof)) == 1
}

// NodeIdentity is the signing identity of a node. Certificates are signed with
// this identity so a verifier can distinguish an all-node decision from an
// arbitrary blob.
func NodeIdentity(org string) string { return "node:" + org }

// SignNode signs bytes as the node authority.
func (r *Registry) SignNode(org string, msg []byte) string {
	return r.Sign(NodeIdentity(org), 0, msg)
}

// VerifyNode verifies a node-authority signature.
func (r *Registry) VerifyNode(org string, msg []byte, proof string) bool {
	return r.Verify(NodeIdentity(org), 0, msg, proof)
}

// Identity joins an organization and a member name into the canonical identity
// form "org:name".
func Identity(org, name string) string {
	if strings.Contains(name, ":") {
		return name
	}
	return org + ":" + name
}

// OrgOf returns the organization prefix of an identity, or "" if malformed.
func OrgOf(identity string) string {
	i := strings.IndexByte(identity, ':')
	if i <= 0 || i == len(identity)-1 {
		return ""
	}
	return identity[:i]
}

// NameOf returns the member name of an identity, or "" if malformed.
func NameOf(identity string) string {
	i := strings.IndexByte(identity, ':')
	if i < 0 || i == len(identity)-1 {
		return ""
	}
	return identity[i+1:]
}

// ValidIdentity reports whether s is a well-formed "org:name" identity.
func ValidIdentity(s string) bool {
	return OrgOf(s) != "" && NameOf(s) != ""
}

// GenKeyID renders the key identifier copied into admission certificates.
func GenKeyID(issuer string, gen int) string {
	return issuer + "#g" + strconv.Itoa(gen)
}
