// Package crypto 封装签发者密钥环与委派边的 Ed25519 签名/验签。
//
// 每个签发者维护“代际 -> 公钥”的历史：换主事件登记新代际公钥，
// 旧代际公钥仍被保留用于审计，但决策引擎只接受当前代际签名，
// 从而保证“凭证代际换任即撤销旧路径”，且换任不可被旧签名快照绕过。
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"revauth/internal/model"
)

// Signer 单个签发者的签名器，仅存在于签发者自身组织内。
type Signer struct {
	Issuer     model.OrgID
	Generation model.Generation
	private    ed25519.PrivateKey
}

// NewSigner 生成一把全新密钥并构造签名器（用于创始代际或换主）。
func NewSigner(issuer model.OrgID, gen model.Generation) (*Signer, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &Signer{Issuer: issuer, Generation: gen, private: priv}, pub, nil
}

// SignerFromPrivate 从既有私钥恢复签名器（节点迁移/重启场景）。
func SignerFromPrivate(issuer model.OrgID, gen model.Generation, priv ed25519.PrivateKey) *Signer {
	return &Signer{Issuer: issuer, Generation: gen, private: priv}
}

// Public 返回对应公钥。
func (s *Signer) Public() ed25519.PublicKey {
	return s.private.Public().(ed25519.PublicKey)
}

// SignEdge 对一条委派边签名，写入 Issuer/Generation/Sig 并返回。
// 签名内容是剥离 Sig 字段后的规范 JSON，保证任何节点可独立复核。
func (s *Signer) SignEdge(e model.DelegationEdge) (model.DelegationEdge, error) {
	if e.Issuer != s.Issuer {
		return e, fmt.Errorf("edge issuer %q != signer %q", e.Issuer, s.Issuer)
	}
	e.Generation = s.Generation
	e.Sig = nil
	e.Sig = ed25519.Sign(s.private, edgeSigningBytes(e))
	return e, nil
}

// Keyring 节点侧的签发者代际公钥环（只含公钥，可随快照迁移）。
type Keyring struct {
	Current model.Generation
	PubKeys map[model.Generation]ed25519.PublicKey
}

// NewKeyring 创建空密钥环。
func NewKeyring() *Keyring {
	return &Keyring{PubKeys: map[model.Generation]ed25519.PublicKey{}}
}

// Rotate 登记新代际公钥并推进当前代际。代际必须严格递增。
func (k *Keyring) Rotate(gen model.Generation, pub []byte) error {
	if gen <= k.Current && k.Current != 0 {
		return fmt.Errorf("generation must advance: current=%d got=%d", k.Current, gen)
	}
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 public key length")
	}
	k.PubKeys[gen] = ed25519.PublicKey(append([]byte(nil), pub...))
	k.Current = gen
	return nil
}

// VerifyEdge 独立验证一条委派边：代际存在、为当前代际、签名有效。
//
// 非当前代际一律拒绝（换任撤销），即使旧公钥仍在环中——旧公钥只服务于
// 事后审计，不服务于实时准入。
func (k *Keyring) VerifyEdge(e model.DelegationEdge) error {
	pub, ok := k.PubKeys[e.Generation]
	if !ok {
		return fmt.Errorf("unknown generation %d", e.Generation)
	}
	if e.Generation != k.Current {
		return fmt.Errorf("stale generation %d, current %d", e.Generation, k.Current)
	}
	if len(e.Sig) != ed25519.SignatureSize {
		return errors.New("missing or malformed signature")
	}
	signed := e
	signed.Sig = nil
	if !ed25519.Verify(pub, edgeSigningBytes(signed), e.Sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// edgeSigningBytes 生成边的规范签名字节。
func edgeSigningBytes(e model.DelegationEdge) []byte {
	type bare struct {
		Tenant     model.TenantID    `json:"tenant"`
		Resource   model.ResourceID  `json:"resource"`
		Issuer     model.OrgID       `json:"issuer"`
		Generation model.Generation  `json:"generation"`
		From       model.PrincipalID `json:"from"`
		To         model.PrincipalID `json:"to"`
		NotBefore  int64             `json:"not_before"`
		NotAfter   int64             `json:"not_after"`
	}
	return model.CanonicalJSON(bare{
		Tenant: e.Tenant, Resource: e.Resource, Issuer: e.Issuer,
		Generation: e.Generation, From: e.From, To: e.To,
		NotBefore: e.NotBefore, NotAfter: e.NotAfter,
	})
}
