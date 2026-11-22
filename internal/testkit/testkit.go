// Package testkit 提供双组织测试夹具：签发者密钥环、跨组织委派链、
// 准入证书与事件构造，以及一个“仅验签”的朴素校验器用于展示最小反例。
package testkit

import (
	"crypto/ed25519"

	"revauth/internal/crypto"
	"revauth/internal/model"
)

// 固定的双组织标识。
const (
	OrgA     model.OrgID      = "org-a"
	OrgB     model.OrgID      = "org-b"
	Tenant   model.TenantID   = "tenant-1"
	Resource model.ResourceID = "repo/secret"
)

// Issuer 测试侧签发者（持有私钥，可换主）。
type Issuer struct {
	ID      model.OrgID
	Signer  *crypto.Signer
	Pub     ed25519.PublicKey
	Gen     model.Generation
}

// NewIssuer 创建创始代际（gen=1）签发者。
func NewIssuer(id model.OrgID) (*Issuer, error) {
	s, pub, err := crypto.NewSigner(id, 1)
	if err != nil {
		return nil, err
	}
	return &Issuer{ID: id, Signer: s, Pub: pub, Gen: 1}, nil
}

// Rotate 换主：生成新代际密钥，返回换主事件载荷与新公钥。
func (i *Issuer) Rotate() (model.KeyRotatedPayload, ed25519.PublicKey, error) {
	newGen := i.Gen + 1
	s, pub, err := crypto.NewSigner(i.ID, newGen)
	if err != nil {
		return model.KeyRotatedPayload{}, nil, err
	}
	i.Signer, i.Pub, i.Gen = s, pub, newGen
	return model.KeyRotatedPayload{NewGeneration: newGen, PublicKey: pub, Reason: "test rotation"}, pub, nil
}

// Edge 构造并签名一条委派边。
func Edge(issuer *Issuer, from, to model.PrincipalID, nb, na int64) model.DelegationEdge {
	e := model.DelegationEdge{
		Tenant: Tenant, Resource: Resource, Issuer: issuer.ID,
		From: from, To: to, NotBefore: nb, NotAfter: na,
	}
	signed, err := issuer.Signer.SignEdge(e)
	if err != nil {
		panic(err)
	}
	return signed
}

// Cert 用若干条路径组装准入证书。
func Cert(subject model.PrincipalID, paths ...[]model.DelegationEdge) model.AdmissionCertificate {
	return model.AdmissionCertificate{
		Tenant: Tenant, Resource: Resource, Subject: subject,
		IssuedAt: 0, Paths: paths,
	}
}

// NaiveVerifier 是“仅验证签名与有效期”的朴素准入器——故意缺失撤销证据
// 与代际检查。最小反例中它会被旧签名快照欺骗，而真实引擎不会。
type NaiveVerifier struct {
	Keys map[model.OrgID]ed25519.PublicKey
}

// NewNaiveVerifier 用创始公钥构造朴素校验器（且永不更新，模拟旧快照）。
func NewNaiveVerifier(a, b *Issuer) *NaiveVerifier {
	return &NaiveVerifier{Keys: map[model.OrgID]ed25519.PublicKey{
		OrgA: a.Pub, OrgB: b.Pub,
	}}
}

// Allow 只看签名与有效期：这正是反例要暴露的缺陷。
func (v *NaiveVerifier) Allow(cert model.AdmissionCertificate, now int64) bool {
	for _, path := range cert.Paths {
		ok := len(path) > 0
		for _, e := range path {
			pub := v.Keys[e.Issuer]
			if pub == nil {
				ok = false
				break
			}
			bare := e
			sig := e.Sig
			bare.Sig = nil
			if !ed25519.Verify(pub, signingBytes(bare), sig) {
				ok = false
				break
			}
			if now < e.NotBefore || now > e.NotAfter {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func signingBytes(e model.DelegationEdge) []byte {
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
