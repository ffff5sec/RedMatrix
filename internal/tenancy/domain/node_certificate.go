package domain

import (
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// NodeCertificate 是节点 mTLS 证书的领域映射（LLD 11 §3.6）。
//
// 服务端仅持 cert 本体（PEM）+ serial + fingerprint；私钥永不入库——
// 由 Agent 自己持有。Server 验链时按 fingerprint hot-lookup。
type NodeCertificate struct {
	ID           string
	NodeID       string
	SerialNumber string // x509.SerialNumber.String()（十进制；可读 + 保留语义）
	Fingerprint  string // SHA-256(DER) hex 64 字符
	CommonName   string
	CertPEM      string

	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time

	IssuedByToken string // 关联 registration_tokens.id；可空（非令牌签发场景）

	CreatedAt time.Time
}

// IsExpired now ≥ ExpiresAt。
func (c *NodeCertificate) IsExpired(now time.Time) bool {
	return c != nil && !c.ExpiresAt.After(now)
}

// IsRevoked 已被吊销。
func (c *NodeCertificate) IsRevoked() bool {
	return c != nil && c.RevokedAt != nil
}

// IsValid mTLS 校验通过条件：未撤 + 未过期。
func (c *NodeCertificate) IsValid(now time.Time) bool {
	return c != nil && !c.IsRevoked() && !c.IsExpired(now)
}

// ValidateForCreate 跑 INSERT 前的全部域内规则。
func (c *NodeCertificate) ValidateForCreate() error {
	if c == nil {
		return errx.New(errx.ErrInvalidInput, "node_certificate is nil")
	}
	if c.NodeID == "" {
		return errx.New(errx.ErrInvalidInput, "node_certificate.node_id 不能为空")
	}
	if c.SerialNumber == "" {
		return errx.New(errx.ErrInvalidInput, "node_certificate.serial_number 不能为空")
	}
	if len(c.Fingerprint) != 64 {
		return errx.New(errx.ErrInvalidInput,
			"node_certificate.fingerprint 必须为 64 字符（SHA-256 hex）")
	}
	if c.CommonName == "" {
		return errx.New(errx.ErrInvalidInput, "node_certificate.common_name 不能为空")
	}
	if c.CertPEM == "" {
		return errx.New(errx.ErrInvalidInput, "node_certificate.cert_pem 不能为空")
	}
	if c.ExpiresAt.IsZero() {
		return errx.New(errx.ErrInvalidInput, "node_certificate.expires_at 不能为零值")
	}
	if !c.IssuedAt.IsZero() && !c.ExpiresAt.After(c.IssuedAt) {
		return errx.New(errx.ErrInvalidInput, "expires_at 必须 > issued_at")
	}
	return nil
}
