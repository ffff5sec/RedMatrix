// Package pki 是 tenancy 模块的 X.509 PKI 零件层（LLD 11 §3.6 / §11）。
//
// 范围（PR-T4-D1）：
//   - 自签 Root CA 生成 + 加载 + 持久化（PEM）
//   - Leaf cert 签发（节点 client cert + 服务端 server cert 共用）
//   - SHA-256 cert 指纹
//   - 不发起 IO（不读写文件）；不依赖 repo / RPC
//
// 选型：ECDSA P-256（FIPS-186-4 / RFC 5480 标配；Go stdlib 一类支持；
// signer 速度快、cert 体积小；与 OpenSSL / mTLS 客户端互操作良好）。
//
// 后续 PR：
//   - PR-T4-D2：node_certificates 表 + repo + Redeem 时签发节点 cert
//   - PR-T4-D3：Heartbeat 流 + 在线状态机
//   - PR-T4-D4：cmd/node Agent 接入闭环
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// CA 是自签 Root CA + 它的私钥（持久化 / 签发 leaf 用）。
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// GenerateCAOptions 自签 CA 入参。
type GenerateCAOptions struct {
	CommonName string        // 默认 "RedMatrix Root CA"
	Validity   time.Duration // 默认 10 年
	Now        time.Time     // 注入；零值 → time.Now()
}

// CA 默认参数。
const (
	DefaultCACommonName = "RedMatrix Root CA"
	DefaultCAValidity   = 10 * 365 * 24 * time.Hour // ~10 年
	DefaultLeafValidity = 30 * 24 * time.Hour       // 30 天；节点 cert 续期由后续 PR 接 cron
	MinLeafValidity     = 1 * time.Minute
	MaxLeafValidity     = 365 * 24 * time.Hour // 1 年；防长期暴露
)

// GenerateCA 自签新 CA（ECDSA P-256）。
//
// 出错：crypto/rand 故障 → ErrCryptoEncryptionFailed；options 非法 →
// ErrInvalidInput。
func GenerateCA(opts GenerateCAOptions) (*CA, error) {
	if opts.CommonName == "" {
		opts.CommonName = DefaultCACommonName
	}
	if opts.Validity == 0 {
		opts.Validity = DefaultCAValidity
	}
	if opts.Validity <= 0 {
		return nil, errx.New(errx.ErrInvalidInput, "CA validity 必须 > 0")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "pki: 生成 CA 密钥失败")
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{"RedMatrix"},
		},
		NotBefore: now.Add(-NotBeforeBackdate),
		NotAfter:  now.Add(opts.Validity),

		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		MaxPathLen:            1, // 允许 leaf 但不允许 intermediate（MVP 单层）
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "pki: 自签 CA 失败")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "pki: 回读 CA cert 失败")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// NotBeforeBackdate CA + leaf 的 NotBefore 回溯量；容忍 client/server 时钟漂移。
const NotBeforeBackdate = 30 * time.Second

// MarshalCAPEM 把 CA 序列化为 PEM 字节（cert + key 两份；caller 决定如何持久）。
func MarshalCAPEM(ca *CA) (certPEM, keyPEM []byte, err error) {
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		return nil, nil, errx.New(errx.ErrInvalidInput, "MarshalCAPEM: ca 不能为 nil")
	}
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return nil, nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "pki: marshal CA key")
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	return certPEM, keyPEM, nil
}

// LoadCAPEM 从 PEM 字节加载 CA。caller 决定怎么读文件 / 从 secret manager 拉。
func LoadCAPEM(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := parseSingleCertPEM(certPEM)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInvalidInput, err, "pki: 解析 CA cert PEM")
	}
	key, err := parseECDSAKeyPEM(keyPEM)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInvalidInput, err, "pki: 解析 CA key PEM")
	}
	if !cert.IsCA {
		return nil, errx.New(errx.ErrInvalidInput, "pki: cert 不是 CA（IsCA=false）")
	}
	// pubkey 与 privkey 配对校验
	if !ecdsaPubsEqual(&key.PublicKey, cert.PublicKey) {
		return nil, errx.New(errx.ErrInvalidInput, "pki: CA cert 与 key 公钥不匹配")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// === Leaf 签发 ===

// LeafUsage 决定签出 cert 的 ExtKeyUsage。
type LeafUsage int

const (
	// LeafUsageClient 节点（Agent）方向：client auth + digital signature。
	LeafUsageClient LeafUsage = iota
	// LeafUsageServer 服务端方向：server auth + digital signature；
	// 通常仅给 cmd/server 自身 mTLS 监听用。
	LeafUsageServer
	// LeafUsageBoth 同时支持 client + server（节点 + 服务端 dual role 时用）。
	LeafUsageBoth
)

// SignLeafOptions leaf 签发入参。
type SignLeafOptions struct {
	CommonName string        // 必填；节点 cert CN 通常是 node_id
	DNSNames   []string      // SAN DNS（server cert 用）
	IPs        []net.IP      // SAN IP
	Validity   time.Duration // 0 → DefaultLeafValidity
	Usage      LeafUsage
	Now        time.Time // 注入；零值 → time.Now()
}

// SignLeaf 用 CA 签发 leaf cert。
//
// 调用方提供 leaf 的公钥（ED25519 / ECDSA / RSA 均可；Go stdlib 一类）。
// 返 cert 本体 + PEM 字节（caller 通常合并 leaf cert + CA cert 成证书链）。
func (c *CA) SignLeaf(leafPub crypto.PublicKey, opts SignLeafOptions) (cert *x509.Certificate, certPEM []byte, err error) {
	if c == nil || c.Cert == nil || c.Key == nil {
		return nil, nil, errx.New(errx.ErrInvalidInput, "SignLeaf: ca 不能为 nil")
	}
	if opts.CommonName == "" {
		return nil, nil, errx.New(errx.ErrInvalidInput, "SignLeaf: CommonName 不能为空")
	}
	if opts.Validity == 0 {
		opts.Validity = DefaultLeafValidity
	}
	if opts.Validity < MinLeafValidity || opts.Validity > MaxLeafValidity {
		return nil, nil, errx.New(errx.ErrInvalidInput,
			"SignLeaf: Validity 必须在 [1m, 1y]").
			WithFields("got", opts.Validity.String())
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	if now.Add(opts.Validity).After(c.Cert.NotAfter) {
		return nil, nil, errx.New(errx.ErrInvalidInput,
			"SignLeaf: leaf 有效期不可超过 CA 过期时间").
			WithFields("ca_expires", c.Cert.NotAfter.Format(time.RFC3339))
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{"RedMatrix"},
		},
		NotBefore: now.Add(-NotBeforeBackdate),
		NotAfter:  now.Add(opts.Validity),

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: extKeyUsageFor(opts.Usage),

		DNSNames:    opts.DNSNames,
		IPAddresses: opts.IPs,

		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, leafPub, c.Key)
	if err != nil {
		return nil, nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "pki: 签发 leaf 失败")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "pki: 回读 leaf cert 失败")
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return leaf, certPEM, nil
}

// === leaf key helper ===

// NewLeafKey 生成 ECDSA P-256 私钥。
func NewLeafKey() (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "pki: 生成 leaf key 失败")
	}
	return k, nil
}

// MarshalLeafKeyPEM 把 leaf 私钥序列化为 PKCS#8 PEM。
func MarshalLeafKeyPEM(k *ecdsa.PrivateKey) ([]byte, error) {
	if k == nil {
		return nil, errx.New(errx.ErrInvalidInput, "MarshalLeafKeyPEM: key is nil")
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "pki: marshal leaf key")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// === Fingerprint ===

// Fingerprint 算 cert DER 的 SHA-256，hex 小写（64 字符）。
//
// 节点身份持久化 + UI 显示用。
func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// === helpers ===

func randomSerial() (*big.Int, error) {
	// 128-bit serial（RFC 5280 推荐）
	upper := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, upper)
	if err != nil {
		return nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "pki: 生成 serial")
	}
	return n, nil
}

func parseSingleCertPEM(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("PEM 块缺失")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM 类型不是 CERTIFICATE")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseECDSAKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("key PEM 块缺失")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, errors.New("key PEM 类型必须为 PRIVATE KEY（PKCS#8）")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key 不是 ECDSA")
	}
	return k, nil
}

func ecdsaPubsEqual(a *ecdsa.PublicKey, b crypto.PublicKey) bool {
	bp, ok := b.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	if a.Curve != bp.Curve {
		return false
	}
	return a.X.Cmp(bp.X) == 0 && a.Y.Cmp(bp.Y) == 0
}

func extKeyUsageFor(u LeafUsage) []x509.ExtKeyUsage {
	switch u {
	case LeafUsageServer:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case LeafUsageBoth:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		// LeafUsageClient
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
}
