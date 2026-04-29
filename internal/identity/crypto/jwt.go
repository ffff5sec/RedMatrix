// Package crypto 是 identity 模块的密码学零件层（JWT、密钥派生等）。
//
// 范围：
//   - 不发起 IO，不依赖 repo / RPC
//   - 输入纯参数（user/sessionID/secret/now/ttl），输出 token 字符串或解析结果
//   - 业务流程（Login / 校验 token_version）在 authservice 层做
package crypto

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// JWT 协议常量（LLD 10 §5.1 / 5.2）。
//
// 注意：
//   - JWTKeyID = "v1" 预留密钥轮换；老 token 用旧 key 校验，新 token 用新 key 签发（Phase 2）
//   - JWTIssuer 是 jwt.RegisteredClaims.iss；ParseAndVerify 不强校 iss（不同部署可能改名）
//   - DefaultAccessTTL 12h（MVP 不实现 RefreshToken；到期重新登录）
const (
	JWTKeyID          = "v1"
	JWTIssuer         = "redmatrix"
	DefaultAccessTTL  = 12 * time.Hour
	NotBeforeBackdate = 30 * time.Second // 容忍 client/server 时钟漂移
	MinSecretLen      = 64               // 04-config §3.4：JWT secret 启动强校验
)

// Claims 是 RedMatrix JWT 的载荷（LLD 10 §5.2）。
//
// json 字段名与 LLD 对齐；新增字段必须保 backward-compat（老 token 仍可解码）。
type Claims struct {
	jwt.RegisteredClaims
	Tenant   string `json:"tenant,omitempty"`
	Role     string `json:"role"`
	TV       int    `json:"tv"`
	Username string `json:"username"`
	Sid      string `json:"sid,omitempty"`
}

// Service 同时承担 Issue 和 ParseAndVerify 职责。HS256 单密钥，单 Server 实例。
type Service struct {
	secret    []byte
	accessTTL time.Duration
	now       func() time.Time // 注入，便于测试
}

// AccessTTL 返回 access token 的 TTL（用于 service 层算 session 过期时间）。
func (s *Service) AccessTTL() time.Duration { return s.accessTTL }

// NewService 创建 JWT 服务。secret 必须 ≥ MinSecretLen；ttl ≤ 0 时用 DefaultAccessTTL。
func NewService(secret string, accessTTL time.Duration) (*Service, error) {
	if len(secret) < MinSecretLen {
		return nil, errx.New(errx.ErrInvalidInput,
			fmt.Sprintf("JWT secret 必须 ≥ %d 字符", MinSecretLen))
	}
	if accessTTL <= 0 {
		accessTTL = DefaultAccessTTL
	}
	return &Service{
		secret:    []byte(secret),
		accessTTL: accessTTL,
		now:       time.Now,
	}, nil
}

// Issue 用 user 当前 token_version 签发一枚 JWT。
//
// sessionID 可空（"" → claim sid 不写）；调用方决定是否先建 session 再签。
// 返回 (token, expires_at, err)。
func (s *Service) Issue(u *domain.User, sessionID string) (string, time.Time, error) {
	if u == nil {
		return "", time.Time{}, errx.New(errx.ErrInvalidInput, "user is nil")
	}
	if u.ID == "" {
		return "", time.Time{}, errx.New(errx.ErrInvalidInput, "user.id 不能为空")
	}
	now := s.now().UTC()
	expires := now.Add(s.accessTTL)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    JWTIssuer,
			Subject:   u.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
			NotBefore: jwt.NewNumericDate(now.Add(-NotBeforeBackdate)),
			ID:        uuid.NewString(), // jti
		},
		Tenant:   u.TenantID,
		Role:     string(u.Role),
		TV:       u.TokenVersion,
		Username: u.Username,
		Sid:      sessionID,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = JWTKeyID
	raw, err := tok.SignedString(s.secret)
	if err != nil {
		return "", time.Time{}, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "jwt: 签名失败")
	}
	return raw, expires, nil
}

// ParseAndVerify 校验签名 + 标准 claims（exp/nbf/iat），返回 *Claims。
//
// 不校 token_version——业务层（AuthService.AuthenticateBearer）拿到 claims 后再去比对 user.token_version。
//
// 错误码：
//   - 空字串 / 段不够 → ErrAuthTokenInvalid
//   - 签名错 / alg=none / kid 错 → ErrAuthTokenInvalid
//   - exp 过 → ErrAuthTokenExpired
//   - 其他错 → ErrAuthTokenInvalid
func (s *Service) ParseAndVerify(raw string) (*Claims, error) {
	if raw == "" {
		return nil, errx.New(errx.ErrAuthTokenInvalid, "token 为空")
	}
	var c Claims
	tok, err := jwt.ParseWithClaims(raw, &c,
		func(t *jwt.Token) (any, error) {
			// 显式只接受 HS256，挡 alg=none 攻击
			if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("不支持的签名算法: %v", t.Method.Alg())
			}
			return s.secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, errx.Wrap(errx.ErrAuthTokenExpired, err, "凭证已过期")
		default:
			return nil, errx.Wrap(errx.ErrAuthTokenInvalid, err, "凭证无效")
		}
	}
	if !tok.Valid {
		return nil, errx.New(errx.ErrAuthTokenInvalid, "凭证无效")
	}
	return &c, nil
}
