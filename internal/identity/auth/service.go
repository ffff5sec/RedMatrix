// Package auth 是 identity 模块的业务流层（Login/Logout/AuthenticateBearer）。
//
// 范围（PR2-C₂ 现状）：
//   - Login：captcha 校验 + 密码校验 + lockout 检查 + 写 session + 签 JWT；失败统一
//     AUTH_FAILED 防枚举（lockout / captcha 错码独立暴露）
//   - AuthenticateBearer：JWT 路径（API Key 路径在 PR3 后挂上 "rmk_" 前缀分支）
//   - Logout：单 session 删除（不动 tv，JWT 自然过期）
//   - LogoutAllSessions：tv++ + sessions.expires_at=now() 单事务
//
// 不在本 PR 范围：
//   - API Key 鉴权（PR3）
//   - LandingURL 计算（依赖 tenancy 模块，后续 PR）
//   - outbox 事件发布（auth.login.succeeded 等，后续 PR）
package auth

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/crypto"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/identity/policy"
	"github.com/ffff5sec/RedMatrix/internal/identity/repo"
)

// PrincipalSource 标识 UserPrincipal 来源（jwt / apikey / internal）。
type PrincipalSource string

const (
	PrincipalSourceJWT      PrincipalSource = "jwt"
	PrincipalSourceAPIKey   PrincipalSource = "apikey"
	PrincipalSourceInternal PrincipalSource = "internal"
)

// LoginRequest 是登录请求的内部参数（与 RPC 层解耦）。
type LoginRequest struct {
	Username      string
	Password      string
	ClientIP      netip.Addr
	UserAgent     string
	CaptchaID     string // 仅当服务端启用 captcha 时必填
	CaptchaAnswer string
}

// LoginResult 是登录成功时返回给上层的结果。
type LoginResult struct {
	AccessToken        string
	ExpiresAt          time.Time
	User               *domain.User
	SessionID          string
	MustChangePassword bool
	// LandingURL 由后续 PR 在挂 tenancy 模块后填充；PR2-B 暂时留空。
	LandingURL string
}

// UserPrincipal 是当前请求的认证主体。Auth interceptor 写入 ctx，业务层读。
type UserPrincipal struct {
	UserID       string
	TenantID     string
	Username     string
	Role         domain.Role
	TokenVersion int
	SessionID    string // JWT 路径有；API Key 路径空
	APIKeyID     string // API Key 路径有；JWT 路径空
	Source       PrincipalSource
}

// Service 是 identity 模块的业务流接口。
type Service interface {
	// Login 校验密码 + 签 JWT + 写 session。
	// 返回 AUTH_FAILED（用户不存在 / 密码错 / 状态非 active 都混淆为同一码，防枚举）。
	Login(ctx context.Context, req LoginRequest) (*LoginResult, error)

	// AuthenticateBearer 解析 JWT 或 API Key（PR3 起），返回 UserPrincipal。
	// PR2-B 只支持 JWT；"rmk_" 前缀路径返回 NOT_IMPLEMENTED。
	AuthenticateBearer(ctx context.Context, raw string) (*UserPrincipal, error)

	// Logout 删除单 session（JWT 自然过期；不动 token_version）。
	Logout(ctx context.Context, sessionID string) error

	// LogoutAllSessions tv++ + 该用户全部未过期 session 置 expires_at=now()。
	// 影响该用户所有现存 JWT 立即失效（下次 AuthenticateBearer 时 tv 不匹配）。
	LogoutAllSessions(ctx context.Context, userID string) error
}

// dummyPlaintext 用于生成 dummy hash；实际值不重要——只要不可猜中即可。
const dummyPlaintext = "REDMATRIX_NEVER_MATCH_DUMMY_PLAINTEXT_v1"

// service 实现 Service。
type service struct {
	users    repo.Repository
	sessions repo.SessionRepository
	jwt      *crypto.Service
	lockout  policy.Lockout // 可空：nil 时跳过所有锁定逻辑（dev / 单测）
	captcha  policy.Captcha // 可空：nil 时跳过 captcha 检查
	now      func() time.Time

	// dummyHash 启动时一次性生成；用户不存在时也跑 VerifyPassword 保耗时一致。
	dummyHash string
}

// New 构造 AuthService。
//
// 参数：
//   - users / sessions：持久层
//   - jwt：JWT 服务（PR2-A）
//   - lockout：失败计数 / IP+账号锁定（可空，nil 表示禁用）
//   - captcha：图片验证码策略（可空，nil 表示禁用）
//
// 副作用：构造时跑一次 HashPassword 生成 dummy hash（约 1 次 argon2id 计算）。
func New(
	users repo.Repository,
	sessions repo.SessionRepository,
	jwt *crypto.Service,
	lockout policy.Lockout,
	captcha policy.Captcha,
) (Service, error) {
	if users == nil || sessions == nil || jwt == nil {
		return nil, errx.New(errx.ErrInternal, "auth.New: 依赖不能为 nil")
	}
	dummy, err := domain.HashPassword(dummyPlaintext)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "auth.New: 生成 dummy hash 失败")
	}
	return &service{
		users:     users,
		sessions:  sessions,
		jwt:       jwt,
		lockout:   lockout,
		captcha:   captcha,
		now:       time.Now,
		dummyHash: dummy,
	}, nil
}

// === Login ===

// Login 实现 LLD 10 §4.3 关键伪代码（含 lockout + captcha）。
//
// 流程：
//  1. IP 锁定 check（早退；暴露 AUTH_IP_LOCKED 给本人）
//  2. captcha check（IsRequired→ 必须通过，否则 AUTH_CAPTCHA_REQUIRED/INVALID）
//  3. 加载用户；不存在也走 dummy verify 保恒定耗时（防账号枚举）
//  4. argon2id 密码比对（恒定耗时；不论何种失败原因都跑）
//  5. 密码错 / 用户不存在 / 状态非 active → 记失败 + AUTH_FAILED（混淆）
//  6. 密码对 + 账号已锁定 → AUTH_ACCOUNT_LOCKED（不计失败；本人能感知）
//  7. 全通过 → 重置失败计数 + 写 session + 签 JWT + 刷 last_login
func (s *service) Login(ctx context.Context, req LoginRequest) (*LoginResult, error) {
	if strings.TrimSpace(req.Username) == "" || req.Password == "" {
		return nil, errx.New(errx.ErrAuthFailed, "用户名或密码错误")
	}

	// 1. IP 锁定 check（无 user 上下文也能查；fail-open 由 lockout 内部管）
	if s.lockout != nil {
		if locked, until := s.lockout.IsIPLocked(ctx, req.ClientIP); locked {
			return nil, errx.New(errx.ErrAuthIPLocked, "请稍后再试").
				WithFields("until", until.UTC().Format(time.RFC3339))
		}
	}

	// 2. Captcha check（在密码校验前；防对齐密码爆破耗 CPU）
	if s.captcha != nil && s.captcha.IsRequired(ctx, req.ClientIP, "") {
		if req.CaptchaID == "" || req.CaptchaAnswer == "" {
			return nil, errx.New(errx.ErrAuthCaptchaRequired, "请完成验证码")
		}
		ok, err := s.captcha.Verify(ctx, req.CaptchaID, req.CaptchaAnswer)
		if err != nil {
			// Redis 故障：透传 internal 错（caller 看到 Internal 而非可绕过的 INVALID）
			return nil, err
		}
		if !ok {
			return nil, errx.New(errx.ErrAuthCaptchaInvalid, "验证码错误或已过期")
		}
	}

	// 2. 加载用户
	u, lookupErr := s.users.GetByUsername(ctx, req.Username)
	hashToCompare := s.dummyHash
	found := lookupErr == nil && u != nil
	if found {
		hashToCompare = u.PasswordHash
	}

	// 3. 恒定耗时密码 verify（即使 found=false 也跑 dummy）
	pwdOK, _ := domain.VerifyPassword(req.Password, hashToCompare)
	statusOK := found && u.Status == domain.StatusActive

	// 4. 失败混淆路径
	if !found || !pwdOK || !statusOK {
		// DB 错原样透（不计入失败计数）
		if lookupErr != nil && !isUserNotFound(lookupErr) {
			return nil, lookupErr
		}
		// 计失败：账号 + IP 双维度
		var userIDForLockout string
		if found {
			userIDForLockout = u.ID
		}
		if s.lockout != nil {
			s.lockout.RecordFailure(ctx, req.ClientIP, userIDForLockout)
		}
		return nil, errx.New(errx.ErrAuthFailed, "用户名或密码错误")
	}

	// 5. 密码对 + 账号锁定 check（账号锁定本人能感知）
	if s.lockout != nil {
		if locked, until := s.lockout.IsAccountLocked(ctx, u.ID); locked {
			return nil, errx.New(errx.ErrAuthAccountLocked, "账号已锁定，请稍后再试").
				WithFields("until", until.UTC().Format(time.RFC3339))
		}
	}

	// 6. 成功路径：清失败计数
	if s.lockout != nil {
		s.lockout.ResetFailures(ctx, req.ClientIP, u.ID)
	}

	now := s.now().UTC()
	expiresAt := now.Add(s.jwt.AccessTTL())

	sess := &domain.Session{
		TenantID:     u.TenantID,
		UserID:       u.ID,
		UserAgent:    req.UserAgent,
		IP:           req.ClientIP,
		IssuedAt:     now,
		LastSeenAt:   now,
		TokenVersion: u.TokenVersion,
		ExpiresAt:    expiresAt,
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return nil, err
	}

	token, exp, err := s.jwt.Issue(u, sess.ID)
	if err != nil {
		// JWT 签失败：尽量回滚 session（best-effort）
		_ = s.sessions.Delete(ctx, sess.ID)
		return nil, err
	}

	if err := s.users.UpdateLastLogin(ctx, u.ID); err != nil {
		// 不阻塞登录；记录但返回成功。日志由 caller 处理。
		// 这里返回 nil 以保 Login 成功路径完整；real impl 可走 log.WithCtx
		_ = err
	}

	return &LoginResult{
		AccessToken:        token,
		ExpiresAt:          exp,
		User:               u,
		SessionID:          sess.ID,
		MustChangePassword: u.MustChangePassword,
	}, nil
}

// === AuthenticateBearer ===

// authAPIKeyPrefix 是 LLD 10 §8.1 约定的 API Key 前缀。
const authAPIKeyPrefix = "rmk_"

// AuthenticateBearer 解析 Bearer token，返回 UserPrincipal。
//
// PR2-B 仅支持 JWT；"rmk_" 前缀返回 NOT_IMPLEMENTED（PR3 实现）。
func (s *service) AuthenticateBearer(ctx context.Context, raw string) (*UserPrincipal, error) {
	if raw == "" {
		return nil, errx.New(errx.ErrAuthTokenInvalid, "token 为空")
	}
	if strings.HasPrefix(raw, authAPIKeyPrefix) {
		return nil, errx.New(errx.ErrNotImplemented, "API Key 鉴权暂未实现（PR3）")
	}

	claims, err := s.jwt.ParseAndVerify(raw)
	if err != nil {
		return nil, err
	}

	u, err := s.users.GetByID(ctx, claims.Subject)
	if err != nil {
		// user 找不到时混淆成 AUTH_FAILED（不暴露 user 状态）
		if isUserNotFound(err) {
			return nil, errx.New(errx.ErrAuthFailed, "用户名或密码错误")
		}
		return nil, err
	}

	if claims.TV != u.TokenVersion {
		return nil, errx.New(errx.ErrAuthTokenVersionMismatch, "凭证已失效").
			WithFields("user_id", u.ID)
	}
	if u.Status != domain.StatusActive {
		return nil, errx.New(errx.ErrAuthFailed, "用户名或密码错误")
	}

	return &UserPrincipal{
		UserID:       u.ID,
		TenantID:     u.TenantID,
		Username:     u.Username,
		Role:         u.Role,
		TokenVersion: u.TokenVersion,
		SessionID:    claims.Sid,
		Source:       PrincipalSourceJWT,
	}, nil
}

// === Logout / LogoutAllSessions ===

// Logout 删除单 session（不动 tv；JWT 自然过期）。LLD 10 §7.4：MVP 不做单 session JWT 黑名单。
func (s *service) Logout(ctx context.Context, sessionID string) error {
	if strings.TrimSpace(sessionID) == "" {
		return errx.New(errx.ErrInvalidInput, "session_id 不能为空")
	}
	return s.sessions.Delete(ctx, sessionID)
}

// LogoutAllSessions = tv++ + 该用户全部未过期 session 置 expires_at=now()（单事务）。
func (s *service) LogoutAllSessions(ctx context.Context, userID string) error {
	if strings.TrimSpace(userID) == "" {
		return errx.New(errx.ErrInvalidInput, "user_id 不能为空")
	}
	return s.users.LogoutAllSessions(ctx, userID)
}

// === helpers ===

func isUserNotFound(err error) bool {
	if err == nil {
		return false
	}
	c, ok := errx.GetCode(err)
	if !ok {
		return false
	}
	return c == errx.ErrUserNotFound
}
