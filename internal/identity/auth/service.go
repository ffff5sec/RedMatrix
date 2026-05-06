// Package auth 是 identity 模块的业务流层（Login/Logout/AuthenticateBearer/API Key）。
//
// 范围（PR3-B 现状）：
//   - Login：captcha + 密码 + lockout + session + JWT；失败统一 AUTH_FAILED 防枚举
//   - AuthenticateBearer：JWT 路径 + rmk_ 路径（API Key）
//   - Logout / LogoutAllSessions
//   - CreateAPIKey / ListAPIKeys / RevokeAPIKey
//
// 不在本 PR 范围：
//   - LandingURL（依赖 tenancy 模块）
//   - outbox 事件发布（auth.login.succeeded / api_key.created 等）
//   - scope 强制（authz interceptor，后续 PR）
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
	SessionID    string   // JWT 路径有；API Key 路径空
	APIKeyID     string   // API Key 路径有；JWT 路径空
	Scopes       []string // API Key 路径有；JWT 路径 nil
	Source       PrincipalSource
}

// CreateAPIKeyRequest 创建 API Key 的入参。
type CreateAPIKeyRequest struct {
	UserID    string     // owner（caller 从 ctx.principal 拿）
	Name      string     // 友好名（≤ 64 字符）
	Scopes    []string   // 可空 = 继承 user 全部权限
	ExpiresAt *time.Time // 可空 = 永不过期
}

// CreateAPIKeyResult 是 CreateAPIKey 的结果。
//
// Plaintext 是 rmk_<prefix><secret> 完整长令牌，**仅创建时一次性返回**；
// 后续无论从 List 还是 Get 都拿不回 secret。Server 不留 secret 副本。
type CreateAPIKeyResult struct {
	Key       *domain.APIKey // 持久态（不含 SecretHash —— 已清空）
	Plaintext string         // 一次性明文长令牌
}

// Service 是 identity 模块的业务流接口。
type Service interface {
	// Login 校验密码 + 签 JWT + 写 session。
	// 返回 AUTH_FAILED（用户不存在 / 密码错 / 状态非 active 都混淆为同一码，防枚举）。
	Login(ctx context.Context, req LoginRequest) (*LoginResult, error)

	// AuthenticateBearer 解析 JWT 或 API Key（rmk_ 前缀），返回 UserPrincipal。
	AuthenticateBearer(ctx context.Context, raw string) (*UserPrincipal, error)

	// Logout 删除单 session（JWT 自然过期；不动 token_version）。
	Logout(ctx context.Context, sessionID string) error

	// LogoutAllSessions tv++ + 该用户全部未过期 session 置 expires_at=now()。
	// 影响该用户所有现存 JWT 立即失效（下次 AuthenticateBearer 时 tv 不匹配）。
	LogoutAllSessions(ctx context.Context, userID string) error

	// CreateAPIKey 生成 + 持久 + 返回一次性明文长令牌。
	// 失败：keys repo 未注入 → ErrNotImplemented。
	CreateAPIKey(ctx context.Context, req CreateAPIKeyRequest) (*CreateAPIKeyResult, error)

	// ListAPIKeys 列出 userID 名下 keys（不含 SecretHash）。created_at DESC。
	ListAPIKeys(ctx context.Context, userID string) ([]*domain.APIKey, error)

	// RevokeAPIKey 撤销自己的 key（owner 校验：keyID 必须属于 userID，否则
	// 返 ErrAPIKeyNotFound 防 ID 枚举）。
	// SuperAdmin 强制撤其他用户 key 的能力留给后续 PR / 单独 RPC。
	RevokeAPIKey(ctx context.Context, userID, keyID string) error
}

// dummyPlaintext 用于生成 dummy hash；实际值不重要——只要不可猜中即可。
const dummyPlaintext = "REDMATRIX_NEVER_MATCH_DUMMY_PLAINTEXT_v1"

// service 实现 Service。
type service struct {
	users    repo.Repository
	sessions repo.SessionRepository
	keys     repo.APIKeyRepository // 可空：nil 时 CreateAPIKey/Revoke/List 与 rmk_ 路径返 NOT_IMPLEMENTED
	jwt      *crypto.Service
	lockout  policy.Lockout // 可空：nil 时跳过所有锁定逻辑
	captcha  policy.Captcha // 可空：nil 时跳过 captcha 检查
	now      func() time.Time

	// dummyHash 启动时一次性生成；用户不存在时也跑 VerifyPassword 保耗时一致。
	dummyHash string

	// dummyAPIKeySecret 启动时一次性生成；FindByPrefix 未命中时也跑一次 hash 比对。
	// SHA-256 本身常数时间，理论收益小，但保留路径一致性 + 防被 timing fingerprint。
	dummyAPIKeyHash string
}

// New 构造 AuthService。
//
// 参数：
//   - users / sessions：持久层（必填）
//   - keys：API Key 持久层（可空，nil 时 API Key 功能禁用）
//   - jwt：JWT 服务（PR2-A）
//   - lockout：失败计数 / IP+账号锁定（可空，nil 表示禁用）
//   - captcha：图片验证码策略（可空，nil 表示禁用）
//
// 副作用：构造时跑一次 HashPassword（argon2id）+ 一次随机 SHA-256 生成 dummy。
func New(
	users repo.Repository,
	sessions repo.SessionRepository,
	keys repo.APIKeyRepository,
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
	dummyKey, err := crypto.GenerateAPIKey()
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "auth.New: 生成 dummy api key hash 失败")
	}
	return &service{
		users:           users,
		sessions:        sessions,
		keys:            keys,
		jwt:             jwt,
		lockout:         lockout,
		captcha:         captcha,
		now:             time.Now,
		dummyHash:       dummy,
		dummyAPIKeyHash: dummyKey.SecretHash,
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
// 按 "rmk_" 前缀分流：API Key 路径走 authenticateAPIKey；其他走 JWT。
func (s *service) AuthenticateBearer(ctx context.Context, raw string) (*UserPrincipal, error) {
	if raw == "" {
		return nil, errx.New(errx.ErrAuthTokenInvalid, "token 为空")
	}
	if strings.HasPrefix(raw, authAPIKeyPrefix) {
		return s.authenticateAPIKey(ctx, raw)
	}
	return s.authenticateJWT(ctx, raw)
}

// authenticateJWT 走 JWT path（含 token_version 比对）。
func (s *service) authenticateJWT(ctx context.Context, raw string) (*UserPrincipal, error) {
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

// authenticateAPIKey 走 API Key path（LLD 10 §8.3）。
//
// 错码混淆原则：
//   - 解析失败 / prefix 找不到 / secret 不对 / user not active → AUTH_FAILED
//     （都混淆成同一码，防 prefix 枚举与 user 状态嗅探）
//   - 已撤销 → AUTH_API_KEY_REVOKED（本人能感知）
//   - 已过期 → AUTH_TOKEN_EXPIRED（本人能感知）
//
// 命中后异步刷 last_used_at（best-effort，独立 ctx + 5s timeout）。
func (s *service) authenticateAPIKey(ctx context.Context, raw string) (*UserPrincipal, error) {
	if s.keys == nil {
		return nil, errx.New(errx.ErrNotImplemented, "API Key 鉴权未启用")
	}

	prefix, secret, err := crypto.ParseAPIKey(raw)
	if err != nil {
		// 解析错也跑一次 dummy hash 比对保恒定耗时
		_ = crypto.VerifyAPIKeySecret("dummy", s.dummyAPIKeyHash)
		return nil, errx.New(errx.ErrAuthFailed, "用户名或密码错误")
	}

	key, lookupErr := s.keys.FindByPrefix(ctx, prefix)
	storedHash := s.dummyAPIKeyHash
	found := lookupErr == nil && key != nil
	if found {
		storedHash = key.SecretHash
	}

	// 恒定耗时 hash 比对（无论 found）
	hashOK := crypto.VerifyAPIKeySecret(secret, storedHash)

	if !found || !hashOK {
		// DB 故障（非 NotFound）原样透；其他混淆成 AUTH_FAILED
		if lookupErr != nil && !isAPIKeyNotFound(lookupErr) {
			return nil, lookupErr
		}
		return nil, errx.New(errx.ErrAuthFailed, "用户名或密码错误")
	}

	now := s.now().UTC()
	if key.IsRevoked() {
		return nil, errx.New(errx.ErrAuthAPIKeyRevoked, "API Key 已撤销").
			WithFields("api_key_id", key.ID)
	}
	if key.IsExpired(now) {
		return nil, errx.New(errx.ErrAuthTokenExpired, "API Key 已过期").
			WithFields("api_key_id", key.ID)
	}

	u, err := s.users.GetByID(ctx, key.UserID)
	if err != nil {
		if isUserNotFound(err) {
			return nil, errx.New(errx.ErrAuthFailed, "用户名或密码错误")
		}
		return nil, err
	}
	if u.Status != domain.StatusActive {
		return nil, errx.New(errx.ErrAuthFailed, "用户名或密码错误")
	}

	// 命中后异步刷 last_used_at（不阻塞；独立 ctx 防 caller cancel）
	keyID := key.ID
	//nolint:gosec // G118: fire-and-forget 必须脱离 caller ctx，否则 caller 一返回就 cancel
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.keys.UpdateLastUsed(bg, keyID)
	}()

	return &UserPrincipal{
		UserID:       u.ID,
		TenantID:     u.TenantID,
		Username:     u.Username,
		Role:         u.Role,
		TokenVersion: u.TokenVersion,
		APIKeyID:     key.ID,
		Scopes:       key.Scopes,
		Source:       PrincipalSourceAPIKey,
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

// === API Key CRUD ===

// CreateAPIKey 生成新 key + 持久化。
//
// 流程：
//  1. 校验入参（user 存在、name 非空、ExpiresAt 合法）
//  2. crypto.GenerateAPIKey → (plaintext, prefix, secret_hash)
//  3. domain.APIKey + ValidateForCreate
//  4. repo.Insert
//  5. 返回 plaintext + sanitized key（清空 SecretHash）
//
// 失败：keys repo 未注入 → ErrNotImplemented；user 不存在 → ErrUserNotFound 透传。
func (s *service) CreateAPIKey(ctx context.Context, req CreateAPIKeyRequest) (*CreateAPIKeyResult, error) {
	if s.keys == nil {
		return nil, errx.New(errx.ErrNotImplemented, "API Key 功能未启用")
	}
	if strings.TrimSpace(req.UserID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "user_id 不能为空")
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "name 不能为空")
	}

	// 校 user 存在 + active（不让 disabled 用户新增 key）
	u, err := s.users.GetByID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	if u.Status != domain.StatusActive {
		return nil, errx.New(errx.ErrInvalidInput, "用户非 active 状态，禁止创建 API Key")
	}

	gen, err := crypto.GenerateAPIKey()
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	k := &domain.APIKey{
		TenantID:   u.TenantID,
		UserID:     u.ID,
		Name:       req.Name,
		KeyPrefix:  gen.Prefix,
		SecretHash: gen.SecretHash,
		Scopes:     req.Scopes,
		ExpiresAt:  req.ExpiresAt,
		CreatedAt:  now,
	}
	if err := s.keys.Insert(ctx, k); err != nil {
		return nil, err
	}

	// 返给上层前清空 SecretHash —— 任何 caller / 日志都不该见到 hash
	sanitized := *k
	sanitized.SecretHash = ""

	return &CreateAPIKeyResult{
		Key:       &sanitized,
		Plaintext: gen.Plaintext,
	}, nil
}

// ListAPIKeys 列出 userID 名下全部 key（含已撤销 / 已过期）。
// 返回时清空 SecretHash 字段。
func (s *service) ListAPIKeys(ctx context.Context, userID string) ([]*domain.APIKey, error) {
	if s.keys == nil {
		return nil, errx.New(errx.ErrNotImplemented, "API Key 功能未启用")
	}
	if strings.TrimSpace(userID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "user_id 不能为空")
	}
	keys, err := s.keys.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		k.SecretHash = ""
	}
	return keys, nil
}

// RevokeAPIKey 撤销自己的 key（owner 校验）。
//
// 安全约束：
//   - keyID 必须属于 userID；不属于时返 ErrAPIKeyNotFound（防 ID 枚举：
//     攻击者无法借此区分"key 不存在"与"key 不属于你"）
//   - 已撤销的再调一遍仍返 nil（repo 幂等）
//   - 找不到 key → ErrAPIKeyNotFound
func (s *service) RevokeAPIKey(ctx context.Context, userID, keyID string) error {
	if s.keys == nil {
		return errx.New(errx.ErrNotImplemented, "API Key 功能未启用")
	}
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(keyID) == "" {
		return errx.New(errx.ErrInvalidInput, "user_id / key_id 不能为空")
	}

	k, err := s.keys.GetByID(ctx, keyID)
	if err != nil {
		return err
	}
	if k.UserID != userID {
		// owner 不匹配：返 NotFound（同上：防 ID 枚举）
		return errx.New(errx.ErrAPIKeyNotFound, "api_key 不存在").
			WithFields("api_key_id", keyID)
	}
	return s.keys.Revoke(ctx, keyID)
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

func isAPIKeyNotFound(err error) bool {
	if err == nil {
		return false
	}
	c, ok := errx.GetCode(err)
	if !ok {
		return false
	}
	return c == errx.ErrAPIKeyNotFound
}
