// Package identity 顶层包当前仅承载 Bootstrap：首次启动落地一个 SuperAdmin。
//
// 子包：
//   - domain：聚合 + 不变式
//   - crypto：JWT / API Key / argon2id
//   - policy：lockout / captcha
//   - repo：PG 持久层
//   - auth：Login/Logout/AuthenticateBearer/API Key CRUD
//   - handler：ConnectRPC 适配
//
// Bootstrap 设计（LLD 10 §9.4）：
//
//  1. 数 SuperAdmin → > 0 即跳过（D-12 幂等）
//  2. 密码：env 给则用；空则随机 16 字符强密码 + 一次性返给 caller（caller 决定打不打日志）
//  3. 创建用户：tenant_id=NULL（CHECK 强制 SuperAdmin 跨租户），TokenVersion=0，
//     MustChangePassword=true（首登强制改密）
//
// 不在本包：
//   - 默认租户创建（tenancy 模块未落地；SuperAdmin 不需要 tenant）
//   - bootstrap_password_used 标记位（system_settings 表未落地，靠 CountByRole 自然幂等）
package identity

import (
	"context"
	"crypto/rand"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/identity/repo"
)

// BootstrapConfig 是 Bootstrap 的入参（与 config.BootstrapAdmin 解耦）。
type BootstrapConfig struct {
	Username string // 默认 "admin"
	Email    string // 默认 "admin@example.com"
	Password string // 空 → 随机生成 16 字符强密码
}

// BootstrapResult 是 Bootstrap 返回信息。
//
// Created=true 时：刚刚创建了 SuperAdmin
//   - GeneratedPassword 非空：caller 配的 Password 为空，本次新生成；caller
//     **必须**把它输出给操作员（一次性，不再持久）
//   - GeneratedPassword 空：caller 提供了密码，已直接 hash 入库
//
// Created=false 时：已存在 SuperAdmin，跳过；GeneratedPassword 为空。
type BootstrapResult struct {
	Created           bool
	GeneratedPassword string // 仅当 Created && cfg.Password 为空时非空
}

// 密码策略：bootstrap 至少 12 字符。完整 LLD §6 password policy 留给后续 PR 接入。
const minBootstrapPasswordLen = 12

// 随机密码长度（足够强且终端友好）。
const randomBootstrapPasswordLen = 16

// 强密码字母表：72 个无歧义可打印 ASCII；终端复制粘贴友好（不含引号 / 反斜杠 / 空格）。
const bootstrapPasswordAlphabet = "" +
	"ABCDEFGHJKLMNPQRSTUVWXYZ" + // 24（去 IO）
	"abcdefghijkmnpqrstuvwxyz" + // 24（去 lo）
	"23456789" + // 8（去 0/1）
	"!#$%&*+-=?@^_~" // 14

// Bootstrap 落地首个 SuperAdmin（幂等）。
//
// 错误：
//   - cfg.Username/Email 为空 → ErrInvalidInput
//   - cfg.Password 非空且过短 → ErrAuthPasswordTooWeak
//   - DB 故障 → ErrDatabase（透传 repo）
func Bootstrap(ctx context.Context, users repo.Repository, cfg BootstrapConfig) (*BootstrapResult, error) {
	if users == nil {
		return nil, errx.New(errx.ErrInternal, "Bootstrap: users repo 不能为 nil")
	}
	if strings.TrimSpace(cfg.Username) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "Bootstrap: username 不能为空")
	}
	if strings.TrimSpace(cfg.Email) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "Bootstrap: email 不能为空")
	}

	// 1. 幂等检查
	n, err := users.CountByRole(ctx, domain.RoleSuperAdmin)
	if err != nil {
		return nil, err
	}
	if n > 0 {
		return &BootstrapResult{Created: false}, nil
	}

	// 2. 决定密码：给定 / 随机生成
	plain := cfg.Password
	generated := ""
	if plain == "" {
		gen, err := randomStrongPassword(randomBootstrapPasswordLen)
		if err != nil {
			return nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err,
				"Bootstrap: 生成随机密码失败")
		}
		plain = gen
		generated = gen
	} else if len(plain) < minBootstrapPasswordLen {
		return nil, errx.New(errx.ErrAuthPasswordTooWeak,
			"Bootstrap: 密码至少 12 字符")
	}

	hash, err := domain.HashPassword(plain)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "Bootstrap: 密码哈希失败")
	}

	// 3. 创建 SuperAdmin（tenant_id=NULL；schema CHECK 强制）
	u := &domain.User{
		Username:           cfg.Username,
		Email:              cfg.Email,
		PasswordHash:       hash,
		Role:               domain.RoleSuperAdmin,
		Status:             domain.StatusActive,
		TokenVersion:       0,
		MustChangePassword: true,
	}
	if err := users.Create(ctx, u); err != nil {
		return nil, err
	}

	return &BootstrapResult{
		Created:           true,
		GeneratedPassword: generated,
	}, nil
}

// randomStrongPassword crypto/rand 抽 n 个字符。拒绝采样防 mod 偏置。
func randomStrongPassword(n int) (string, error) {
	abLen := len(bootstrapPasswordAlphabet)
	if abLen == 0 || abLen > 256 {
		return "", errx.New(errx.ErrInternal, "alphabet 长度非法")
	}
	maxAcceptable := 256 - (256 % abLen)
	out := make([]byte, n)
	buf := make([]byte, 1)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= maxAcceptable {
			continue
		}
		out[i] = bootstrapPasswordAlphabet[int(buf[0])%abLen]
		i++
	}
	return string(out), nil
}
