// Package enroll 实现 Agent 首启 enrollment：
//
//	store.Load → ErrNotEnrolled
//	→ TenancyService.RedeemRegistrationToken(plaintext, node_name, version)
//	→ store.Save(cert + key + ca + node_id)
//	→ 后续启动直接走 store.Load
//
// 失败语义：
//   - 已 enroll → 直接返当前 enrollment（caller 复用）
//   - token 无效 / 已用 / 已撤 → ErrNodeRegistrationTokenInvalid（透传）
//   - 网络故障 → 透传给 caller 决定是否退出
package enroll

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
	"github.com/ffff5sec/RedMatrix/internal/agent/store"
)

// Request 是 Enroll 入参。
type Request struct {
	Plaintext string // RegistrationToken 原文 rmnode_xxx
	NodeName  string // 租户内唯一
	Version   string // Agent 版本（可空）
}

// Validate 跑 Enroll 前的本地校验。
func (r *Request) Validate() error {
	if r == nil {
		return errors.New("enroll: request is nil")
	}
	if strings.TrimSpace(r.Plaintext) == "" {
		return errors.New("enroll: token plaintext 不能为空")
	}
	if strings.TrimSpace(r.NodeName) == "" {
		return errors.New("enroll: node_name 不能为空")
	}
	return nil
}

// Enroller 提供 Ensure 方法：已 enroll → 复用；未 enroll → Redeem + 持久。
type Enroller struct {
	Store  *store.Store
	Client tenancyv1connect.TenancyServiceClient
}

// Ensure 保证返一份可用的 enrollment（loaded 或新签）。
//
// req 仅在需要 Redeem 时被读；已 enroll 状态会跳过校验。
func (e *Enroller) Ensure(ctx context.Context, req Request) (*store.Enrollment, error) {
	if e == nil || e.Store == nil || e.Client == nil {
		return nil, errors.New("enroll: Enroller 依赖未装齐")
	}
	if existing, err := e.Store.Load(); err == nil {
		return existing, nil
	} else if !errors.Is(err, store.ErrNotEnrolled) {
		return nil, fmt.Errorf("enroll: 读已存 enrollment: %w", err)
	}

	if err := req.Validate(); err != nil {
		return nil, err
	}

	res, err := e.Client.RedeemRegistrationToken(ctx, connect.NewRequest(&tenancyv1.RedeemRegistrationTokenRequest{
		Plaintext: req.Plaintext,
		NodeName:  req.NodeName,
		Version:   req.Version,
	}))
	if err != nil {
		return nil, fmt.Errorf("enroll: Redeem 调用失败: %w", err)
	}
	msg := res.Msg
	if msg.GetNode() == nil {
		return nil, errors.New("enroll: server 返回空 Node")
	}
	if msg.GetNodeCertPem() == "" || msg.GetNodeKeyPem() == "" || msg.GetCaCertPem() == "" {
		return nil, errors.New("enroll: server 未签发 cert（CA 未配？）")
	}

	en := &store.Enrollment{
		NodeID:    msg.GetNode().GetId(),
		CertPEM:   []byte(msg.GetNodeCertPem()),
		KeyPEM:    []byte(msg.GetNodeKeyPem()),
		CACertPEM: []byte(msg.GetCaCertPem()),
	}
	if err := e.Store.Save(en); err != nil {
		return nil, fmt.Errorf("enroll: 持久 enrollment: %w", err)
	}
	return en, nil
}
