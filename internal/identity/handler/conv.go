package handler

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	identityv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/identity/v1"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// userToProto domain.User → identityv1.User。nil → nil。
func userToProto(u *domain.User) *identityv1.User {
	if u == nil {
		return nil
	}
	out := &identityv1.User{
		Id:        u.ID,
		TenantId:  u.TenantID,
		Username:  u.Username,
		Role:      string(u.Role),
		Status:    string(u.Status),
		CreatedAt: timestampProto(u.CreatedAt),
	}
	if u.Email != "" {
		e := u.Email
		out.Email = &e
	}
	if !u.LastLoginAt.IsZero() {
		out.LastLoginAt = timestampProto(u.LastLoginAt)
	}
	return out
}

// apiKeyToProto domain.APIKey → identityv1.APIKey。nil → nil。
// 永不返 SecretHash（service 层已清空，这里也不读）。
func apiKeyToProto(k *domain.APIKey) *identityv1.APIKey {
	if k == nil {
		return nil
	}
	out := &identityv1.APIKey{
		Id:        k.ID,
		UserId:    k.UserID,
		TenantId:  k.TenantID,
		Name:      k.Name,
		KeyPrefix: k.KeyPrefix,
		Scopes:    append([]string(nil), k.Scopes...), // 浅拷防共享底层数组
		CreatedAt: timestampProto(k.CreatedAt),
	}
	if k.ExpiresAt != nil {
		out.ExpiresAt = timestampProto(*k.ExpiresAt)
	}
	if k.LastUsedAt != nil {
		out.LastUsedAt = timestampProto(*k.LastUsedAt)
	}
	if k.RevokedAt != nil {
		out.RevokedAt = timestampProto(*k.RevokedAt)
	}
	return out
}

// timestampProto time.Time → *timestamppb.Timestamp；零值 → nil。
func timestampProto(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
