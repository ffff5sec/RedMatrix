package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// NodeCertificateRepository 是 node_certificates 表的持久层接口（LLD 11 §3.6）。
//
// 错误约定：
//   - GetBySerial / GetByFingerprint 找不到 → ErrNodeCertExpired（无独立 NotFound
//     错码；mTLS 校验路径返"证书已过期"语义合理）—— 注意：service 层可上层包装
//   - Insert serial / fingerprint 重复 → ErrDatabase（极少见，无独立错码）
//   - 其他 DB 故障 → ErrDatabase 包装
type NodeCertificateRepository interface {
	// Insert 写入新证书行；要求 c.ValidateForCreate 已通过。
	Insert(ctx context.Context, c *domain.NodeCertificate) error

	// GetBySerial 按 serial_number 查；找不到 → ErrNodeCertExpired
	// （mTLS 校验路径返"证书无效/过期"语义；不返 NotFound 防 ID 枚举）。
	GetBySerial(ctx context.Context, serial string) (*domain.NodeCertificate, error)

	// GetByFingerprint mTLS hot path：peer cert 的 SHA-256 → 反查记录。
	GetByFingerprint(ctx context.Context, fingerprint string) (*domain.NodeCertificate, error)

	// ListByNode 列某节点全部 cert（含已撤 / 已过期），issued_at DESC。
	ListByNode(ctx context.Context, nodeID string) ([]*domain.NodeCertificate, error)

	// Revoke 写 revoked_at = now()；幂等（COALESCE 保留首次值）。
	// 行不存在 → ErrNodeCertExpired。
	Revoke(ctx context.Context, id string) error
}
