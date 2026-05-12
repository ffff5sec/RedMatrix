// Package repo 插件包模块持久层（PR-S28）。
package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/pluginpkg/domain"
)

// PluginFilter ListPlugins 查询过滤。
type PluginFilter struct {
	Slug     string
	Platform string
	Active   *bool
}

// Page 通用分页。
type Page struct {
	Page     int
	PageSize int
}

// PluginRepository plugin_packages 表持久层。
type PluginRepository interface {
	Insert(ctx context.Context, p *domain.PluginPackage) error
	GetByID(ctx context.Context, id string) (*domain.PluginPackage, error)
	List(ctx context.Context, filter PluginFilter, page Page) ([]*domain.PluginPackage, int, error)

	// GetLatestActive (slug, platform) 内最新非 deprecated + is_active=true 的版本（uploaded_at DESC）。
	// 不存在返 ErrPluginNotFound。
	GetLatestActive(ctx context.Context, slug, platform string) (*domain.PluginPackage, error)

	UpdateActive(ctx context.Context, id string, isActive bool) error
	Deprecate(ctx context.Context, id string) error
}

// SigningKeyRepository plugin_signing_keys 表持久层。
type SigningKeyRepository interface {
	Insert(ctx context.Context, k *domain.SigningKey) error
	GetByKeyID(ctx context.Context, keyID string) (*domain.SigningKey, error)
	ListActive(ctx context.Context) ([]*domain.SigningKey, error)
	Revoke(ctx context.Context, keyID string) error
}
