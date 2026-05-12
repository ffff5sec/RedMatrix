// pluginpkg_wire.go 装配 PluginPackageService（PR-S28）。
//
// 私钥从 env PLUGIN_SIGNING_KEY_BASE64 加载；空 → 上传被拒（read-only 模式）。
package main

import (
	"context"
	"net/http"
	"os"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/pluginpkg/v1/pluginpkgv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/pluginpkg"
	pluginhandler "github.com/ffff5sec/RedMatrix/internal/pluginpkg/handler"
	pluginrepo "github.com/ffff5sec/RedMatrix/internal/pluginpkg/repo"
	"github.com/ffff5sec/RedMatrix/internal/storage/minio"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
)

type pluginpkgMount struct {
	path    string
	handler http.Handler
}

// DefaultSigningKeyID 默认 key_id；可通过 env PLUGIN_SIGNING_KEY_ID 覆盖。
const DefaultSigningKeyID = "redmatrix-default"

// buildPluginPkgMount 装配 PluginPackageService。
// 启动期自动注册当前签名 key 到 plugin_signing_keys（幂等）。
func buildPluginPkgMount(
	ctx context.Context,
	pool *pg.Pool,
	mc *minio.Client,
	authSvc auth.Service,
	logger *log.Logger,
) (*pluginpkgMount, pluginpkg.Service, error) {
	if pool == nil || pool.App == nil {
		return nil, nil, errx.New(errx.ErrInternal, "buildPluginPkgMount: pg.Pool.App 不能为 nil")
	}
	if authSvc == nil {
		return nil, nil, errx.New(errx.ErrInternal, "buildPluginPkgMount: authSvc 不能为 nil")
	}
	if mc == nil || mc.Client == nil {
		return nil, nil, errx.New(errx.ErrInternal, "buildPluginPkgMount: MinIO 未配置")
	}

	packages := pluginrepo.NewPluginPG(pool.App)
	keys := pluginrepo.NewSigningKeyPG(pool.App)

	// 加载私钥（可空 — 空时 upload RPC 报错）
	var priv []byte
	keyID := os.Getenv("PLUGIN_SIGNING_KEY_ID")
	if keyID == "" {
		keyID = DefaultSigningKeyID
	}
	privB64 := os.Getenv("PLUGIN_SIGNING_KEY_BASE64")
	var signingPriv []byte
	if privB64 != "" {
		p, err := pluginpkg.LoadPrivateKeyFromBase64(privB64)
		if err != nil {
			if logger != nil {
				logger.LogError(ctx, "pluginpkg: PLUGIN_SIGNING_KEY_BASE64 加载失败，upload 将被拒", err)
			}
		} else {
			signingPriv = p
			priv = p
		}
	} else if logger != nil {
		logger.Info("pluginpkg: PLUGIN_SIGNING_KEY_BASE64 未配置，UploadPackage 将被拒")
	}

	// 启动期把公钥注册到 plugin_signing_keys（幂等）
	if signingPriv != nil {
		if err := pluginpkg.EnsureSigningKeyRegistered(ctx, keys, keyID, signingPriv,
			"启动时从 PLUGIN_SIGNING_KEY_BASE64 自动注册"); err != nil && logger != nil {
			logger.LogError(ctx, "pluginpkg: 注册签名公钥失败", err)
		}
	}

	svc, err := pluginpkg.New(pluginpkg.Deps{
		Packages:       packages,
		SigningKeys:    keys,
		MinIO:          mc.Client,
		SigningKeyID:   keyID,
		SigningPrivate: priv,
	})
	if err != nil {
		return nil, nil, err
	}

	h, err := pluginhandler.New(svc, authSvc)
	if err != nil {
		return nil, nil, err
	}
	path, hh := pluginpkgv1connect.NewPluginPackageServiceHandler(h)
	return &pluginpkgMount{path: path, handler: hh}, svc, nil
}
