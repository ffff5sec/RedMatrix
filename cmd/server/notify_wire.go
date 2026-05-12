// notify_wire.go 装配 NotifyService（PR-S25）。
//
// 依赖：pgxpool.App + identity Auth Service + tenancy ProjectMember repo（PA RBAC）。
// SMTP 配置走 env NOTIFY_SMTP_HOST/PORT/USERNAME/PASSWORD/FROM/USE_TLS；未配置 → email channel 失败回退到 dead。
package main

import (
	"net/http"
	"os"
	"strconv"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/notify/v1/notifyv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	"github.com/ffff5sec/RedMatrix/internal/notify"
	notifyhandler "github.com/ffff5sec/RedMatrix/internal/notify/handler"
	notifyrepo "github.com/ffff5sec/RedMatrix/internal/notify/repo"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
	tenancyrepo "github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// notifyMount mount 信息。
type notifyMount struct {
	path    string
	handler http.Handler
}

// buildNotifyMount 装配 NotifyService。
//
// 返回值：mount + 桥接到 scan 的 hook（cmd/server 主流程注入到 scanDeps.Notifier）。
func buildNotifyMount(
	pool *pg.Pool,
	authSvc auth.Service,
	logger *log.Logger,
) (*notifyMount, notify.Service, *notify.ScanHook, error) {
	if pool == nil || pool.App == nil {
		return nil, nil, nil, errx.New(errx.ErrInternal, "buildNotifyMount: pg.Pool.App 不能为 nil")
	}
	if authSvc == nil {
		return nil, nil, nil, errx.New(errx.ErrInternal, "buildNotifyMount: authSvc 不能为 nil")
	}

	subs := notifyrepo.NewSubscriptionPG(pool.App)
	dels := notifyrepo.NewDeliveryPG(pool.App)

	webhook := notify.NewWebhookAdapter()
	smtpCfg := loadSMTPConfigFromEnv()
	email := notify.NewEmailAdapter(smtpCfg)

	svc, err := notify.New(notify.Deps{
		Subscriptions: subs,
		Deliveries:    dels,
		Adapters: []notify.ChannelAdapter{
			webhook,
			email,
		},
		Logger: logger,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	memberDB := tenancyrepo.NewProjectMemberPG(pool.App)
	h, err := notifyhandler.New(svc, authSvc, memberDB)
	if err != nil {
		return nil, nil, nil, err
	}
	path, hh := notifyv1connect.NewNotifyServiceHandler(h)

	hook := notify.NewScanHook(svc, logger)
	return &notifyMount{path: path, handler: hh}, svc, hook, nil
}

// loadSMTPConfigFromEnv 从 env 读 SMTP 配置；missing → 字段空 → Configured() false。
func loadSMTPConfigFromEnv() notify.SMTPConfig {
	port, _ := strconv.Atoi(os.Getenv("NOTIFY_SMTP_PORT"))
	useTLS := os.Getenv("NOTIFY_SMTP_USE_TLS") == "true"
	return notify.SMTPConfig{
		Host:     os.Getenv("NOTIFY_SMTP_HOST"),
		Port:     port,
		Username: os.Getenv("NOTIFY_SMTP_USERNAME"),
		Password: os.Getenv("NOTIFY_SMTP_PASSWORD"),
		From:     os.Getenv("NOTIFY_SMTP_FROM"),
		UseTLS:   useTLS,
	}
}
