//go:build integration

// Package pgharness 提供 testcontainers 启 PG 容器的 helper，仅在
// `go test -tags=integration` 下编译。
//
// 用法：
//
//	func TestFoo_Real(t *testing.T) {
//	    pg := pgharness.Start(t)
//	    db, _ := sql.Open("pgx", pg.AdminDSN)
//	    // ...
//	}
//
// 容器在 t.Cleanup 时自动 Terminate。
package pgharness

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // 注册 sql.Open("pgx", ...)
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	appPassword         = "app_test_pw"
	maintenancePassword = "maint_test_pw"

	imageDefault = "postgres:16-alpine"
	dbDefault    = "redmatrix_test"
)

// PG 是一个运行中的 PG 容器及其各 role 的 DSN。
//
// DSN 用 sslmode=prefer，pgx 会先尝试 TLS，失败则降级 plain（容器无 TLS）。
// 这样既兼容 config.Validate（拒绝 sslmode=disable），又能连上无 TLS 的容器。
type PG struct {
	Container      *postgres.PostgresContainer
	AdminDSN       string // postgres role（容器超管，DDL）
	AppDSN         string // redmatrix_app
	MaintenanceDSN string // redmatrix_maintenance
}

// Start 启动 PG 容器并预创建 redmatrix_app + redmatrix_maintenance role
// （含密码，让 App / Maintenance DSN 能直接 auth）。
//
// 容器在 t.Cleanup 时关闭。Docker 不可达会让 testcontainers 自身报错，
// 调用方运行集成测试前请确保 Docker daemon 在线。
func Start(t *testing.T) *PG {
	t.Helper()

	ctx := context.Background()
	container, err := postgres.Run(ctx,
		imageDefault,
		postgres.WithDatabase(dbDefault),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err, "PG 容器启动失败（确认 Docker daemon 已运行）")

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("PG 容器 terminate 失败: %v", err)
		}
	})

	adminDSN, err := container.ConnectionString(ctx, "sslmode=prefer")
	require.NoError(t, err)

	require.NoError(t, createRoles(ctx, adminDSN))

	return &PG{
		Container:      container,
		AdminDSN:       adminDSN,
		AppDSN:         replaceUserPassword(adminDSN, "redmatrix_app", appPassword),
		MaintenanceDSN: replaceUserPassword(adminDSN, "redmatrix_maintenance", maintenancePassword),
	}
}

// createRoles 用 superuser 创建 redmatrix_app + redmatrix_maintenance（含密码 + GRANT）。
//
// 与 internal/storage/migrate 0001 互补：迁移以 IF NOT EXISTS 方式处理 role，
// harness 在迁移之前就已建好（含密码），让所有 DSN 立即可用。
func createRoles(ctx context.Context, adminDSN string) error {
	db, err := sql.Open("pgx", adminDSN)
	if err != nil {
		return fmt.Errorf("sql.Open admin: %w", err)
	}
	defer db.Close()

	stmts := []string{
		fmt.Sprintf(`CREATE ROLE redmatrix_app WITH LOGIN PASSWORD '%s'`, appPassword),
		fmt.Sprintf(`CREATE ROLE redmatrix_maintenance WITH LOGIN PASSWORD '%s'`, maintenancePassword),
		`GRANT USAGE, CREATE ON SCHEMA public TO redmatrix_app, redmatrix_maintenance`,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO redmatrix_app, redmatrix_maintenance`,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO redmatrix_app, redmatrix_maintenance`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", s, err)
		}
	}
	return nil
}

// replaceUserPassword 把 dsn 里的 userinfo 换成 user:password 形式。失败则原样返回（让上游测试自行 fail）。
func replaceUserPassword(dsn, user, password string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	u.User = url.UserPassword(user, password)
	return u.String()
}

// Sanitize 同 pg.Sanitize（但避免 import cycle 故复制一份）；测试断言用。
func Sanitize(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "<invalid>"
	}
	return u.Redacted()
}

// EnsureDockerSkipReason 是给希望"硬性需要 Docker"的测试预留的钩子。
// 当前实现不主动 probe（依赖 testcontainers 自身报错），保留 API 待后续用。
func EnsureDockerSkipReason() string {
	if v := strings.TrimSpace(""); v != "" {
		return v
	}
	return ""
}
