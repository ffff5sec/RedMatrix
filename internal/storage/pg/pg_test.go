package pg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

const (
	// 指向不会监听的 loopback 端口。pgxpool.New 不会立即建连（lazy），
	// 故 Open 成功；Ping 在带 timeout 的 ctx 下快速失败 → BOOTSTRAP_DB_UNREACHABLE。
	unreachableDSN = "postgres://redmatrix_app:pw@127.0.0.1:1/redmatrix?sslmode=disable"
	unreachableMnt = "postgres://redmatrix_maintenance:pw@127.0.0.1:1/redmatrix?sslmode=disable"
)

// fastTestConfig 返回一份不会触发后台连接补齐的池配置（MinConns=0），
// 让 Open / Close 的单元测试在不可达 DSN 上能秒级完成。
func fastTestConfig() Config {
	return Config{
		AppDSN:              unreachableDSN,
		MaintenanceDSN:      unreachableMnt,
		AppMaxConns:         2,
		AppMinConns:         0,
		MaintenanceMaxConns: 2,
		MaintenanceMinConns: 0,
	}
}

// === Open / Close 基本路径 ===

func TestOpenLazyDoesNotConnect(t *testing.T) {
	p, err := Open(context.Background(), fastTestConfig())
	require.NoError(t, err, "pgxpool.New is lazy; should not connect on Open")
	require.NotNil(t, p)
	defer p.Close()

	assert.NotNil(t, p.App)
	assert.NotNil(t, p.Maintenance)
	assert.Nil(t, p.Admin)
}

func TestOpenRequiresAppDSN(t *testing.T) {
	_, err := Open(context.Background(), Config{
		MaintenanceDSN: unreachableMnt,
	})
	require.Error(t, err)
	c, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)

	var de *errx.DomainError
	require.True(t, errors.As(err, &de))
	assert.Equal(t, "PG_DSN", de.Fields["var"])
}

func TestOpenRequiresMaintenanceDSN(t *testing.T) {
	_, err := Open(context.Background(), Config{
		AppDSN: unreachableDSN,
	})
	require.Error(t, err)
	c, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)

	var de *errx.DomainError
	require.True(t, errors.As(err, &de))
	assert.Equal(t, "PG_DSN_MAINTENANCE", de.Fields["var"])
}

func TestOpenWithAdminDSN(t *testing.T) {
	cfg := fastTestConfig()
	cfg.AdminDSN = "postgres://redmatrix_admin:pw@127.0.0.1:1/redmatrix?sslmode=disable"
	cfg.AdminMaxConns = 1
	p, err := Open(context.Background(), cfg)
	require.NoError(t, err)
	defer p.Close()

	assert.NotNil(t, p.Admin)
}

func TestOpenWithSyntacticallyInvalidDSN(t *testing.T) {
	cfg := fastTestConfig()
	cfg.AppDSN = "this is not a dsn"
	_, err := Open(context.Background(), cfg)
	require.Error(t, err)
	c, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)

	var de *errx.DomainError
	require.True(t, errors.As(err, &de))
	assert.Equal(t, "app", de.Fields["pool"])
}

// === Ping ===

func TestPingFailsOnUnreachable(t *testing.T) {
	p, err := Open(context.Background(), fastTestConfig())
	require.NoError(t, err)
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = p.Ping(ctx)
	require.Error(t, err)
	c, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, c)
}

func TestPingNilPool(t *testing.T) {
	var p *Pool
	err := p.Ping(context.Background())
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, c)
}

// === Close 安全性 ===

func TestCloseNilSafe(t *testing.T) {
	var p *Pool
	p.Close() // 不应 panic
}

func TestCloseEmptyPoolSafe(t *testing.T) {
	p := &Pool{} // 所有内嵌 pool 为 nil
	p.Close()    // 不应 panic
}

// === Stats ===

func TestStats(t *testing.T) {
	p, err := Open(context.Background(), fastTestConfig())
	require.NoError(t, err)
	defer p.Close()

	s := p.Stats()
	assert.NotNil(t, s.App)
	assert.NotNil(t, s.Maintenance)
	assert.Nil(t, s.Admin)
}

func TestStatsNilPool(t *testing.T) {
	var p *Pool
	s := p.Stats() // 不应 panic
	assert.Nil(t, s.App)
	assert.Nil(t, s.Maintenance)
	assert.Nil(t, s.Admin)
}

// === Sanitize ===

func TestSanitizeRedactsPassword(t *testing.T) {
	in := "postgres://redmatrix_app:supersecret@host:5432/db?sslmode=require"
	out := Sanitize(in)
	assert.NotContains(t, out, "supersecret")
	assert.Contains(t, out, "redmatrix_app")
	assert.Contains(t, out, "host")
}

func TestSanitizeNoUserInfo(t *testing.T) {
	in := "postgres://host:5432/db"
	out := Sanitize(in)
	assert.Equal(t, in, out)
}

func TestSanitizeEmpty(t *testing.T) {
	assert.Equal(t, "", Sanitize(""))
}

func TestSanitizeInvalid(t *testing.T) {
	// url.Parse 对 "postgres://" 这类残缺串是宽容的；用真正的非法字符触发 err。
	out := Sanitize("postgres://%%%@host/db")
	assert.Equal(t, "<invalid dsn>", out)
}

// === 默认值 ===

func TestWithDefaultsFillsZero(t *testing.T) {
	cfg := withDefaults(Config{})
	assert.Equal(t, int32(defaultAppMaxConns), cfg.AppMaxConns)
	assert.Equal(t, int32(defaultAppMinConns), cfg.AppMinConns)
	assert.Equal(t, int32(defaultMaintenanceMaxConns), cfg.MaintenanceMaxConns)
	assert.Equal(t, int32(defaultMaintenanceMinConns), cfg.MaintenanceMinConns)
	assert.Equal(t, int32(defaultAdminMaxConns), cfg.AdminMaxConns)
	assert.Equal(t, defaultConnMaxLifetime, cfg.ConnMaxLifetime)
	assert.Equal(t, defaultConnMaxIdleTime, cfg.ConnMaxIdleTime)
}

func TestWithDefaultsExplicitMaxConnsKeepsExplicitMinConns(t *testing.T) {
	// 关键不变量：MaxConns 显式 > 0 时，MinConns 不再被回填默认。
	// 否则一个想要"小池"的调用方（如测试）会被默认 MinConns 反向放大。
	cfg := withDefaults(Config{
		AppMaxConns:         2,
		AppMinConns:         0, // 显式 0 应当保留
		MaintenanceMaxConns: 2,
		MaintenanceMinConns: 0,
	})
	assert.Equal(t, int32(2), cfg.AppMaxConns)
	assert.Equal(t, int32(0), cfg.AppMinConns)
	assert.Equal(t, int32(2), cfg.MaintenanceMaxConns)
	assert.Equal(t, int32(0), cfg.MaintenanceMinConns)
}

func TestWithDefaultsRespectsLifetimeOnly(t *testing.T) {
	cfg := withDefaults(Config{
		ConnMaxLifetime: 5 * time.Minute,
	})
	// MaxConns 未显式 → 仍走默认 + 默认 MinConns
	assert.Equal(t, int32(defaultAppMaxConns), cfg.AppMaxConns)
	assert.Equal(t, int32(defaultAppMinConns), cfg.AppMinConns)
	assert.Equal(t, 5*time.Minute, cfg.ConnMaxLifetime)
}
