//go:build integration

package pg

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
)

// TestOpenAndPing_RealPG 验证 Open + Ping 在真实 PG 上工作。
func TestOpenAndPing_RealPG(t *testing.T) {
	h := pgharness.Start(t)

	pool, err := Open(context.Background(), Config{
		AppDSN:         h.AppDSN,
		MaintenanceDSN: h.MaintenanceDSN,
		AdminDSN:       h.AdminDSN,
	})
	require.NoError(t, err)
	defer pool.Close()

	assert.NotNil(t, pool.Admin, "AdminDSN 配置后 Admin pool 应非 nil")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, pool.Ping(ctx))

	// Stats 应反映默认配置
	s := pool.Stats()
	require.NotNil(t, s.App)
	assert.Equal(t, int32(defaultAppMaxConns), s.App.MaxConns())
	require.NotNil(t, s.Maintenance)
	assert.Equal(t, int32(defaultMaintenanceMaxConns), s.Maintenance.MaxConns())
	require.NotNil(t, s.Admin)
}

// TestPing_PartialFailure 一个池可达 + 另一个不可达 → Ping 应失败并指出具体池。
func TestPing_PartialFailure(t *testing.T) {
	h := pgharness.Start(t)

	pool, err := Open(context.Background(), Config{
		AppDSN:         h.AppDSN,
		MaintenanceDSN: "postgres://redmatrix_maintenance:wrong@127.0.0.1:1/redmatrix_test?sslmode=prefer",
		// 用小池 + MinConns=0 防止 maintenance 后台无限重连
		AppMaxConns:         2,
		AppMinConns:         0,
		MaintenanceMaxConns: 2,
		MaintenanceMinConns: 0,
	})
	require.NoError(t, err)
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = pool.Ping(ctx)
	require.Error(t, err)

	c, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, c)

	var de *errx.DomainError
	require.ErrorAs(t, err, &de)
	assert.Equal(t, "maintenance", de.Fields["pool"], "失败的池应是 maintenance")
}

// TestAcquire_RealRoleSeparation 验证 App / Maintenance / Admin 三 pool 用不同 role 连接。
func TestAcquire_RealRoleSeparation(t *testing.T) {
	h := pgharness.Start(t)

	pool, err := Open(context.Background(), Config{
		AppDSN:         h.AppDSN,
		MaintenanceDSN: h.MaintenanceDSN,
		AdminDSN:       h.AdminDSN,
	})
	require.NoError(t, err)
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cases := []struct {
		name string
		pool *pgxpool.Pool
		want string
	}{
		{"app", pool.App, "redmatrix_app"},
		{"maintenance", pool.Maintenance, "redmatrix_maintenance"},
		{"admin", pool.Admin, "postgres"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := currentUser(ctx, tt.pool)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// currentUser 跑 SELECT current_user 验证连接落到的真实 PG role。
func currentUser(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var u string
	if err := pool.QueryRow(ctx, "SELECT current_user").Scan(&u); err != nil {
		return "", err
	}
	return u, nil
}
