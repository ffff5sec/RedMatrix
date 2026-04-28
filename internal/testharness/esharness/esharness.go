//go:build integration

// Package esharness 提供 testcontainers 启 Elasticsearch 容器 helper，仅在
// `go test -tags=integration` 下编译。
//
// 容器配置：
//   - elasticsearch:8.x single-node
//   - xpack.security 关闭（与生产 MVP 一致，详见 40 §4.2）
//   - heap 512m（测试足够，避免 1G+ 容器拖慢 CI）
//   - 等待 _cluster/health 200 OK
package esharness

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const imageDefault = "docker.elastic.co/elasticsearch/elasticsearch:8.15.0"

// ES 是一个运行中的 ES 容器及其 URL。
type ES struct {
	Container testcontainers.Container
	URL       string // http://host:port
}

// Start 启动 ES 容器（关 security，单节点，512m heap）。
//
// 容器在 t.Cleanup 时关闭。startup 超时 2 分钟（ES 8.x 启动较慢）。
func Start(t *testing.T) *ES {
	t.Helper()

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        imageDefault,
		ExposedPorts: []string{"9200/tcp"},
		Env: map[string]string{
			"discovery.type":                   "single-node",
			"xpack.security.enabled":           "false",
			"xpack.security.enrollment.enabled": "false",
			"ES_JAVA_OPTS":                      "-Xms512m -Xmx512m",
			"cluster.routing.allocation.disk.threshold_enabled": "false",
		},
		WaitingFor: wait.ForHTTP("/_cluster/health").
			WithPort("9200/tcp").
			WithStartupTimeout(2 * time.Minute),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "ES 容器启动失败（确认 Docker daemon 在线 + 内存足够 ≥ 1GB）")

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("ES 容器 terminate 失败: %v", err)
		}
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "9200/tcp")
	require.NoError(t, err)

	return &ES{
		Container: container,
		URL:       fmt.Sprintf("http://%s:%s", host, port.Port()),
	}
}
