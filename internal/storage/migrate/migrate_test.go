package migrate

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 单元测试聚焦：embed FS 结构 / 命名规范 / goose 标记。
// 真实迁移 Up 流程的集成测试（要 PG）放在 *_integration_test.go（build tag 控制），
// 与 testcontainers-go 一起在后续 PR 引入。

// === 命名规范（00-conventions §5.3）===

func TestEmbedFSContainsMigrations(t *testing.T) {
	entries, err := fs.ReadDir(sqlFS, sqlDir)
	require.NoError(t, err)

	var sqlFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			sqlFiles = append(sqlFiles, e.Name())
		}
	}
	assert.NotEmpty(t, sqlFiles, "no .sql migrations embedded")
}

func TestMigrationFilenamePattern(t *testing.T) {
	// 规范：{YYYYMMDDHHMMSS}_{snake_action}.sql
	pattern := regexp.MustCompile(`^\d{14}_[a-z][a-z0-9_]*\.sql$`)

	entries, err := fs.ReadDir(sqlFS, sqlDir)
	require.NoError(t, err)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		assert.Truef(t, pattern.MatchString(e.Name()),
			"file %q violates {YYYYMMDDHHMMSS}_{snake}.sql convention", e.Name())
	}
}

func TestMigrationsAreOrdered(t *testing.T) {
	// 文件名按字典序应该等价于按时间序（goose 默认按 timestamp）。
	entries, err := fs.ReadDir(sqlFS, sqlDir)
	require.NoError(t, err)

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}

	for i := 1; i < len(names); i++ {
		assert.Lessf(t, names[i-1], names[i],
			"migration order broken: %s should precede %s", names[i-1], names[i])
	}
}

// === Goose 标记完整性 ===

func TestEachMigrationHasUpAndDownMarkers(t *testing.T) {
	entries, err := fs.ReadDir(sqlFS, sqlDir)
	require.NoError(t, err)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			body, err := fs.ReadFile(sqlFS, sqlDir+"/"+e.Name())
			require.NoError(t, err)

			content := string(body)
			assert.Contains(t, content, "-- +goose Up",
				"%s missing -- +goose Up marker", e.Name())
			assert.Contains(t, content, "-- +goose Down",
				"%s missing -- +goose Down marker", e.Name())

			// Up 必须出现在 Down 前
			upIdx := strings.Index(content, "-- +goose Up")
			downIdx := strings.Index(content, "-- +goose Down")
			assert.Less(t, upIdx, downIdx,
				"%s: -- +goose Up must appear before -- +goose Down", e.Name())
		})
	}
}

func TestStatementBeginEndPaired(t *testing.T) {
	// 含 DO 块的迁移必须配对 +goose StatementBegin / StatementEnd。
	entries, err := fs.ReadDir(sqlFS, sqlDir)
	require.NoError(t, err)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(sqlFS, sqlDir+"/"+e.Name())
		require.NoError(t, err)

		content := string(body)
		begins := strings.Count(content, "-- +goose StatementBegin")
		ends := strings.Count(content, "-- +goose StatementEnd")
		assert.Equalf(t, begins, ends,
			"%s: StatementBegin (%d) / StatementEnd (%d) mismatched", e.Name(), begins, ends)
	}
}

// === 内容存在性（防止迁移文件被误删 / 截断）===

func TestRolesMigrationCreatesAllThreeRoles(t *testing.T) {
	body, err := fs.ReadFile(sqlFS, sqlDir+"/20260428000001_create_roles.sql")
	require.NoError(t, err)

	content := string(body)
	for _, role := range []string{"redmatrix_app", "redmatrix_maintenance"} {
		assert.Containsf(t, content, role, "role %s must be referenced", role)
	}
	// admin 由 docker entrypoint 创建，不在本迁移；但应在文档注释中提及。
	assert.Contains(t, content, "redmatrix_admin")
}

func TestExtensionsMigrationInstallsRequired(t *testing.T) {
	body, err := fs.ReadFile(sqlFS, sqlDir+"/20260428000002_install_extensions.sql")
	require.NoError(t, err)

	content := string(body)
	for _, ext := range []string{"pgcrypto", "pg_trgm", "pg_stat_statements"} {
		assert.Containsf(t, content, ext, "extension %s must be installed", ext)
	}
}

// === 程序化 setup ===

func TestSetupConfiguresDialect(t *testing.T) {
	// setup() 是幂等的；多次调用不应 panic / err
	require.NoError(t, setup())
	require.NoError(t, setup())
}

func TestFSExposed(t *testing.T) {
	got := FS()
	entries, err := fs.ReadDir(got, sqlDir)
	require.NoError(t, err)
	assert.NotEmpty(t, entries)
}
