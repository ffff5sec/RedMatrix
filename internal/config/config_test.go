package config

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// 三个 32 字节、互异的合法 base64 密钥（仅测试用，绝不入仓真实凭据）。
var (
	testEncKey    = base64.StdEncoding.EncodeToString(bytesOfLen(32, 0xA1))
	testHMACKey   = base64.StdEncoding.EncodeToString(bytesOfLen(32, 0xB2))
	testBackupKey = base64.StdEncoding.EncodeToString(bytesOfLen(32, 0xC3))
	testJWTSecret = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@" // 64 chars
)

func bytesOfLen(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

// validEnv 返回一份能通过 Load + Validate 的最小 env。
func validEnv() map[string]string {
	return map[string]string{
		"PG_DSN":                "postgres://redmatrix_app:pw@pg:5432/redmatrix?sslmode=require",
		"PG_DSN_MAINTENANCE":    "postgres://redmatrix_maintenance:pw@pg:5432/redmatrix?sslmode=require",
		"ES_URL":                "http://es:9200",
		"REDIS_URL":             "redis://:pw@redis:6379/0",
		"MINIO_ENDPOINT":        "minio:9000",
		"MINIO_PUBLIC_ENDPOINT": "minio.example.com:9000",
		"MINIO_ACCESS_KEY":      "AKIA",
		"MINIO_SECRET_KEY":      "secret",
		"PUBLIC_DOMAIN":         "redmatrix.example.com",
		"PUBLIC_GRPC_ADDR":      "grpc.example.com:9090",
		"PUBLIC_MINIO_ADDR":     "minio.example.com:9000",
		"JWT_SECRET":            testJWTSecret,
		"ENCRYPTION_KEY":        testEncKey,
		"AUDIT_HMAC_KEY":        testHMACKey,
		"BACKUP_KEY":            testBackupKey,
	}
}

// === Load ===

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(WithEnvSource(validEnv()))
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "prod", cfg.Env)
	assert.Equal(t, "info", cfg.Log.Level)
	assert.Equal(t, "json", cfg.Log.Format)
	assert.Equal(t, "admin", cfg.Bootstrap.Username)
	assert.Equal(t, "admin@example.com", cfg.Bootstrap.Email)
	assert.True(t, cfg.Dev.AutoMigrate)
	assert.False(t, cfg.Dev.DevMode)
	assert.False(t, cfg.Dev.LEStaging)

	// IngestAddr 自动从 GRPC 端口派生
	assert.Equal(t, "grpc.example.com:9091", cfg.Public.IngestAddr)
}

func TestLoadOverrides(t *testing.T) {
	env := validEnv()
	env["ENV"] = "staging"
	env["LOG_LEVEL"] = "debug"
	env["LOG_FORMAT"] = "text"
	env["PUBLIC_INGEST_ADDR"] = "ingest.example.com:9091"
	env["RM_AUTO_MIGRATE"] = "false"
	env["RM_DEV_MODE"] = "true"
	env["LE_STAGING"] = "true"

	cfg, err := Load(WithEnvSource(env))
	require.NoError(t, err)

	assert.Equal(t, "staging", cfg.Env)
	assert.Equal(t, "debug", cfg.Log.Level)
	assert.Equal(t, "text", cfg.Log.Format)
	assert.Equal(t, "ingest.example.com:9091", cfg.Public.IngestAddr)
	assert.False(t, cfg.Dev.AutoMigrate)
	assert.True(t, cfg.Dev.DevMode)
	assert.True(t, cfg.Dev.LEStaging)
}

func TestLoadCryptoBase64Decode(t *testing.T) {
	cfg, err := Load(WithEnvSource(validEnv()))
	require.NoError(t, err)
	assert.Len(t, cfg.Crypto.EncryptionKey, 32)
	assert.Len(t, cfg.Crypto.AuditHMACKey, 32)
	assert.Len(t, cfg.Crypto.BackupKey, 32)
}

func TestLoadInvalidBase64(t *testing.T) {
	env := validEnv()
	env["ENCRYPTION_KEY"] = "not-base64!!!@@@"

	_, err := Load(WithEnvSource(env))
	require.Error(t, err)
	assertCode(t, err, errx.ErrBootstrapCryptoInvalid)

	var de *errx.DomainError
	require.True(t, errors.As(err, &de))
	assert.Equal(t, "ENCRYPTION_KEY", de.Fields["var"])
}

func TestLoadAcceptsRawBase64(t *testing.T) {
	// raw (no padding) 也应该接受
	env := validEnv()
	env["ENCRYPTION_KEY"] = base64.RawStdEncoding.EncodeToString(bytesOfLen(32, 0xD4))

	cfg, err := Load(WithEnvSource(env))
	require.NoError(t, err)
	assert.Len(t, cfg.Crypto.EncryptionKey, 32)
}

// === Validate ===

func TestValidateGreenPath(t *testing.T) {
	cfg, err := Load(WithEnvSource(validEnv()))
	require.NoError(t, err)
	assert.NoError(t, cfg.Validate())
}

func TestValidateMissingRequired(t *testing.T) {
	tests := []struct {
		name   string
		unset  string
		expect errx.Code
	}{
		{"missing PG_DSN", "PG_DSN", errx.ErrBootstrapConfigInvalid},
		{"missing PG_DSN_MAINTENANCE", "PG_DSN_MAINTENANCE", errx.ErrBootstrapConfigInvalid},
		{"missing ES_URL", "ES_URL", errx.ErrBootstrapConfigInvalid},
		{"missing REDIS_URL", "REDIS_URL", errx.ErrBootstrapConfigInvalid},
		{"missing MINIO_ENDPOINT", "MINIO_ENDPOINT", errx.ErrBootstrapConfigInvalid},
		{"missing PUBLIC_DOMAIN", "PUBLIC_DOMAIN", errx.ErrBootstrapConfigInvalid},
		{"missing JWT_SECRET", "JWT_SECRET", errx.ErrBootstrapConfigInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnv()
			delete(env, tt.unset)

			cfg, err := Load(WithEnvSource(env))
			require.NoError(t, err) // Load 仅在 base64 解析失败时报错

			err = cfg.Validate()
			require.Error(t, err)
			assertCode(t, err, tt.expect)

			var de *errx.DomainError
			require.True(t, errors.As(err, &de))
			// 缺失的必须是 var=tt.unset 或 JWT_SECRET 长度不足（JWT_SECRET 为空时 length 为 0）
			if tt.unset != "JWT_SECRET" {
				assert.Equal(t, tt.unset, de.Fields["var"], "expected var=%s", tt.unset)
			}
		})
	}
}

func TestValidateJWTSecretTooShort(t *testing.T) {
	env := validEnv()
	env["JWT_SECRET"] = "short"

	cfg, err := Load(WithEnvSource(env))
	require.NoError(t, err)

	err = cfg.Validate()
	require.Error(t, err)
	assertCode(t, err, errx.ErrBootstrapCryptoInvalid)
}

func TestValidateKeyReuseForbidden(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"ENCRYPTION_KEY == AUDIT_HMAC_KEY",
			func(m map[string]string) { m["AUDIT_HMAC_KEY"] = m["ENCRYPTION_KEY"] }},
		{"ENCRYPTION_KEY == BACKUP_KEY",
			func(m map[string]string) { m["BACKUP_KEY"] = m["ENCRYPTION_KEY"] }},
		{"AUDIT_HMAC_KEY == BACKUP_KEY",
			func(m map[string]string) { m["BACKUP_KEY"] = m["AUDIT_HMAC_KEY"] }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnv()
			tt.mutate(env)

			cfg, err := Load(WithEnvSource(env))
			require.NoError(t, err)

			err = cfg.Validate()
			require.Error(t, err)
			assertCode(t, err, errx.ErrBootstrapKeyReuseForbidden)
		})
	}
}

func TestValidatePGDSNRejectsSslmodeDisable(t *testing.T) {
	env := validEnv()
	env["PG_DSN"] = "postgres://redmatrix_app:pw@pg:5432/redmatrix?sslmode=disable"

	cfg, err := Load(WithEnvSource(env))
	require.NoError(t, err)

	err = cfg.Validate()
	require.Error(t, err)
	assertCode(t, err, errx.ErrBootstrapConfigInvalid)

	var de *errx.DomainError
	require.True(t, errors.As(err, &de))
	assert.Equal(t, "PG_DSN", de.Fields["var"])
}

func TestValidatePGMaintenanceDSNRejectsWrongRole(t *testing.T) {
	env := validEnv()
	env["PG_DSN_MAINTENANCE"] = "postgres://redmatrix_app:pw@pg:5432/redmatrix?sslmode=require"

	cfg, err := Load(WithEnvSource(env))
	require.NoError(t, err)

	err = cfg.Validate()
	require.Error(t, err)
	assertCode(t, err, errx.ErrBootstrapConfigInvalid)

	var de *errx.DomainError
	require.True(t, errors.As(err, &de))
	assert.Equal(t, "redmatrix_maintenance", de.Fields["expected"])
	assert.Equal(t, "redmatrix_app", de.Fields["got"])
}

func TestValidateLogLevel(t *testing.T) {
	env := validEnv()
	env["LOG_LEVEL"] = "verbose"

	cfg, err := Load(WithEnvSource(env))
	require.NoError(t, err)

	err = cfg.Validate()
	require.Error(t, err)
	assertCode(t, err, errx.ErrBootstrapConfigInvalid)
}

func TestValidateLogFormat(t *testing.T) {
	env := validEnv()
	env["LOG_FORMAT"] = "yaml"

	cfg, err := Load(WithEnvSource(env))
	require.NoError(t, err)

	err = cfg.Validate()
	require.Error(t, err)
	assertCode(t, err, errx.ErrBootstrapConfigInvalid)
}

func TestValidateNilConfig(t *testing.T) {
	var cfg *Config
	err := cfg.Validate()
	require.Error(t, err)
	assertCode(t, err, errx.ErrBootstrapConfigInvalid)
}

func TestValidateAdminDSNAlsoChecked(t *testing.T) {
	env := validEnv()
	env["PG_DSN_ADMIN"] = "postgres://redmatrix_admin:pw@pg:5432/redmatrix?sslmode=disable"

	cfg, err := Load(WithEnvSource(env))
	require.NoError(t, err)

	err = cfg.Validate()
	require.Error(t, err)
	assertCode(t, err, errx.ErrBootstrapConfigInvalid)

	var de *errx.DomainError
	require.True(t, errors.As(err, &de))
	assert.Equal(t, "PG_DSN_ADMIN", de.Fields["var"])
}

// === helpers ===

func assertCode(t *testing.T, err error, want errx.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", want)
	}
	got, ok := errx.GetCode(err)
	if !ok {
		t.Fatalf("expected *errx.DomainError, got %T: %v", err, err)
	}
	if got != want {
		t.Fatalf("expected code %s, got %s (err=%v)", want, got, err)
	}
}
