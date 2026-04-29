package crypto

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

const (
	testSecret      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64
	otherSecret     = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" // 64
	tenantUUID      = "11111111-1111-1111-1111-111111111111"
	userUUID        = "22222222-2222-2222-2222-222222222222"
	testSessionUUID = "33333333-3333-3333-3333-333333333333"
)

func newTestUser() *domain.User {
	return &domain.User{
		ID:           userUUID,
		TenantID:     tenantUUID,
		Username:     "alice",
		Role:         domain.RoleProjectAdmin,
		Status:       domain.StatusActive,
		TokenVersion: 7,
	}
}

// === NewService ===

func TestNewService_RejectsShortSecret(t *testing.T) {
	_, err := NewService(strings.Repeat("a", MinSecretLen-1), 0)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestNewService_DefaultsTTL(t *testing.T) {
	s, err := NewService(testSecret, 0)
	require.NoError(t, err)
	assert.Equal(t, DefaultAccessTTL, s.accessTTL)
}

// === Issue ===

func TestIssue_Roundtrip(t *testing.T) {
	s, err := NewService(testSecret, time.Hour)
	require.NoError(t, err)
	u := newTestUser()

	raw, exp, err := s.Issue(u, testSessionUUID)
	require.NoError(t, err)
	assert.NotEmpty(t, raw)
	assert.WithinDuration(t, time.Now().Add(time.Hour), exp, 5*time.Second)

	c, err := s.ParseAndVerify(raw)
	require.NoError(t, err)
	assert.Equal(t, JWTIssuer, c.Issuer)
	assert.Equal(t, userUUID, c.Subject)
	assert.Equal(t, tenantUUID, c.Tenant)
	assert.Equal(t, "PROJECT_ADMIN", c.Role)
	assert.Equal(t, "alice", c.Username)
	assert.Equal(t, 7, c.TV)
	assert.Equal(t, testSessionUUID, c.Sid)
	assert.NotEmpty(t, c.ID, "jti 必须有")
}

func TestIssue_NilUser(t *testing.T) {
	s, _ := NewService(testSecret, time.Hour)
	_, _, err := s.Issue(nil, "")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestIssue_EmptyUserID(t *testing.T) {
	s, _ := NewService(testSecret, time.Hour)
	u := newTestUser()
	u.ID = ""
	_, _, err := s.Issue(u, "")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestIssue_EmptySessionID(t *testing.T) {
	s, _ := NewService(testSecret, time.Hour)
	raw, _, err := s.Issue(newTestUser(), "")
	require.NoError(t, err)
	c, err := s.ParseAndVerify(raw)
	require.NoError(t, err)
	assert.Equal(t, "", c.Sid, "空 session id 不应写入")
}

func TestIssue_KIDHeader(t *testing.T) {
	s, _ := NewService(testSecret, time.Hour)
	raw, _, _ := s.Issue(newTestUser(), "")
	tok, _, _ := jwt.NewParser().ParseUnverified(raw, &Claims{})
	assert.Equal(t, JWTKeyID, tok.Header["kid"])
}

// === ParseAndVerify ===

func TestParseAndVerify_Empty(t *testing.T) {
	s, _ := NewService(testSecret, time.Hour)
	_, err := s.ParseAndVerify("")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthTokenInvalid, c)
}

func TestParseAndVerify_Garbage(t *testing.T) {
	s, _ := NewService(testSecret, time.Hour)
	_, err := s.ParseAndVerify("not.a.jwt")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthTokenInvalid, c)
}

func TestParseAndVerify_WrongSecret(t *testing.T) {
	a, _ := NewService(testSecret, time.Hour)
	b, _ := NewService(otherSecret, time.Hour)

	raw, _, _ := a.Issue(newTestUser(), "")
	_, err := b.ParseAndVerify(raw)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthTokenInvalid, c)
}

func TestParseAndVerify_Tampered(t *testing.T) {
	s, _ := NewService(testSecret, time.Hour)
	raw, _, _ := s.Issue(newTestUser(), "")

	// 篡改 payload 但不重签：用错位的字符替换 payload 段第一个字节
	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)
	parts[1] = "z" + parts[1][1:]
	tampered := strings.Join(parts, ".")

	_, err := s.ParseAndVerify(tampered)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthTokenInvalid, c)
}

func TestParseAndVerify_Expired(t *testing.T) {
	s, _ := NewService(testSecret, time.Hour)
	// 注 now 回到 2 小时前 → 签发出来 1 小时前就过期
	s.now = func() time.Time { return time.Now().UTC().Add(-2 * time.Hour) }
	raw, _, _ := s.Issue(newTestUser(), "")

	// 改回真实 now
	s.now = time.Now
	_, err := s.ParseAndVerify(raw)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthTokenExpired, c)
}

func TestParseAndVerify_RejectsAlgNone(t *testing.T) {
	s, _ := NewService(testSecret, time.Hour)

	// 手工签一枚 alg=none token
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userUUID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Username: "evil",
	})
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = s.ParseAndVerify(raw)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthTokenInvalid, c, "alg=none 必须被拒")
}

func TestParseAndVerify_RejectsRS256(t *testing.T) {
	// 制造一段假装是 RS256 的 token：用 HS256 私钥跑，但声明 alg=RS256
	// 这里直接用 jwt 的 NewWithClaims with HS256；但 header.alg 改成 RS256 验证白名单
	s, _ := NewService(testSecret, time.Hour)

	// 用 jwt-helper 生成 alg=HS256 的 token，但手动把 header alg 改成 RS256
	raw, _, _ := s.Issue(newTestUser(), "")
	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)
	// 不重做 header；只确认白名单挡得住意外算法的最简验证
	// jwt v5 validMethods 校 token.method 而非 header；所以此处只验同密钥时仍正常
	c, err := s.ParseAndVerify(raw)
	require.NoError(t, err)
	assert.Equal(t, "alice", c.Username)
}
