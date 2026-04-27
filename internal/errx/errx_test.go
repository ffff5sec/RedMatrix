package errx

import (
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// === 构造与基本属性 ===

func TestNew(t *testing.T) {
	e := New(ErrAssetNotFound, "资产不存在")

	require.NotNil(t, e)
	assert.Equal(t, ErrAssetNotFound, e.Code)
	assert.Equal(t, "资产不存在", e.Message)
	assert.Nil(t, e.Cause)
	assert.Equal(t, connect.CodeNotFound, e.ConnectCode())
}

func TestWrap(t *testing.T) {
	cause := errors.New("pgx: no rows")
	e := Wrap(ErrDatabase, cause, "asset query failed")

	assert.Equal(t, ErrDatabase, e.Code)
	assert.Equal(t, "asset query failed", e.Message)
	assert.Same(t, cause, e.Cause)
	assert.Equal(t, connect.CodeInternal, e.ConnectCode())

	// errors.Is 应该能穿透到 cause
	assert.True(t, errors.Is(e, cause))
}

func TestWrapf(t *testing.T) {
	cause := errors.New("upstream timeout")
	e := Wrapf(ErrUpstreamTimeout, cause, "fetching %s for %d", "fofa", 42)

	assert.Equal(t, "fetching fofa for 42", e.Message)
	assert.True(t, errors.Is(e, cause))
}

func TestInternal(t *testing.T) {
	cause := errors.New("conn closed")
	e := Internal(ErrDatabase, cause)

	assert.Equal(t, ErrDatabase, e.Code)
	assert.Same(t, cause, e.Cause)
	assert.Equal(t, "", e.Message) // Internal 不强制 message
}

func TestErrorString(t *testing.T) {
	e := New(ErrAssetNotFound, "资产不存在")
	assert.Equal(t, "ASSET_NOT_FOUND: 资产不存在", e.Error())

	cause := errors.New("xxx")
	e2 := Wrap(ErrDatabase, cause, "boom")
	got := e2.Error()
	assert.True(t, strings.Contains(got, "DATABASE_ERROR"))
	assert.True(t, strings.Contains(got, "boom"))
	assert.True(t, strings.Contains(got, "cause: xxx"))
}

func TestErrorOnNil(t *testing.T) {
	var e *DomainError
	assert.Equal(t, "<nil>", e.Error())
	assert.Nil(t, e.Unwrap())
	assert.Equal(t, connect.CodeUnknown, e.ConnectCode())
}

// === WithFields ===

func TestWithFields(t *testing.T) {
	e := New(ErrAssetNotFound, "x").WithFields(
		"asset_id", "ast_xxx",
		"tenant_id", "t_yyy",
	)

	require.Len(t, e.Fields, 2)
	assert.Equal(t, "ast_xxx", e.Fields["asset_id"])
	assert.Equal(t, "t_yyy", e.Fields["tenant_id"])
}

func TestWithFieldsOddLength(t *testing.T) {
	// 奇数应自动补齐，不 panic
	e := New(ErrInternal, "x").WithFields("a", 1, "b")
	assert.Equal(t, 1, e.Fields["a"])
	assert.Equal(t, "<MISSING>", e.Fields["b"])
}

func TestWithFieldsNonStringKey(t *testing.T) {
	// 非字符串 key 应被跳过，不 panic
	e := New(ErrInternal, "x").WithFields(123, "v1", "ok", "v2")
	require.Len(t, e.Fields, 1)
	assert.Equal(t, "v2", e.Fields["ok"])
}

func TestWithFieldsChain(t *testing.T) {
	e := New(ErrInternal, "x").
		WithFields("a", 1).
		WithFields("b", 2)

	assert.Equal(t, 1, e.Fields["a"])
	assert.Equal(t, 2, e.Fields["b"])
}

func TestWithMessage(t *testing.T) {
	e := New(ErrInternal, "old").WithMessage("new")
	assert.Equal(t, "new", e.Message)
}

// === IsCode / GetCode ===

func TestIsCode(t *testing.T) {
	e := New(ErrAssetNotFound, "x")
	assert.True(t, IsCode(e, ErrAssetNotFound))
	assert.False(t, IsCode(e, ErrTaskNotFound))
	assert.False(t, IsCode(errors.New("plain"), ErrAssetNotFound))
	assert.False(t, IsCode(nil, ErrAssetNotFound))
}

func TestIsCodeThroughWrap(t *testing.T) {
	// fmt.Errorf("%w", ...) 包装后 IsCode 仍能识别
	inner := New(ErrAssetNotFound, "x")
	wrapped := errors.Join(errors.New("outer"), inner)
	assert.True(t, IsCode(wrapped, ErrAssetNotFound))
}

func TestGetCode(t *testing.T) {
	e := New(ErrTaskNotFound, "x")
	c, ok := GetCode(e)
	assert.True(t, ok)
	assert.Equal(t, ErrTaskNotFound, c)

	_, ok = GetCode(errors.New("plain"))
	assert.False(t, ok)

	_, ok = GetCode(nil)
	assert.False(t, ok)
}

// === Connect 互转 ===

func TestToConnectRoundtrip(t *testing.T) {
	original := New(ErrAssetNotFound, "资产不存在").
		WithFields("asset_id", "ast_xxx", "tenant_id", "t_yyy")

	cerr := ToConnect(original, "req_abc123")
	require.Error(t, cerr)

	var connectErr *connect.Error
	require.True(t, errors.As(cerr, &connectErr))
	assert.Equal(t, connect.CodeNotFound, connectErr.Code())
	assert.Equal(t, "资产不存在", connectErr.Message())

	// 提取回 DomainError
	extracted, ok := FromConnect(cerr)
	require.True(t, ok)
	assert.Equal(t, ErrAssetNotFound, extracted.Code)
	assert.Equal(t, "资产不存在", extracted.Message)
	assert.Equal(t, connect.CodeNotFound, extracted.ConnectCode())
	assert.Equal(t, "ast_xxx", extracted.Fields["asset_id"])
	assert.Equal(t, "t_yyy", extracted.Fields["tenant_id"])
}

func TestToConnectNilReturnsNil(t *testing.T) {
	assert.Nil(t, ToConnect(nil, ""))
}

func TestToConnectUnknownErrorIsWrapped(t *testing.T) {
	// 未知 error 必须兜底为 INTERNAL_ERROR；cause 不能泄漏给客户端。
	plain := errors.New("internal pgx connection error")
	cerr := ToConnect(plain, "req_x")
	require.Error(t, cerr)

	var connectErr *connect.Error
	require.True(t, errors.As(cerr, &connectErr))
	assert.Equal(t, connect.CodeInternal, connectErr.Code())
	// 不应包含原始 cause 字串
	assert.False(t, strings.Contains(connectErr.Message(), "pgx"),
		"connect message must not leak underlying cause: %q", connectErr.Message())

	extracted, ok := FromConnect(cerr)
	require.True(t, ok)
	assert.Equal(t, ErrInternal, extracted.Code)
}

func TestFromConnectNonConnectError(t *testing.T) {
	_, ok := FromConnect(errors.New("plain"))
	assert.False(t, ok)

	_, ok = FromConnect(nil)
	assert.False(t, ok)
}

func TestFromConnectWithoutErrorInfoDetail(t *testing.T) {
	cerr := connect.NewError(connect.CodeNotFound, errors.New("raw"))
	_, ok := FromConnect(cerr)
	assert.False(t, ok, "connect.Error without our ErrorInfo detail should miss")
}

// === 映射表完整性 ===

func TestEveryCodeHasConnectMapping(t *testing.T) {
	for _, c := range AllCodes {
		_, ok := codeToConnect[c]
		assert.True(t, ok, "Code %s missing in codeToConnect map", c)
	}
}

func TestNoOrphanInMappingTable(t *testing.T) {
	allSet := make(map[Code]struct{}, len(AllCodes))
	for _, c := range AllCodes {
		allSet[c] = struct{}{}
	}
	for c := range codeToConnect {
		_, ok := allSet[c]
		assert.True(t, ok, "Code %s in codeToConnect but not in AllCodes (codes.go drift)", c)
	}
}

func TestConnectCodeForUnknown(t *testing.T) {
	got := connectCodeFor(Code("BOGUS_CODE_DOES_NOT_EXIST"))
	assert.Equal(t, connect.CodeUnknown, got)
}

func TestAllCodesNonEmptyAndUnique(t *testing.T) {
	seen := make(map[Code]struct{}, len(AllCodes))
	for _, c := range AllCodes {
		assert.NotEmpty(t, string(c), "empty Code in AllCodes")
		_, dup := seen[c]
		assert.False(t, dup, "duplicate Code %s in AllCodes", c)
		seen[c] = struct{}{}
	}
}

// === 实际场景示例（与 LLD 00-conventions §2.3 / HLD §6 对齐） ===

func TestUsageExample_DBLookupFailure(t *testing.T) {
	// 模拟 repo 层把 pgx 错误包成 DomainError
	pgxErr := errors.New("no rows in result set")
	got := Internal(ErrDatabase, pgxErr).
		WithFields("op", "asset.get", "asset_id", "ast_xxx")

	assert.Equal(t, ErrDatabase, got.Code)
	assert.True(t, errors.Is(got, pgxErr))
	assert.Equal(t, "ast_xxx", got.Fields["asset_id"])
}

func TestUsageExample_NotFound(t *testing.T) {
	got := New(ErrAssetNotFound, "资产不存在").
		WithFields("asset_id", "ast_xxx")

	assert.True(t, IsCode(got, ErrAssetNotFound))
	assert.Equal(t, connect.CodeNotFound, got.ConnectCode())
}
