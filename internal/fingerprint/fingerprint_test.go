package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// === NewLibrary 解析 + 边界 ===

func TestNewLibrary_HappyPath(t *testing.T) {
	y := []byte(`rules:
  - name: nginx
    fields: [webserver]
    keyword: nginx
  - name: WordPress
    fields: [body]
    keyword: wp-content
`)
	lib, err := NewLibrary(y)
	require.NoError(t, err)
	require.Len(t, lib.Rules(), 2)
}

func TestNewLibrary_InvalidYAML(t *testing.T) {
	_, err := NewLibrary([]byte("not: valid: yaml: : :"))
	require.Error(t, err)
}

func TestNewLibrary_SkipsEmptyNameOrKeyword(t *testing.T) {
	y := []byte(`rules:
  - name: ""
    keyword: x
  - name: ok
    keyword: ""
  - name: nginx
    keyword: nginx
`)
	lib, err := NewLibrary(y)
	require.NoError(t, err)
	require.Len(t, lib.Rules(), 1, "应只保留有效规则")
	assert.Equal(t, "nginx", lib.Rules()[0].Name)
}

func TestNewLibrary_SkipsDuplicateName(t *testing.T) {
	y := []byte(`rules:
  - name: nginx
    keyword: nginx
  - name: nginx
    keyword: tengine
`)
	lib, err := NewLibrary(y)
	require.NoError(t, err)
	require.Len(t, lib.Rules(), 1, "重复 name 应跳过")
}

// === Match ===

func TestMatch_KeywordInWebserver(t *testing.T) {
	lib, _ := NewLibrary([]byte(`rules:
  - name: nginx
    fields: [webserver]
    keyword: nginx
`))
	hits := lib.Match(map[string]any{"webserver": "nginx/1.20.1"})
	assert.Equal(t, []string{"nginx"}, hits)
}

func TestMatch_CaseInsensitiveByDefault(t *testing.T) {
	lib, _ := NewLibrary([]byte(`rules:
  - name: nginx
    fields: [webserver]
    keyword: NGINX
`))
	hits := lib.Match(map[string]any{"webserver": "nginx/1.20.1"})
	assert.Equal(t, []string{"nginx"}, hits)
}

func TestMatch_CaseSensitiveStrict(t *testing.T) {
	lib, _ := NewLibrary([]byte(`rules:
  - name: nginx
    fields: [webserver]
    keyword: NGINX
    case_sensitive: true
`))
	hits := lib.Match(map[string]any{"webserver": "nginx/1.20.1"})
	assert.Empty(t, hits, "case_sensitive=true 时大写 NGINX 不该命中小写 nginx")
}

func TestMatch_EmptyFieldsScansAllStrings(t *testing.T) {
	lib, _ := NewLibrary([]byte(`rules:
  - name: WordPress
    keyword: wp-content
`))
	hits := lib.Match(map[string]any{
		"body":  "<a href=\"/wp-content/themes/x.css\">",
		"title": "无关",
	})
	assert.Equal(t, []string{"WordPress"}, hits)
}

func TestMatch_FieldRestriction(t *testing.T) {
	lib, _ := NewLibrary([]byte(`rules:
  - name: WordPress
    fields: [body]
    keyword: wp-content
`))
	// 关键字在 title 不算命中（field 限定 body）
	hits := lib.Match(map[string]any{
		"title": "wp-content 测试页",
	})
	assert.Empty(t, hits)
}

func TestMatch_ArrayFieldElements(t *testing.T) {
	lib, _ := NewLibrary([]byte(`rules:
  - name: tomcat-tag
    fields: [tech]
    keyword: tomcat
`))
	hits := lib.Match(map[string]any{
		"tech": []any{"nginx", "Tomcat/9.0"},
	})
	assert.Equal(t, []string{"tomcat-tag"}, hits)
}

func TestMatch_NoData_NoHits(t *testing.T) {
	lib, _ := NewLibrary([]byte(`rules:
  - name: nginx
    keyword: nginx
`))
	assert.Nil(t, lib.Match(nil))
	assert.Nil(t, lib.Match(map[string]any{}))
}

func TestMatch_MultipleHitsDedupedAndSorted(t *testing.T) {
	lib, _ := NewLibrary([]byte(`rules:
  - name: WordPress
    keyword: wp-content
  - name: nginx
    keyword: nginx
  - name: 用友NC
    keyword: /nccloud/
`))
	hits := lib.Match(map[string]any{
		"webserver": "nginx/1.20",
		"body":      "wp-content /nccloud/ /nccloud/ wp-content",
	})
	// 全部命中 + 去重 + 字典序
	assert.Equal(t, []string{"WordPress", "nginx", "用友NC"}, hits)
}

// === 默认规则集 ===

func TestDefault_LoadsWithoutPanic(t *testing.T) {
	lib := Default()
	require.NotNil(t, lib)
	// 默认规则集 ≥ 30 条
	assert.GreaterOrEqual(t, len(lib.Rules()), 30,
		"默认规则集应 ≥ 30 条（覆盖国内常见 stack + 通用 Web）")
}

func TestDefault_HitsCommonStack(t *testing.T) {
	lib := Default()
	cases := []struct {
		name string
		data map[string]any
		want string
	}{
		{"nginx webserver", map[string]any{"webserver": "nginx/1.20"}, "nginx"},
		{"WordPress body", map[string]any{"body": "<link href='/wp-content/themes/foo'>"}, "WordPress"},
		{"致远OA path", map[string]any{"body": "<img src='/seeyon/USER-DATA/IMAGES/'>"}, "致远OA"},
		{"用友NC path", map[string]any{"body": "/nccloud/dist/index.html"}, "用友NC"},
		{"宝塔面板 title", map[string]any{"title": "宝塔Linux面板"}, "宝塔面板"},
		{"Jenkins title", map[string]any{"title": "Dashboard [Jenkins]"}, "Jenkins"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits := lib.Match(c.data)
			assert.Contains(t, hits, c.want, "data: %+v", c.data)
		})
	}
}
