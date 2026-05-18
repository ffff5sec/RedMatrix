package fingerprint

import (
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// CustomRule 用户自定义指纹规则（PR-S74）。
//
// 与内嵌 Rule 同语义，加 tenant 隔离 + 软删 + 元数据。
type CustomRule struct {
	ID            string
	TenantID      string
	Name          string
	Fields        []string
	Keyword       string
	CaseSensitive bool
	Enabled       bool
	Description   string
	CreatedBy     *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     *time.Time
}

// ToRule 把 CustomRule 转成 match 用的 Rule。
func (c *CustomRule) ToRule() *Rule {
	if c == nil {
		return nil
	}
	return &Rule{
		Name:          c.Name,
		Fields:        c.Fields,
		Keyword:       c.Keyword,
		CaseSensitive: c.CaseSensitive,
		Source:        "custom",
	}
}

// ValidateForCreate INSERT 前校验。
func (c *CustomRule) ValidateForCreate() error {
	if c == nil {
		return errx.New(errx.ErrInvalidInput, "fingerprint rule 不能为 nil")
	}
	if strings.TrimSpace(c.TenantID) == "" {
		return errx.New(errx.ErrInvalidInput, "fingerprint rule.tenant_id 不能为空")
	}
	if strings.TrimSpace(c.Name) == "" {
		return errx.New(errx.ErrInvalidInput, "fingerprint rule.name 不能为空")
	}
	if len(c.Name) > 128 {
		return errx.New(errx.ErrInvalidInput, "fingerprint rule.name 长度不能超 128").
			WithFields("got", len(c.Name))
	}
	if strings.TrimSpace(c.Keyword) == "" {
		return errx.New(errx.ErrInvalidInput, "fingerprint rule.keyword 不能为空")
	}
	if len(c.Keyword) > 512 {
		return errx.New(errx.ErrInvalidInput, "fingerprint rule.keyword 长度不能超 512").
			WithFields("got", len(c.Keyword))
	}
	for _, f := range c.Fields {
		if strings.TrimSpace(f) == "" {
			return errx.New(errx.ErrInvalidInput, "fingerprint rule.fields 元素不能空字符串")
		}
	}
	return nil
}
