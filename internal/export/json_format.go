package export

import (
	"encoding/json"
	"io"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// JSONFormat 标准 JSON 数组流式输出：开 `[`，逐行 `,obj`，关 `]`。
//
// 不用 NDJSON（行分隔 JSON）—— 浏览器下载场景下 JSON.parse 简单是用户优先级。
type JSONFormat struct {
	wroteFirst bool
}

// ContentType 实现 Format。
func (*JSONFormat) ContentType() string { return "application/json; charset=utf-8" }

// Extension 实现 Format。
func (*JSONFormat) Extension() string { return "json" }

// WriteHeader 写 `[`；JSON 无列头概念。
func (f *JSONFormat) WriteHeader(w io.Writer, _ []string) error {
	if _, err := io.WriteString(w, "[\n"); err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.json: write '['")
	}
	return nil
}

// WriteRow 写 obj；首行前不写逗号，之后每行前写 `,\n`。
func (f *JSONFormat) WriteRow(w io.Writer, cols []string, row Row) error {
	obj := make(map[string]string, len(cols))
	for i, c := range cols {
		if i >= len(row) {
			break
		}
		obj[c] = row[i]
	}
	if f.wroteFirst {
		if _, err := io.WriteString(w, ",\n"); err != nil {
			return errx.Wrap(errx.ErrInternal, err, "export.json: write delim")
		}
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.json: encode row")
	}
	f.wroteFirst = true
	return nil
}

// Close 写 `]`。
func (f *JSONFormat) Close(w io.Writer) error {
	if _, err := io.WriteString(w, "]\n"); err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.json: write ']'")
	}
	return nil
}
