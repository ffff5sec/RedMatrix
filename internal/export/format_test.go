package export

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xuri/excelize/v2"
)

// TestCSVFormat_WritesBOMAndHeader_RowsEscapeQuotes：CSV 写 BOM、header、行；
// 含逗号 / 引号 / 换行的字段被正确 quote。
func TestCSVFormat_WritesBOMAndHeader_RowsEscapeQuotes(t *testing.T) {
	var buf bytes.Buffer
	f := CSVFormat{}
	cols := []string{"a", "b", "c"}
	require.NoError(t, f.WriteHeader(&buf, cols))
	require.NoError(t, f.WriteRow(&buf, cols, Row{"x", "y,z", `quote " in`}))
	require.NoError(t, f.WriteRow(&buf, cols, Row{"newline\nhere", "", "ok"}))
	require.NoError(t, f.Close(&buf))

	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "\xef\xbb\xbf"), "should start with UTF-8 BOM")
	body := strings.TrimPrefix(out, "\xef\xbb\xbf")
	// 首行 header
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	assert.Equal(t, "a,b,c", lines[0])
	// 含逗号 / 引号 被 quote
	assert.Contains(t, body, `"y,z"`)
	assert.Contains(t, body, `"quote "" in"`)
}

// TestJSONFormat_ProducesValidArrayWithRowObjects：JSON 输出可被 std json 解析。
func TestJSONFormat_ProducesValidArrayWithRowObjects(t *testing.T) {
	var buf bytes.Buffer
	f := &JSONFormat{}
	cols := []string{"a", "b"}
	require.NoError(t, f.WriteHeader(&buf, cols))
	require.NoError(t, f.WriteRow(&buf, cols, Row{"x", "1"}))
	require.NoError(t, f.WriteRow(&buf, cols, Row{"y", "2"}))
	require.NoError(t, f.Close(&buf))

	var parsed []map[string]string
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed), "output should be valid JSON")
	require.Len(t, parsed, 2)
	assert.Equal(t, "x", parsed[0]["a"])
	assert.Equal(t, "1", parsed[0]["b"])
	assert.Equal(t, "y", parsed[1]["a"])
	assert.Equal(t, "2", parsed[1]["b"])
}

// TestJSONFormat_EmptyArrayWhenNoRows：无行也应输出 `[]`。
func TestJSONFormat_EmptyArrayWhenNoRows(t *testing.T) {
	var buf bytes.Buffer
	f := &JSONFormat{}
	require.NoError(t, f.WriteHeader(&buf, []string{"a"}))
	require.NoError(t, f.Close(&buf))

	var parsed []map[string]string
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	assert.Empty(t, parsed)
}

// TestXLSXFormat_ProducesValidWorkbook：用 excelize 反向解析校验列 / 行。
func TestXLSXFormat_ProducesValidWorkbook(t *testing.T) {
	var buf bytes.Buffer
	f := &XLSXFormat{}
	cols := []string{"id", "name"}
	require.NoError(t, f.WriteHeader(&buf, cols))
	require.NoError(t, f.WriteRow(&buf, cols, Row{"1", "alpha"}))
	require.NoError(t, f.WriteRow(&buf, cols, Row{"2", "beta"}))
	require.NoError(t, f.Close(&buf))

	xf, err := excelize.OpenReader(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	defer xf.Close()
	rows, err := xf.GetRows("Sheet1")
	require.NoError(t, err)
	require.Len(t, rows, 3, "header + 2 data rows")
	assert.Equal(t, []string{"id", "name"}, rows[0])
	assert.Equal(t, []string{"1", "alpha"}, rows[1])
	assert.Equal(t, []string{"2", "beta"}, rows[2])
}
