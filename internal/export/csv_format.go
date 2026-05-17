package export

import (
	"encoding/csv"
	"io"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// CSVFormat RFC 4180 + UTF-8 BOM（让 Excel 直开中文不乱码）。
type CSVFormat struct{}

// ContentType 实现 Format。
func (CSVFormat) ContentType() string { return "text/csv; charset=utf-8" }

// Extension 实现 Format。
func (CSVFormat) Extension() string { return "csv" }

// utf8BOM Excel for Windows 检测到 BOM 会按 UTF-8 解析。
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// WriteHeader 写 BOM + 列名。
func (CSVFormat) WriteHeader(w io.Writer, cols []string) error {
	if _, err := w.Write(utf8BOM); err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.csv: write BOM")
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(cols); err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.csv: write header")
	}
	cw.Flush()
	return cw.Error()
}

// WriteRow 写单行。
func (CSVFormat) WriteRow(w io.Writer, _ []string, row Row) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(row); err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.csv: write row")
	}
	cw.Flush()
	return cw.Error()
}

// Close CSV 无收尾。
func (CSVFormat) Close(_ io.Writer) error { return nil }
