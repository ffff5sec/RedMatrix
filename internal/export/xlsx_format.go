package export

import (
	"io"

	"github.com/xuri/excelize/v2"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// XLSXFormat 输出 Excel .xlsx（OOXML SpreadsheetML）。
//
// 用 excelize StreamWriter：行不全量驻内存，写完 Flush 后调 file.Write(w) 把
// 整个 zip 包送出去。Handler 不需要中途 Flush；XLSX 必须等所有行写完才能 finalize
// zip 结构。
type XLSXFormat struct {
	file   *excelize.File
	sw     *excelize.StreamWriter
	rowIdx int // 1-based
}

// ContentType 实现 Format。
func (*XLSXFormat) ContentType() string {
	return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
}

// Extension 实现 Format。
func (*XLSXFormat) Extension() string { return "xlsx" }

// WriteHeader 初始化 file + sheet1 stream writer + 写表头到 row 1。
func (x *XLSXFormat) WriteHeader(_ io.Writer, cols []string) error {
	f := excelize.NewFile()
	sw, err := f.NewStreamWriter("Sheet1")
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.xlsx: new stream writer")
	}
	x.file = f
	x.sw = sw
	x.rowIdx = 1
	cells := make([]any, len(cols))
	for i, c := range cols {
		cells[i] = c
	}
	cell, err := excelize.CoordinatesToCellName(1, x.rowIdx)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.xlsx: coords header")
	}
	if err := sw.SetRow(cell, cells); err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.xlsx: set header row")
	}
	return nil
}

// WriteRow 写一行；忽略 w（行数据先 buffer 在 excelize 内）。
func (x *XLSXFormat) WriteRow(_ io.Writer, _ []string, row Row) error {
	if x.sw == nil {
		return errx.New(errx.ErrInternal, "export.xlsx: WriteRow before WriteHeader")
	}
	x.rowIdx++
	cells := make([]any, len(row))
	for i, v := range row {
		cells[i] = v
	}
	cell, err := excelize.CoordinatesToCellName(1, x.rowIdx)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.xlsx: coords row")
	}
	if err := x.sw.SetRow(cell, cells); err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.xlsx: set row")
	}
	return nil
}

// Close flush stream writer + 把整个 file 写到 w（这一步才真正出字节）。
func (x *XLSXFormat) Close(w io.Writer) error {
	if x.sw != nil {
		if err := x.sw.Flush(); err != nil {
			return errx.Wrap(errx.ErrInternal, err, "export.xlsx: flush stream")
		}
	}
	if x.file == nil {
		return nil
	}
	defer x.file.Close()
	if err := x.file.Write(w); err != nil {
		return errx.Wrap(errx.ErrInternal, err, "export.xlsx: write file")
	}
	return nil
}
