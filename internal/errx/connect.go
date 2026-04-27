package errx

import (
	"errors"
	"fmt"

	"connectrpc.com/connect"

	errorv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/error/v1"
)

// ToConnect 把 *DomainError（或链中含 *DomainError 的 error）转成 *connect.Error。
//   - 用 DomainError.Message 作为 user-facing 文本（绝不暴露 Cause）
//   - 把业务码 + request_id + 字段编入 redmatrix.error.v1.ErrorInfo 作为 Detail
//   - err 不是 DomainError 时，统一兜底为 ErrInternal（防止 cause 泄漏）
//
// 用法（Server interceptor）：
//
//	if err != nil {
//	    return nil, errx.ToConnect(err, requestID)
//	}
func ToConnect(err error, requestID string) error {
	if err == nil {
		return nil
	}

	var de *DomainError
	if !errors.As(err, &de) {
		// 未知错误不能直接 ToConnect，否则 cause 会回客户端。
		// 包装成统一的 INTERNAL_ERROR，原始 err 保留在 Cause 供日志层读取。
		de = Wrap(ErrInternal, err, "系统内部错误")
	}

	cerr := connect.NewError(de.connectCode, errors.New(de.Message))

	info := &errorv1.ErrorInfo{
		Code:      string(de.Code),
		Message:   de.Message,
		RequestId: requestID,
		Fields:    fieldsToString(de.Fields),
	}
	if detail, derr := connect.NewErrorDetail(info); derr == nil {
		cerr.AddDetail(detail)
	}
	return cerr
}

// FromConnect 从 *connect.Error 中提取我们的 ErrorInfo Detail，重建 *DomainError。
// 没有匹配的 Detail 时返回 (nil, false)；err 不是 connect.Error 时也返回 false。
func FromConnect(err error) (*DomainError, bool) {
	if err == nil {
		return nil, false
	}
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return nil, false
	}
	for _, d := range cerr.Details() {
		msg, derr := d.Value()
		if derr != nil {
			continue
		}
		info, ok := msg.(*errorv1.ErrorInfo)
		if !ok {
			continue
		}
		return &DomainError{
			Code:        Code(info.GetCode()),
			Message:     info.GetMessage(),
			Fields:      stringMapToAny(info.GetFields()),
			connectCode: cerr.Code(),
		}, true
	}
	return nil, false
}

// fieldsToString 把上下文字段序列化为 map[string]string（ErrorInfo.fields 的类型）。
// 任意类型走 fmt.Sprintf；nil 转空串。
func fieldsToString(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = stringify(v)
	}
	return out
}

func stringMapToAny(in map[string]string) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func stringify(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}
