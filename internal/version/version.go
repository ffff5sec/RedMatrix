// Package version 暴露构建期注入的版本元信息，供 cmd/server 与 cmd/node 共享。
//
// 编译时通过 `-ldflags "-X github.com/ffff5sec/RedMatrix/internal/version.Version=v1.0.0"`
// 注入；未注入时为占位字串。
package version

// 构建期 ldflags 注入；保持包级 var（const 不可被 -X 替换）。
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// String 返回单行可打印版本字串。
func String() string {
	return Version + " (commit " + Commit + ", built " + BuildDate + ")"
}
