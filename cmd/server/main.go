// Command redmatrix-server 是 RedMatrix 平台中心的入口。
//
// 完整启动流程见 docs/LLD/40-deployment-detail.md §2.5（启动期 fail-fast 校验顺序）
// 与 docs/LLD/04-config-schema.md §3.4（配置校验规则）。
//
// 当前为 scaffold 阶段：仅打印版本并退出，方便 CI/部署管线先行打通。
package main

import (
	"fmt"
	"os"

	"github.com/ffff5sec/RedMatrix/internal/version"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "redmatrix-server: %v\n", err)
		os.Exit(1)
	}
}

func run(_ []string, out *os.File) error {
	fmt.Fprintf(out, "redmatrix-server %s\n", version.String())
	// TODO(scaffold): 配置加载 / fail-fast 校验 / PG·ES·Redis·MinIO 连接 / RPC handler 注册 / 监听
	return nil
}
