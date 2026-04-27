// Command redmatrix-node 是扫描节点 Agent 的入口。
//
// 完整流程见 docs/LLD/13-scan-module.md §节点端 与 docs/LLD/40-deployment-detail.md §3。
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
		fmt.Fprintf(os.Stderr, "redmatrix-node: %v\n", err)
		os.Exit(1)
	}
}

func run(_ []string, out *os.File) error {
	fmt.Fprintf(out, "redmatrix-node %s\n", version.String())
	// TODO(scaffold): 加载注册令牌 / mTLS 证书 / 连接 NodeService :9090 + IngestService :9091 /
	// 启动断点续扫 (PebbleDB) / 接入插件下载 + 沙箱
	return nil
}
