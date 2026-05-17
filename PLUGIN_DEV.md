# RedMatrix 插件开发指南

RedMatrix 用**三层插件架构**把"任务 kind → 扫描结果"的执行细节解耦：

| 层 | 形态 | 例子 | 适用 |
|---|---|---|---|
| **L1 原生适配器** | Go 代码 + HTTP / SDK 调外部 API | crt.sh / FOFA / Hunter / Quake | API 类资产源 |
| **L2 二进制包装器** | Go 代码 fork-exec CLI 工具 | nmap / subfinder / httpx / nuclei / tlsx / rustscan / ksubdomain / amass / fingerprintx / gospider / wayback / katana | 业界 CLI 工具 |
| **L3 声明式 POC** | YAML 模板 + CEL 表达式 | 类 Nuclei template | CVE POC（**Phase 2**，当前用 L2 nuclei 顶替） |

每个插件实现 `plugin.Plugin` 接口：

```go
type Plugin interface {
    Kind() string                       // 服务的任务类型
    IsMock() bool                       // mock=true 走 sleep 节奏
    Run(ctx context.Context,
        target, targetKind string,
        settings map[string]any) ([]map[string]any, error)
}
```

任务 kind 当前枚举（`internal/scan/domain/task.go`）：`port_scan` / `web_crawl` / `subdomain` / `fingerprint` / `vuln_scan` / `tls_scan`。

---

## 目录

1. [写 L2 插件（最常见）](#1-写-l2-插件最常见)
2. [写 L1 插件（API 类）](#2-写-l1-插件api-类)
3. [Registry 注册与多源聚合](#3-registry-注册与多源聚合)
4. [安全要求](#4-安全要求)
5. [插件包 .rpkg 格式](#5-插件包-rpkg-格式)
6. [打包、签名、上传](#6-打包签名上传)
7. [测试规范](#7-测试规范)
8. [常见坑](#8-常见坑)

---

## 1. 写 L2 插件（最常见）

把业界 CLI 工具包成一个 Go 子包，agent 启动时 `LookPath` 找二进制，fork-exec 跑出 JSON / 文本 → 解析成 `[]map[string]any`。

### 1.1 文件骨架

`internal/agent/plugin/<name>/<name>.go`：

```go
package mytool

import (
    "context"
    "encoding/json"
    "os/exec"
    "strings"

    "github.com/ffff5sec/RedMatrix/internal/agent/plugin"
    "github.com/ffff5sec/RedMatrix/internal/agent/plugin/safetarget"
)

// binaryName 工具可执行文件名；可被测试覆盖。
var binaryName = "mytool"

// MaxResults 单任务结果上限；防止巨包 stream error。
var MaxResults = 500

type Plugin struct {
    bin string
}

// New：bin 不在 PATH 时返 ErrNotInstalled。
func New() (*Plugin, error) {
    bin, err := exec.LookPath(binaryName)
    if err != nil {
        return nil, plugin.ErrNotInstalled
    }
    return &Plugin{bin: bin}, nil
}

// Kind 服务的任务类型；与 scan_tasks.kind CHECK 一致。
func (*Plugin) Kind() string { return "subdomain" } // 改成你的 kind

// IsMock 真插件返 false；mock 子包返 true。
func (*Plugin) IsMock() bool { return false }

func (p *Plugin) Run(
    ctx context.Context,
    target, targetKind string,
    settings map[string]any,
) ([]map[string]any, error) {
    target = strings.TrimSpace(target)
    if err := safetarget.Validate(target, targetKind); err != nil {
        return nil, err
    }

    args := []string{"-d", target, "-silent", "-json"}
    cmd := exec.CommandContext(ctx, p.bin, args...)
    out, err := cmd.Output()
    if err != nil {
        return nil, plugin.WrapToolError("mytool", err)
    }

    return parseOutput(out)
}

func parseOutput(out []byte) ([]map[string]any, error) {
    rows := []map[string]any{}
    dec := json.NewDecoder(bytes.NewReader(out))
    for dec.More() {
        var item map[string]any
        if err := dec.Decode(&item); err != nil {
            continue // 单行解析失败跳过
        }
        rows = append(rows, item)
        if len(rows) >= MaxResults {
            break
        }
    }
    return rows, nil
}
```

### 1.2 关键约定

1. **`binaryName` 变量必须可被测试覆盖**（用 `var` 而非 const）。测试在 `_test.go` 里 `binaryName = "false"` 制造 `ErrNotInstalled` 路径。
2. **不存在的二进制不报错**：`New()` 返 `plugin.ErrNotInstalled`，cmd/node 自动回落 mock。这让 CI / dev 无需装真工具。
3. **`MaxResults` 必有上限**：防止某些工具（如 subfinder 跑 example.com 拿 22k+ 行）触发 server 端 stream 限制。
4. **`safetarget.Validate(target, targetKind)`**：所有插件必须先校验目标。目录 `internal/agent/plugin/safetarget/` 拦截 SSRF / 本机 metadata 端点（如 169.254.169.254）/ localhost。
5. **结果字段 schema-less**：返 `[]map[string]any`，按 task kind 约定字段（见下表）。但**核心字段必填**：

| task kind | 核心字段 | 示例 |
|---|---|---|
| `subdomain` | `name` | `{"name": "api.example.com", "source": "mytool"}` |
| `port_scan` | `host`, `port` | `{"host": "1.2.3.4", "port": 443, "service": "https"}` |
| `web_crawl` | `url` | `{"url": "https://x.example.com/login"}` |
| `fingerprint` | `target`, `tech` | `{"target": "https://x.com", "tech": ["nginx"]}` |
| `vuln_scan` | `info` (含 `severity`, `name`) | nuclei JSON 结构 |
| `tls_scan` | `host`, `port`, `not_after`, `sha256_fingerprint` | tlsx JSON |

字段不齐时上游 service.UpsertFromResults 派生 asset 时会静默跳过。

### 1.3 注册

`cmd/node/plugin_register.go`：

```go
import "github.com/ffff5sec/RedMatrix/internal/agent/plugin/mytool"

// 在合适的注册函数（如 buildSubdomainPlugin）的 case 表里加：
"mytool": func() (plugin.Plugin, error) { return mytool.New() },
```

支持 env 多选并跑：`SUBDOMAIN_PLUGIN=subfinder,amass,mytool` 三者结果合并去重（Registry 自动聚合，PR-S56）。

---

## 2. 写 L1 插件（API 类）

L1 = 不依赖外部 CLI，直接 HTTP / SDK 调远端 API。例如 `internal/agent/plugin/crtsh`：

```go
type Plugin struct {
    client *http.Client
}

func New() (*Plugin, error) {
    return &Plugin{client: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (*Plugin) Kind() string { return "subdomain" }
func (*Plugin) IsMock() bool { return false }

func (p *Plugin) Run(ctx context.Context, target, targetKind string, _ map[string]any) ([]map[string]any, error) {
    // GET https://crt.sh/?q=%25.example.com&output=json
    // parse → []map{"name": ...}
}
```

环境变量约定（带 API key 的）：

| 插件 | env |
|---|---|
| `fofa` | `FOFA_EMAIL`, `FOFA_KEY` |
| `hunter` | `HUNTER_KEY` |
| `quake` | `QUAKE_KEY` |

env 缺失时 `New()` 返 `ErrNotInstalled`（key 不可用 = 等价工具未装），caller 回落 mock。**绝不能 hardcode key**。

---

## 3. Registry 注册与多源聚合

`cmd/node/main.go` 启动时按 env 选哪些 plugin：

```bash
# 单选
SUBDOMAIN_PLUGIN=subfinder

# 多选自动 group 聚合
SUBDOMAIN_PLUGIN=subfinder,amass,crtsh,fofa
```

聚合行为（PR-S56 `group.go`）：

- 同 kind 多个 plugin 并发执行 → 结果合并去重（按字段 hash）
- 任一 plugin 失败不阻断其他，只把失败 log 出来
- 全部都是 mock 时 group 也标 mock（继承）

各 kind 的 env 变量名：

| kind | env |
|---|---|
| subdomain | `SUBDOMAIN_PLUGIN`（默认 `subfinder`） |
| port_scan | `PORT_SCAN_PLUGIN`（默认 `nmap`） |
| web_crawl | `WEB_CRAWL_PLUGIN`（默认 `gospider`） |
| fingerprint | `FINGERPRINT_PLUGIN`（默认 `httpx`） |
| vuln_scan | `VULN_SCAN_PLUGIN`（默认 `nuclei`） |
| tls_scan | `TLS_SCAN_PLUGIN`（默认 `tlsx`） |

未配 env = 用默认（单个）。

---

## 4. 安全要求

每个 plugin 必须遵守：

1. **`safetarget.Validate` 拦 SSRF**：调用前检 target 不是 169.254.169.254 / localhost / RFC 1918（默认拒，例外用 settings 显式开放）
2. **context 透传**：所有 fork-exec / HTTP 都用 `exec.CommandContext` / `http.NewRequestWithContext`，让 task cancel 能立即中止子进程
3. **结果数量上限**：`MaxResults` 防巨包；超过截断并 log warning
4. **超时**：要么 ctx 自带 timeout，要么 plugin 内 `http.Client.Timeout = 30*time.Second`
5. **不写本地文件**（默认）：必须写时用 `os.MkdirTemp("", "plugin-")` + defer cleanup；不接受 settings 里传任意路径
6. **不读环境变量**（除了文档化的 API key env）：避免 leakage

---

## 5. 插件包 .rpkg 格式

L2 / L3 plugin 通过 `.rpkg` 包分发到节点（SA 上传 → server 持久 MinIO → agent 拉取）。

### 5.1 文件结构

```
mytool-1.2.3-linux-amd64.rpkg     # zip 文件
├── manifest.yaml                 # 元数据
├── mytool                        # 可执行文件（chmod +x）
├── README.md                     # 用户文档（可选）
└── LICENSE                       # 许可证（可选）
```

### 5.2 manifest.yaml schema

```yaml
slug: mytool                      # 唯一 ID（小写 + 短横线）
name: My Tool                     # 显示名
version: 1.2.3                    # SemVer
platform: linux-amd64             # GOOS-GOARCH；windows / darwin 各自独立 .rpkg
description: |
  My Tool 是 ...

# 二进制入口（与 zip 里的文件名对齐）
entrypoint: mytool

# 服务的 task kind（与 plugin.go Kind() 对齐）
kinds:
  - subdomain

# 特权请求（all-or-nothing）；任一未批准插件整体不可分发
privileges:
  - network              # 出站网络访问
  # - filesystem-read   # 读宿主路径
  # - raw-socket        # 原始套接字（nmap SYN 扫需要）
```

特权枚举：`network` / `filesystem-read` / `filesystem-write` / `raw-socket` / `privileged-port`。SA 上传时一次性审批；之后所有版本继承不再问。

---

## 6. 打包、签名、上传

### 6.1 生成 ed25519 签名 key

```bash
# 一次性生成 keypair；私钥放 server 端 secret manager
openssl genpkey -algorithm Ed25519 -outform DER | base64 -w0
# → 这个 base64 设到 server 的 PLUGIN_SIGNING_KEY_BASE64 + 命名 PLUGIN_SIGNING_KEY_ID
```

### 6.2 打包

```bash
# 1. 准备目录
mkdir mytool-1.2.3-linux-amd64
cp manifest.yaml mytool README.md mytool-1.2.3-linux-amd64/

# 2. 计算 sha256
zip -r mytool-1.2.3-linux-amd64.rpkg mytool-1.2.3-linux-amd64/
sha256sum mytool-1.2.3-linux-amd64.rpkg
```

### 6.3 签名

SA 上传时 server 自动用 `PLUGIN_SIGNING_KEY_BASE64` 对 .rpkg 内容做 ed25519 签名；agent 拉取时校验签名 + 校验 sha256，任一不匹配拒绝安装。

不需要 plugin 开发者自己签 —— 上传走 SA 即视为可信。

### 6.4 上传（SA 路径）

UI → 「插件库」→ 「上传新插件」→ 选 .rpkg → 填特权审批 → 提交。

CLI（脚本化场景）：

```bash
curl -X POST https://redmatrix.example.com/redmatrix.pluginpkg.v1.PluginPackageService/UploadPackage \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/proto" \
  --data-binary @upload-request.pb
```

protobuf 入参 schema 见 `api/proto/redmatrix/pluginpkg/v1/pluginpkg.proto`。

### 6.5 节点拉取

Agent 启动后或收到「新版本可用」通知时主动拉：

```
GET /api/v1/pluginpkg/<slug>/latest?platform=linux-amd64
→ 200 + .rpkg bytes + X-Signature header
```

Agent 验签 → 解包 → 原子 `mv` 到 `REDMATRIX_PLUGIN_DIR/<slug>/<version>/`（同一 slug 多版本共存，按 SemVer DESC active 当前 default）。

---

## 7. 测试规范

每个 plugin 子包必须有 `<name>_test.go`，覆盖：

```go
// 1. 二进制不存在路径
func TestNew_NotInstalled_Stub(t *testing.T) {
    binaryName = "nonexistent-binary-xxx-123"
    defer func() { binaryName = "mytool" }()
    _, err := New()
    if !errors.Is(err, plugin.ErrNotInstalled) {
        t.Fatalf("want ErrNotInstalled, got %v", err)
    }
}

// 2. Kind + IsMock
func TestKindAndMockFlags(t *testing.T) {
    p := &Plugin{}
    assert.Equal(t, "subdomain", p.Kind())
    assert.False(t, p.IsMock())
}

// 3. 输出解析（导出 parseOutput 供测试调）
func TestParseOutput_Happy(t *testing.T) {
    sample := []byte(`{"name":"api.example.com"}` + "\n" + `{"name":"www.example.com"}`)
    rows, err := parseOutput(sample)
    require.NoError(t, err)
    assert.Len(t, rows, 2)
    assert.Equal(t, "api.example.com", rows[0]["name"])
}

// 4. 边界（MaxResults / 空输入 / 畸形 JSON 跳过）
func TestParseOutput_RespectsMaxResults(t *testing.T) {
    orig := MaxResults
    MaxResults = 2
    defer func() { MaxResults = orig }()
    sample := bytes.Repeat([]byte(`{"name":"a.com"}` + "\n"), 5)
    rows, _ := parseOutput(sample)
    assert.Len(t, rows, 2)
}
```

**绝不** depend on 真实 binary（`exec.LookPath("mytool")`）。CI 跑不起来 = 不让进。

---

## 8. 常见坑

| 坑 | 解 |
|---|---|
| 工具输出 ANSI 颜色 / 进度条污染解析 | 加 `-silent` / `--no-color` / 把 stdout 用 `bufio.Scanner` 行解析 + `strings.HasPrefix("\\u001b[")` 跳过 |
| `subfinder` 跑 `example.com` 输出 22k+ 行 → `ReportTaskResults` stream too large | `MaxResults` 截断（subdomain 500 / port_scan 5000 / vuln_scan 1000 等） |
| `nmap -sS` 需要 CAP_NET_RAW | docker 容器加 `cap_add: NET_RAW` 或退到 `-sT`（TCP connect） |
| 192.0.2.1 被识别为 hostname → safetarget 没过 | `net.ParseIP` 二次过滤；hostRe 单跑过 |
| `tlsx` 默认不打 SAN → 漏掉证书 → cert_expiring 漏报 | 用 `-san` / `-cn` 强制输出 |
| 私网 IP 扫被 `safetarget` 拒 | settings 里 `{"allow_private": true}` 显式打开，仅限 SA 配的 internal tenant |
| Plugin 写本地文件残留 | `t.TempDir()` + `defer os.RemoveAll`，永远不写 `/tmp/...` 固定路径 |
| Plugin 内部用 goroutine 没 ctx 退出 | 所有 goroutine 都 select case `<-ctx.Done()` 退出 |

---

## 附录 A：参考插件源码

| 插件 | 路径 | 学习点 |
|---|---|---|
| subfinder | `internal/agent/plugin/subfinder/` | 标准 L2 模板 |
| nmap | `internal/agent/plugin/nmap/` | greppable 输出解析 + settings 透传 |
| nuclei | `internal/agent/plugin/nuclei/` | severity 提取 + finding 自动入工单 |
| tlsx | `internal/agent/plugin/tlsx/` | 证书字段解析 + cert_expiring 事件源 |
| crtsh | `internal/agent/plugin/crtsh/` | L1 HTTP（无 API key） |
| fofa | `internal/agent/plugin/fofa/` | L1 + env API key + 分页 |
| hunter | `internal/agent/plugin/hunter/` | L1 + WAF 防护应对 |
| quake | `internal/agent/plugin/quake/` | L1 + 复杂 query DSL |

---

更多内部设计细节见 `docs/LLD/14-plugin-module.md`（仓内部文档）。
