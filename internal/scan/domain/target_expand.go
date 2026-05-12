package domain

// target_expand.go —— 目标自动展开（PR-S24）。
//
// 支持的输入形态：
//   - IPv4 CIDR：192.168.1.0/24 → 256 个 IP
//   - IPv4 区间：192.168.1.10-192.168.1.20 / 192.168.1.10-20（短形式：末段）
//   - IPv6 CIDR：仅允许 prefix ≥ 112（最多 65536 个），过大返错
//   - 其它：host / URL / 单 IP 原样透传
//
// 输出去重保序。所有错误归类为 ErrInvalidInput / ErrValidationFailed。

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// DefaultMaxExpansion 单次展开默认上限。
// 4096 可覆盖 IPv4 /20，在多数红队场景够用；过大易把 agent 拍死。
const DefaultMaxExpansion = 4096

// v6MinPrefix IPv6 CIDR 允许的最小前缀（=> 最多 2^(128-112) = 65536 地址）。
// 实际还会受 maxExpansion 钳制，这里只是粗筛，挡掉 /0 这种荒谬输入。
const v6MinPrefix = 112

// ExpandTargets 严格模式：展开后总数 > maxOut → ErrValidationFailed。
// 用于 CreateTask 批量路径 + RunSuite 提交路径。
//
// 任意单条输入解析错误 → 整体返错（不"尽力而为"，防止用户写错被静默丢一半目标）。
func ExpandTargets(raw []string, maxOut int) ([]string, error) {
	if maxOut <= 0 {
		maxOut = DefaultMaxExpansion
	}
	expanded, total, _, err := expandTargets(raw, maxOut)
	if err != nil {
		return nil, err
	}
	if total > maxOut {
		return nil, errx.New(errx.ErrValidationFailed,
			fmt.Sprintf("展开后目标数 %d 超过上限 %d（请缩小 CIDR/范围或拆批提交）", total, maxOut))
	}
	return expanded, nil
}

// PreviewExpandTargets 宽松模式：超过 maxOut 时截断到 maxOut，并报告 total。
// 用于 UI 预览 RPC。
//   - expanded：实际返回的 IP 列表（len ≤ maxOut）
//   - total：完整展开后的总数（即使被截断也是真实值）
//   - truncated：true ⇔ total > maxOut
//   - err：仅解析错误时非 nil（超限不视为错误）
func PreviewExpandTargets(raw []string, maxOut int) (expanded []string, total int, truncated bool, err error) {
	if maxOut <= 0 {
		maxOut = DefaultMaxExpansion
	}
	return expandTargets(raw, maxOut)
}

// expandTargets 核心实现：收集 ≤ maxOut 个目标；total 累加所有展开后的真实数量。
// 超限时不报错（由调用方决定如何处理：ExpandTargets 严格报错；PreviewExpandTargets 接受截断）。
func expandTargets(raw []string, maxOut int) ([]string, int, bool, error) {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	total := 0
	truncated := false

	emit := func(s string) {
		total++
		if _, dup := seen[s]; dup {
			return
		}
		if len(out) >= maxOut {
			truncated = true
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	for _, item := range raw {
		s := strings.TrimSpace(item)
		if s == "" {
			continue
		}

		// 1) CIDR
		if strings.Contains(s, "/") && !looksLikeURL(s) {
			if ips, count, perr := expandCIDR(s, maxOut); perr != nil {
				return nil, 0, false, perr
			} else if ips != nil {
				// emit 全部（受 maxOut 钳制于 emit 内部），total 用 count 累加准确值
				for _, ip := range ips {
					if _, dup := seen[ip]; !dup && len(out) < maxOut {
						seen[ip] = struct{}{}
						out = append(out, ip)
					}
				}
				total += count
				if count > len(ips) {
					truncated = true
				}
				continue
			}
		}

		// 2) IPv4 区间
		if start, end, ok := parseIPv4Range(s); ok {
			count := ipv4RangeCount(start, end)
			if count < 0 {
				return nil, 0, false, errx.New(errx.ErrInvalidInput,
					"IPv4 区间起止反向").WithFields("range", s)
			}
			emitted := 0
			for ip := start; emitted < count; ip, emitted = nextIPv4(ip), emitted+1 {
				if len(out) >= maxOut {
					break
				}
				str := ip.String()
				if _, dup := seen[str]; dup {
					continue
				}
				seen[str] = struct{}{}
				out = append(out, str)
			}
			total += count
			if count > emitted || total > maxOut {
				truncated = true
			}
			continue
		}

		// 3) 透传（host / URL / 单 IP）
		emit(s)
	}

	if total > maxOut {
		truncated = true
	}
	return out, total, truncated, nil
}

// expandCIDR 展开 CIDR。返回 (ips, totalCount, err)。
//   - ips 长度 ≤ maxOut；超过时只填前 maxOut 个，count 仍是完整 count
//   - 若 CIDR 数学上有效但单条 CIDR 的 count 本身 > maxOut，依旧返回前 maxOut 个 + count
//     由调用方决定是 PreviewExpandTargets 截断 还是 ExpandTargets 严格报错
//
// IPv4：包含 network/broadcast；不剔除（与 nmap 默认行为一致）。
// IPv6：prefix < 120 直接报错（防止用户误写 /64 等同 1.8e19 地址）。
func expandCIDR(s string, maxOut int) ([]string, int, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, 0, errx.New(errx.ErrInvalidInput,
			"CIDR 格式不合法").WithFields("input", s, "err", err.Error())
	}
	ones, bits := ipNet.Mask.Size()
	if bits == 0 {
		return nil, 0, errx.New(errx.ErrInvalidInput, "CIDR mask 不合法").WithFields("input", s)
	}

	if bits == 32 { //nolint:mnd // IPv4 mask 总位数固定 32
		count := 1 << (bits - ones)
		ips := make([]string, 0, min(count, maxOut))
		ip := ipNet.IP.Mask(ipNet.Mask).To4()
		if ip == nil {
			return nil, 0, errx.New(errx.ErrInvalidInput, "CIDR IP 转 IPv4 失败").WithFields("input", s)
		}
		cur := append(net.IP(nil), ip...)
		for i := 0; i < count; i++ {
			if len(ips) >= maxOut {
				break
			}
			ips = append(ips, cur.String())
			cur = nextIPv4(cur)
		}
		return ips, count, nil
	}

	// IPv6
	if ones < v6MinPrefix {
		return nil, 0, errx.New(errx.ErrValidationFailed,
			fmt.Sprintf("IPv6 CIDR 前缀过小（/%d）；仅支持 /%d 及以上以防爆炸展开", ones, v6MinPrefix))
	}
	hostBits := bits - ones
	if hostBits >= 31 { // 安全起见
		return nil, 0, errx.New(errx.ErrValidationFailed,
			fmt.Sprintf("IPv6 CIDR /%d 展开后超 2^31 地址，拒绝", ones))
	}
	count := 1 << hostBits
	ips := make([]string, 0, min(count, maxOut))
	cur := append(net.IP(nil), ipNet.IP.Mask(ipNet.Mask)...)
	for i := 0; i < count; i++ {
		if len(ips) >= maxOut {
			break
		}
		ips = append(ips, cur.String())
		cur = nextIP(cur)
	}
	return ips, count, nil
}

// parseIPv4Range 严格识别 "A.B.C.D-E.F.G.H" 或 "A.B.C.D-N" 形式。
// host 名（如 my-server.com）含 '-' 但首段不是 IP → 返回 ok=false 透传。
func parseIPv4Range(s string) (net.IP, net.IP, bool) {
	idx := strings.IndexByte(s, '-')
	if idx <= 0 {
		return nil, nil, false
	}
	left := strings.TrimSpace(s[:idx])
	right := strings.TrimSpace(s[idx+1:])
	start := net.ParseIP(left)
	if start == nil {
		return nil, nil, false
	}
	start = start.To4()
	if start == nil {
		return nil, nil, false
	}
	// 完整 IP
	if end := net.ParseIP(right); end != nil {
		if end4 := end.To4(); end4 != nil {
			return start, end4, true
		}
		return nil, nil, false
	}
	// 短形式：末段
	if n, err := strconv.Atoi(right); err == nil && n >= 0 && n < 256 { //nolint:mnd // 末段 octet 上限
		end := append(net.IP(nil), start...)
		end[3] = byte(n)
		return start, end, true
	}
	return nil, nil, false
}

// ipv4RangeCount 计算 [start, end] 闭区间长度。end < start → -1。
func ipv4RangeCount(start, end net.IP) int {
	a := ipv4ToUint32(start)
	b := ipv4ToUint32(end)
	if b < a {
		return -1
	}
	return int(b-a) + 1
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func nextIPv4(ip net.IP) net.IP {
	out := append(net.IP(nil), ip.To4()...)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

func nextIP(ip net.IP) net.IP {
	out := append(net.IP(nil), ip...)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// looksLikeURL 简单判定 "http://" / "https://"。CIDR "/" 与 URL "/" 区分用。
func looksLikeURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
