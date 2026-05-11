// Package safetarget 是 agent 真插件入参的统一校验（PR-S17-SAFE）。
//
// 背景：plugin.Run 收到 target/ports 等字符串后直接 exec.Command(bin, ..., target)。
// 即使用 argv（非 shell），target 仍是工具的命令行选项 — 恶意 PA 传
// "-iL=/etc/passwd" 让 nmap 读任意文件，"-h | sh" 不会触发 shell 但工具自身
// 可能解析。
//
// 防御：
//   - 调用 exec 前先 ValidateTarget：拒 "-" 起头、拒 shell metachars、按
//     target_kind 走对应格式（ip/cidr/host/url 各自 regex）
//   - argv 拼参时，target 放尾，并在它前面单独传 "--" end-of-options 哨兵
//     让 GNU getopt 风格的工具明确 "后面全是 positional"
package safetarget

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// shellMeta 任何 target / ports 都不可能合法含的字符集（防御深度，即使 exec.Command 用 argv 也不放）。
var shellMeta = regexp.MustCompile("[$`\\\\\\n\\r\\x00;&|<>(){}\\[\\]*?]")

// hostRe RFC 1123 hostname/domain（含 wildcard 子域不行；纯字母数字 hyphen + dot）。
var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// portsRe nmap-style 端口列表："22"、"80,443"、"1-1000"、"21,22,80-90"。
var portsRe = regexp.MustCompile(`^[0-9]+([,\-][0-9]+)*$`)

// ValidateTarget 按 targetKind 校 target；不通过返 error。
//
// 公共拦截（所有 kind 适用）：
//   - 空 / 长度 > 512 / 包含 shell metachar / 以 "-" 起头（防 argv 选项注入）
//
// 各 kind 进一步格式校验：
//   - host:  hostRe（RFC 1123 域名）
//   - ip:    net.ParseIP
//   - cidr:  net.ParseCIDR
//   - url:   url.Parse + scheme ∈ {http, https}
func ValidateTarget(target, targetKind string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("safetarget: empty target")
	}
	if len(target) > 512 {
		return fmt.Errorf("safetarget: target 超长 (>512)")
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("safetarget: target 不可以 - 起头（防 argv 选项注入）")
	}
	if shellMeta.MatchString(target) {
		return fmt.Errorf("safetarget: target 含非法字符（shell metachar）")
	}
	switch targetKind {
	case "host":
		if !hostRe.MatchString(target) {
			return fmt.Errorf("safetarget: host 格式不合法")
		}
	case "ip":
		if net.ParseIP(target) == nil {
			return fmt.Errorf("safetarget: ip 不合法")
		}
	case "cidr":
		if _, _, err := net.ParseCIDR(target); err != nil {
			return fmt.Errorf("safetarget: cidr 不合法: %w", err)
		}
	case "url":
		u, err := url.Parse(target)
		if err != nil {
			return fmt.Errorf("safetarget: url 解析失败: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("safetarget: url scheme 必须 http|https")
		}
		if u.Host == "" {
			return fmt.Errorf("safetarget: url 缺 host")
		}
	default:
		return fmt.Errorf("safetarget: 未知 target_kind=%q", targetKind)
	}
	return nil
}

// ValidatePorts 校 nmap -p 端口列表；空 → 用 caller 默认。
func ValidatePorts(ports string) error {
	ports = strings.TrimSpace(ports)
	if ports == "" {
		return nil
	}
	if len(ports) > 256 {
		return fmt.Errorf("safetarget: ports 超长")
	}
	if strings.HasPrefix(ports, "-") {
		return fmt.Errorf("safetarget: ports 不可以 - 起头")
	}
	if !portsRe.MatchString(ports) {
		return fmt.Errorf("safetarget: ports 格式不合法（仅 \\d / , / -）")
	}
	return nil
}
