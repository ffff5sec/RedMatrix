package notify

// email.go —— Email channel adapter（PR-S25）。
//
// 走标准库 net/smtp。SMTP 服务器 / 凭证从 SMTPConfig 注入（来自 server 启动时
// 读 env）。配置不全时 Send 立即报错 → delivery 视作失败一路重试到 dead。

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/notify/domain"
)

// SMTPConfig SMTP 连接配置。
type SMTPConfig struct {
	Host     string // smtp.example.com
	Port     int    // 25 / 465 / 587
	Username string
	Password string
	From     string
	UseTLS   bool // true → STARTTLS（587）；false → 明文（25）
}

// Configured 必填字段非空。
func (c SMTPConfig) Configured() bool {
	return strings.TrimSpace(c.Host) != "" && c.Port > 0 && strings.TrimSpace(c.From) != ""
}

// EmailAdapter SMTP-backed Channel。
type EmailAdapter struct {
	cfg SMTPConfig
}

// NewEmailAdapter 构造 adapter；cfg 不完整时 adapter 仍可注入，
// Send 时再报错（这样允许"先注入再补 env"的部署顺序）。
func NewEmailAdapter(cfg SMTPConfig) *EmailAdapter {
	return &EmailAdapter{cfg: cfg}
}

// Channel 返 ChannelEmail。
func (a *EmailAdapter) Channel() domain.Channel { return domain.ChannelEmail }

// Send 发送邮件到 sub.Config.to。
func (a *EmailAdapter) Send(ctx context.Context, sub *domain.Subscription, d *domain.Delivery) error {
	if !a.cfg.Configured() {
		return fmt.Errorf("SMTP 未配置；请设置 NOTIFY_SMTP_HOST / PORT / FROM")
	}

	toAny, _ := sub.Config["to"].([]any)
	if len(toAny) == 0 {
		return fmt.Errorf("subscription.to 为空")
	}
	to := make([]string, 0, len(toAny))
	for _, x := range toAny {
		if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
			to = append(to, strings.TrimSpace(s))
		}
	}
	if len(to) == 0 {
		return fmt.Errorf("subscription.to 全部为非字符串/空")
	}

	subject := summarizeForChat(d) // 复用 webhook 的 summary 作为邮件标题
	body := renderEmailBody(d)
	msg := buildRFC822Message(a.cfg.From, to, subject, body)

	addr := net.JoinHostPort(a.cfg.Host, fmt.Sprintf("%d", a.cfg.Port))

	// SMTP 客户端阻塞调用，无原生 ctx；起一个 goroutine + select 兼顾 ctx 超时。
	done := make(chan error, 1)
	go func() {
		done <- a.sendSMTP(addr, a.cfg.From, to, msg)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("smtp send timeout: %w", ctx.Err())
	case <-time.After(20 * time.Second): // 双保险
		return fmt.Errorf("smtp send hard timeout after 20s")
	}
}

func (a *EmailAdapter) sendSMTP(addr, from string, to []string, msg []byte) error {
	var auth smtp.Auth
	if a.cfg.Username != "" {
		auth = smtp.PlainAuth("", a.cfg.Username, a.cfg.Password, a.cfg.Host)
	}
	if a.cfg.UseTLS {
		// STARTTLS 模式：先明文连，再 STARTTLS 升级
		c, err := smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("smtp dial: %w", err)
		}
		defer c.Close()
		if err := c.StartTLS(&tls.Config{ServerName: a.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
		if auth != nil {
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
		if err := c.Mail(from); err != nil {
			return fmt.Errorf("smtp mail from: %w", err)
		}
		for _, t := range to {
			if err := c.Rcpt(t); err != nil {
				return fmt.Errorf("smtp rcpt %s: %w", t, err)
			}
		}
		w, err := c.Data()
		if err != nil {
			return fmt.Errorf("smtp data: %w", err)
		}
		if _, err := w.Write(msg); err != nil {
			return fmt.Errorf("smtp write: %w", err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("smtp data close: %w", err)
		}
		return c.Quit()
	}
	return smtp.SendMail(addr, auth, from, to, msg)
}

// renderEmailBody 简单纯文本正文。
func renderEmailBody(d *domain.Delivery) string {
	var b strings.Builder
	fmt.Fprintf(&b, "事件类型：%s\n", d.EventKind)
	fmt.Fprintf(&b, "Delivery ID：%s\n", d.ID)
	b.WriteString("\n--- payload ---\n")
	for k, v := range d.Payload {
		fmt.Fprintf(&b, "%s: %v\n", k, v)
	}
	b.WriteString("\n此邮件由 RedMatrix 通知系统自动发出，请勿直接回复。\n")
	return b.String()
}

func buildRFC822Message(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}
