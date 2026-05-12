package notify

// webhook.go —— Webhook channel adapter（PR-S25）。
//
// 行为：POST application/json 到 sub.Config.url。可选 HMAC-SHA256 签名走 X-RedMatrix-Signature header
// （key = sub.Config.secret）。响应 2xx 视为成功；其它一律失败。
//
// payload schema 走 Slack/飞书/钉钉 兼容的最小集（fallback "text" 字段），
// 让大多数 webhook 工具直接用；用户也可以走自家网关再转换。

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/notify/domain"
)

// WebhookAdapter 走 HTTP POST。
type WebhookAdapter struct {
	httpClient *http.Client
}

// NewWebhookAdapter 构造默认 10s 超时的 adapter。
func NewWebhookAdapter() *WebhookAdapter {
	return &WebhookAdapter{
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Channel 返 ChannelWebhook。
func (a *WebhookAdapter) Channel() domain.Channel { return domain.ChannelWebhook }

// Send POST sub.Config.url。
func (a *WebhookAdapter) Send(ctx context.Context, sub *domain.Subscription, d *domain.Delivery) error {
	url, _ := sub.Config["url"].(string)
	if strings.TrimSpace(url) == "" {
		return fmt.Errorf("webhook url 为空")
	}
	body, err := buildWebhookPayload(sub, d)
	if err != nil {
		return fmt.Errorf("build payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "RedMatrix-Notifier/1.0")

	if secret, _ := sub.Config["secret"].(string); secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-RedMatrix-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// buildWebhookPayload 把 delivery 组装成对 Slack/飞书/钉钉 都友好的 JSON。
//   - text: 一行摘要（Slack incoming-webhook 默认字段；飞书机器人 v1 接受）
//   - 同时把完整 event / payload 暴露给自定义解析（{ "event": {...} }）
func buildWebhookPayload(sub *domain.Subscription, d *domain.Delivery) ([]byte, error) {
	text := summarizeForChat(d)
	envelope := map[string]any{
		"text": text,
		"event": map[string]any{
			"kind":            string(d.EventKind),
			"topic":           d.EventTopic,
			"tenant_id":       d.TenantID,
			"subscription_id": sub.ID,
			"delivery_id":     d.ID,
			"payload":         d.Payload,
		},
	}
	return json.Marshal(envelope)
}

func summarizeForChat(d *domain.Delivery) string {
	switch d.EventKind {
	case domain.EventTaskCompleted:
		name, _ := d.Payload["task_name"].(string)
		return fmt.Sprintf("[RedMatrix] 任务完成：%s", strFallback(name, "<unnamed>"))
	case domain.EventTaskFailed:
		name, _ := d.Payload["task_name"].(string)
		reason, _ := d.Payload["reason"].(string)
		return fmt.Sprintf("[RedMatrix] 任务失败：%s（%s）",
			strFallback(name, "<unnamed>"), strFallback(reason, "no detail"))
	case domain.EventFindingHigh:
		sev, _ := d.Payload["severity"].(string)
		title, _ := d.Payload["title"].(string)
		host, _ := d.Payload["host"].(string)
		return fmt.Sprintf("[RedMatrix] 发现 %s 漏洞：%s @ %s",
			strFallback(sev, "high"), strFallback(title, "<no title>"), strFallback(host, "<no host>"))
	}
	if msg, ok := d.Payload["message"].(string); ok {
		return fmt.Sprintf("[RedMatrix] %s", msg)
	}
	return fmt.Sprintf("[RedMatrix] event=%s", d.EventKind)
}

func strFallback(s, fb string) string {
	if strings.TrimSpace(s) == "" {
		return fb
	}
	return s
}
