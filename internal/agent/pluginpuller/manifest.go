// Package pluginpuller agent 端的插件拉取 + 安装（PR-S29）。
//
// 流程：
//  1. Run() 启动期一次 + Interval 周期循环
//  2. 每个 slug：调 GetLatestPluginVersion(slug, platform)
//  3. 与 local manifest 比对版本：相同 → 跳过；新 → 下载 + 校签 + 原子安装
//  4. 更新 manifest
//
// 本地布局：
//
//	plugin_dir/
//	  manifest.json     — 当前各 slug 已安装版本
//	  <slug>            — 二进制（chmod 0755）
//	  <slug>.tmp        — 下载中（写完后 rename 到 <slug>）
package pluginpuller

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ManifestFileName 本地版本表文件名。
const ManifestFileName = "manifest.json"

// ManifestEntry 单 slug 的安装记录。
type ManifestEntry struct {
	Slug         string    `json:"slug"`
	Version      string    `json:"version"`
	Platform     string    `json:"platform"`
	SHA256       string    `json:"sha256"`
	SigningKeyID string    `json:"signing_key_id"`
	InstalledAt  time.Time `json:"installed_at"`
}

// Manifest 多 slug 版本表，按 slug 索引。
type Manifest struct {
	Entries map[string]ManifestEntry `json:"entries"`

	dir string
	mu  sync.Mutex
}

// LoadManifest 加载 plugin_dir/manifest.json；不存在 → 空 Manifest。
func LoadManifest(dir string) (*Manifest, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("plugin_dir 不能为空")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("plugin_dir mkdir: %w", err)
	}
	m := &Manifest{Entries: map[string]ManifestEntry{}, dir: dir}
	path := filepath.Join(dir, ManifestFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return m, nil
		}
		return nil, fmt.Errorf("manifest read: %w", err)
	}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("manifest parse: %w", err)
	}
	if m.Entries == nil {
		m.Entries = map[string]ManifestEntry{}
	}
	m.dir = dir
	return m, nil
}

// Get 拿单 slug 当前版本；不存在 → ok=false。
func (m *Manifest) Get(slug string) (ManifestEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.Entries[slug]
	return e, ok
}

// Put 写入并落盘。
func (m *Manifest) Put(entry ManifestEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Entries[entry.Slug] = entry
	return m.saveLocked()
}

// Dir 返回 plugin_dir 路径。
func (m *Manifest) Dir() string {
	return m.dir
}

// BinaryPath 给定 slug 的二进制目标路径（plugin_dir/<slug>）。
func (m *Manifest) BinaryPath(slug string) string {
	return filepath.Join(m.dir, slug)
}

// TempPath 下载临时文件路径（plugin_dir/<slug>.tmp）。
func (m *Manifest) TempPath(slug string) string {
	return filepath.Join(m.dir, slug+".tmp")
}

// saveLocked 写 manifest.json（pretty-print）。caller 持锁。
func (m *Manifest) saveLocked() error {
	data, err := json.MarshalIndent(struct {
		Entries map[string]ManifestEntry `json:"entries"`
	}{Entries: m.Entries}, "", "  ")
	if err != nil {
		return fmt.Errorf("manifest marshal: %w", err)
	}
	// 原子写：先写 tmp 后 rename
	path := filepath.Join(m.dir, ManifestFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil { //nolint:gosec // manifest 仅本地，无敏感
		return fmt.Errorf("manifest write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("manifest rename: %w", err)
	}
	return nil
}
