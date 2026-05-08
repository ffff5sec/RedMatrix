// Package store 是 Agent 的 enrollment 持久层。
//
// 落盘文件（位于 dataDir 下，文件全部 0600 / 目录 0700）：
//
//	node-id        UTF-8；Redeem 返回的 node UUID
//	node-cert.pem  client cert（CN = node-id）
//	node-key.pem   client cert 私钥；只此一份，泄露需 Revoke + 重 enroll
//	ca-cert.pem    server 根 CA；mTLS 校验 server cert 用
//
// Load 用于 Agent 重启时读已 enroll 状态；任何文件缺 → ErrNotEnrolled，
// 由 caller 决定走 enroll 路径或退出。
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotEnrolled 是 Load 读不到完整 4 件套时的哨兵错。
var ErrNotEnrolled = errors.New("agent store: 未 enroll；node-id / cert / key / ca 缺失")

// 文件名常量（Load/Save 共用）。
const (
	fileNodeID  = "node-id"
	fileCert    = "node-cert.pem"
	fileKey     = "node-key.pem"
	fileCACert  = "ca-cert.pem"
	dirMode     = 0o700
	fileModePEM = 0o600
)

// Enrollment 是 Agent 持久化的全部身份信息（key 不入服务端，仅本地存）。
type Enrollment struct {
	NodeID    string
	CertPEM   []byte
	KeyPEM    []byte
	CACertPEM []byte
}

// Store 是磁盘 backed enrollment 持久层；DataDir 不存在时 Save 自动创建。
type Store struct {
	DataDir string
}

// New 构造 Store；dataDir 为空 → ErrInvalidArg。
func New(dataDir string) (*Store, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil, errors.New("agent store: dataDir 不能为空")
	}
	return &Store{DataDir: dataDir}, nil
}

// Load 读全部 4 件套；任意一份缺 / 空 → ErrNotEnrolled。
func (s *Store) Load() (*Enrollment, error) {
	if s == nil {
		return nil, errors.New("agent store: nil receiver")
	}
	files := map[string]string{
		fileNodeID: filepath.Join(s.DataDir, fileNodeID),
		fileCert:   filepath.Join(s.DataDir, fileCert),
		fileKey:    filepath.Join(s.DataDir, fileKey),
		fileCACert: filepath.Join(s.DataDir, fileCACert),
	}
	contents := make(map[string][]byte, len(files))
	for name, path := range files {
		b, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil, ErrNotEnrolled
		case err != nil:
			return nil, fmt.Errorf("agent store: 读 %s: %w", name, err)
		case len(b) == 0:
			return nil, ErrNotEnrolled
		}
		contents[name] = b
	}
	return &Enrollment{
		NodeID:    strings.TrimSpace(string(contents[fileNodeID])),
		CertPEM:   contents[fileCert],
		KeyPEM:    contents[fileKey],
		CACertPEM: contents[fileCACert],
	}, nil
}

// Save 把 enrollment 全量持久化（4 文件原子-ish：每个用 .tmp + rename）。
func (s *Store) Save(e *Enrollment) error {
	if s == nil {
		return errors.New("agent store: nil receiver")
	}
	if e == nil {
		return errors.New("agent store: enrollment is nil")
	}
	if strings.TrimSpace(e.NodeID) == "" {
		return errors.New("agent store: node_id 不能为空")
	}
	if len(e.CertPEM) == 0 || len(e.KeyPEM) == 0 || len(e.CACertPEM) == 0 {
		return errors.New("agent store: cert / key / ca 不能为空")
	}
	if err := os.MkdirAll(s.DataDir, dirMode); err != nil {
		return fmt.Errorf("agent store: 创建 dataDir: %w", err)
	}
	pairs := []struct {
		name string
		data []byte
	}{
		{fileNodeID, []byte(e.NodeID + "\n")},
		{fileCert, e.CertPEM},
		{fileKey, e.KeyPEM},
		{fileCACert, e.CACertPEM},
	}
	for _, p := range pairs {
		if err := atomicWrite(filepath.Join(s.DataDir, p.name), p.data); err != nil {
			return fmt.Errorf("agent store: 写 %s: %w", p.name, err)
		}
	}
	return nil
}

// atomicWrite 写 .tmp 同目录 + rename，避免半状态。
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, fileModePEM); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
