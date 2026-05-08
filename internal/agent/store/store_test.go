package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sample() *Enrollment {
	return &Enrollment{
		NodeID:    "00000000-0000-0000-0000-000000000aaa",
		CertPEM:   []byte("CERT"),
		KeyPEM:    []byte("KEY"),
		CACertPEM: []byte("CA"),
	}
}

func TestNew_EmptyDataDir(t *testing.T) {
	_, err := New("")
	require.Error(t, err)
}

func TestSaveLoad_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	require.NoError(t, err)

	require.NoError(t, s.Save(sample()))

	got, err := s.Load()
	require.NoError(t, err)
	assert.Equal(t, sample().NodeID, got.NodeID)
	assert.Equal(t, []byte("CERT"), got.CertPEM)
	assert.Equal(t, []byte("KEY"), got.KeyPEM)
	assert.Equal(t, []byte("CA"), got.CACertPEM)
}

func TestSave_FileModes(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	require.NoError(t, s.Save(sample()))

	for _, name := range []string{"node-cert.pem", "node-key.pem", "ca-cert.pem", "node-id"} {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
			"%s 必须是 0600", name)
	}
}

func TestLoad_MissingDir_ReturnsNotEnrolled(t *testing.T) {
	s, _ := New(filepath.Join(t.TempDir(), "ghost"))
	_, err := s.Load()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotEnrolled))
}

func TestLoad_PartialFiles_ReturnsNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	require.NoError(t, s.Save(sample()))
	// 删一个文件 → 必须 NotEnrolled（不能 Half-load）
	require.NoError(t, os.Remove(filepath.Join(dir, "node-key.pem")))
	_, err := s.Load()
	assert.True(t, errors.Is(err, ErrNotEnrolled))
}

func TestLoad_EmptyFile_ReturnsNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	require.NoError(t, s.Save(sample()))
	require.NoError(t, os.Truncate(filepath.Join(dir, "node-cert.pem"), 0))
	_, err := s.Load()
	assert.True(t, errors.Is(err, ErrNotEnrolled))
}

func TestSave_RejectsIncomplete(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)

	cases := []struct {
		name string
		mut  func(*Enrollment)
	}{
		{"empty node_id", func(e *Enrollment) { e.NodeID = "" }},
		{"empty cert", func(e *Enrollment) { e.CertPEM = nil }},
		{"empty key", func(e *Enrollment) { e.KeyPEM = nil }},
		{"empty ca", func(e *Enrollment) { e.CACertPEM = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := sample()
			tc.mut(e)
			require.Error(t, s.Save(e))
		})
	}
}

func TestSave_NilEnrollment(t *testing.T) {
	s, _ := New(t.TempDir())
	require.Error(t, s.Save(nil))
}

func TestNilStore_Methods(t *testing.T) {
	var s *Store
	_, err := s.Load()
	require.Error(t, err)
	require.Error(t, s.Save(sample()))
}
