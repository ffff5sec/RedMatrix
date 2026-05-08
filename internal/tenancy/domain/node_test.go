package domain

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func validNode() *Node {
	return &Node{
		TenantID: "00000000-0000-0000-0000-000000000001",
		Name:     "agent-01",
		Version:  "1.0.0",
	}
}

func TestNode_ValidateForCreate_Happy(t *testing.T) {
	n := validNode()
	require.NoError(t, n.ValidateForCreate())
	assert.Equal(t, NodePending, n.Status, "Status 缺省 pending")
}

func TestNode_ValidateForCreate_Errors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Node)
	}{
		{"empty tenant", func(n *Node) { n.TenantID = "" }},
		{"empty name", func(n *Node) { n.Name = "" }},
		{"name 超长", func(n *Node) { n.Name = strings.Repeat("x", 65) }},
		{"status 非法", func(n *Node) { n.Status = NodeStatus("bogus") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := validNode()
			tc.mut(n)
			err := n.ValidateForCreate()
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, errx.ErrInvalidInput, c)
		})
	}
}

func TestNode_NilReceiver(t *testing.T) {
	var n *Node
	require.Error(t, n.ValidateForCreate())
	assert.False(t, n.IsActive())
	assert.False(t, n.IsOnline())
	assert.False(t, n.IsDeleted())
}

func TestNode_StateChecks(t *testing.T) {
	n := validNode()
	n.Status = NodeOnline
	assert.True(t, n.IsActive())
	assert.True(t, n.IsOnline())

	n.Status = NodeDisabled
	assert.False(t, n.IsActive())
	assert.False(t, n.IsOnline())

	n.Status = NodeOnline
	now := time.Now()
	n.DeletedAt = &now
	assert.True(t, n.IsDeleted())
	assert.False(t, n.IsActive())
}

func TestNodeStatus_Valid(t *testing.T) {
	for _, s := range []NodeStatus{NodePending, NodeOnline, NodeOffline, NodeDisabled} {
		assert.True(t, s.Valid())
	}
	assert.False(t, NodeStatus("BOGUS").Valid())
}

func TestNode_DeriveStatus(t *testing.T) {
	now := time.Now()
	mk := func(status NodeStatus, last *time.Time) *Node {
		return &Node{Status: status, LastSeenAt: last}
	}
	recent := now.Add(-10 * time.Second)
	stale := now.Add(-NodeOfflineGrace - time.Second)
	deleted := now.Add(-time.Hour)

	cases := []struct {
		name string
		n    *Node
		want NodeStatus
	}{
		{"pending 不动", mk(NodePending, nil), NodePending},
		{"disabled 不动（即使心跳新）", mk(NodeDisabled, &recent), NodeDisabled},
		{"online + 心跳新 → online", mk(NodeOnline, &recent), NodeOnline},
		{"online + 心跳过期 → offline", mk(NodeOnline, &stale), NodeOffline},
		{"offline + 心跳过期 → offline", mk(NodeOffline, &stale), NodeOffline},
		{"软删 → 原样（不计算）", &Node{
			Status: NodeOnline, LastSeenAt: &stale, DeletedAt: &deleted,
		}, NodeOnline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.n.DeriveStatus(now))
		})
	}
}

func TestNode_DeriveStatus_NilSafe(t *testing.T) {
	var n *Node
	assert.Equal(t, NodeStatus(""), n.DeriveStatus(time.Now()))
}
