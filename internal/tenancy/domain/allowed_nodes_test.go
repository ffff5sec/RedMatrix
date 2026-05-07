package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllowedNodes_Contains_AllNodes(t *testing.T) {
	a := AllowedNodes{AllNodes: true}
	assert.True(t, a.Contains("any-id"))
	assert.True(t, a.Contains(""))
	assert.False(t, a.IsExplicitWhitelist())
}

func TestAllowedNodes_Contains_Whitelist(t *testing.T) {
	a := AllowedNodes{NodeIDs: []string{"n1", "n2"}}
	assert.True(t, a.Contains("n1"))
	assert.True(t, a.Contains("n2"))
	assert.False(t, a.Contains("n3"))
	assert.True(t, a.IsExplicitWhitelist())
}

func TestAllowedNodes_Contains_EmptyWhitelist(t *testing.T) {
	a := AllowedNodes{}
	assert.False(t, a.Contains("any"), "AllNodes=false 且空 → 全拒")
	assert.True(t, a.IsExplicitWhitelist())
}
