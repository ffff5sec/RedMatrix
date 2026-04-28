package eventbus

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func TestRegistry_Dispatch_Roundtrip(t *testing.T) {
	r := NewRegistry()
	RegisterType[AssetCreated](r)

	bus := New(nil)
	var got AssetCreated
	Subscribe[AssetCreated](bus, func(_ context.Context, ev AssetCreated) error {
		got = ev
		return nil
	})

	original := AssetCreated{AssetID: "ast_1", TenantID: "t_1"}
	payload, _ := json.Marshal(original)

	require.NoError(t, r.Dispatch(context.Background(), bus, original.Topic(), payload))
	assert.Equal(t, original, got)
}

func TestRegistry_UnknownTopic(t *testing.T) {
	r := NewRegistry()
	bus := New(nil)
	err := r.Dispatch(context.Background(), bus, "nope.v1", []byte("{}"))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInternal, c)
}

func TestRegistry_BadJSON(t *testing.T) {
	r := NewRegistry()
	RegisterType[AssetCreated](r)
	bus := New(nil)

	err := r.Dispatch(context.Background(), bus, AssetCreated{}.Topic(), []byte("not-json"))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInternal, c)
}

func TestRegistry_TopicsSorted(t *testing.T) {
	r := NewRegistry()
	RegisterType[TaskComplete](r)
	RegisterType[AssetCreated](r)
	RegisterType[AssetDeleted](r)

	assert.Equal(t, []string{
		"asset.created.v1",
		"asset.deleted.v1",
		"task.run.complete.v1",
	}, r.Topics())
}

func TestRegistry_NilSafe(t *testing.T) {
	var r *Registry
	assert.Nil(t, r.Topics())
	err := r.Dispatch(context.Background(), New(nil), "x", []byte("{}"))
	require.Error(t, err)

	// 注册到 nil registry 不 panic
	RegisterType[AssetCreated](nil)
}

func TestRegistry_HandlerErrorPropagated(t *testing.T) {
	r := NewRegistry()
	RegisterType[AssetCreated](r)

	bus := New(nil)
	Subscribe[AssetCreated](bus, func(context.Context, AssetCreated) error {
		return errx.New(errx.ErrInternal, "handler boom")
	})

	err := r.Dispatch(context.Background(), bus, AssetCreated{}.Topic(), []byte(`{"AssetID":"x"}`))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInternal, c)
}
