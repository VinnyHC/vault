package redis

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/sdk/logical"
)

func BenchmarkAuditCloud_request(b *testing.B) {
	config := map[string]string{
		"redis_addrs": "localhost:6379",
	}

	sink, err := Factory(context.Background(), &audit.BackendConfig{
		Config:     config,
		SaltConfig: &salt.Config{},
		SaltView:   &logical.InmemStorage{},
	})
	if err != nil {
		b.Fatal(err)
	}

	in := &logical.LogInput{
		Auth: &logical.Auth{
			ClientToken:     "foo",
			Accessor:        "bar",
			EntityID:        "foobarentity",
			DisplayName:     "testtoken",
			NoDefaultPolicy: true,
			Policies:        []string{"root"},
			TokenType:       logical.TokenTypeService,
		},
		Request: &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "/foo",
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
			WrapInfo: &logical.RequestWrapInfo{
				TTL: 60 * time.Second,
			},
			Headers: map[string][]string{
				"foo": {"bar"},
			},
		},
	}

	ctx := namespace.RootContext(nil)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := sink.LogRequest(ctx, in); err != nil {
				panic(err)
			}
		}
	})
}
