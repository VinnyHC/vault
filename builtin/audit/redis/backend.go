package redis

import (
	"bytes"
	"context"
	"fmt"
	"github.com/alicebob/miniredis/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/go-redis/redis/v9"
)

func Factory(ctx context.Context, conf *audit.BackendConfig) (audit.Backend, error) {
	if conf.SaltConfig == nil {
		return nil, fmt.Errorf("nil salt config")
	}
	if conf.SaltView == nil {
		return nil, fmt.Errorf("nil salt view")
	}

	user, ok := conf.Config["redis_username"]
	if !ok {
		user = ""
	}

	pw, ok := conf.Config["redis_password"]
	if !ok {
		pw = ""
	}

	// Check if we should embed
	devRedis := false
	if raw, ok := conf.Config["dev_redis"]; ok {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, err
		}
		devRedis = b
	}

	var addrs []string

	switch {
	case devRedis:
		if devRedis {
			s, err := miniredis.Run()
			if err != nil {
				return nil, err
			}
			addrs = []string{s.Addr()}
			s.RequireUserAuth(user, pw)
		}
	default:
		rawAddr, ok := conf.Config["redis_addrs"]
		if !ok {
			return nil, fmt.Errorf("redis_addrs is required")
		}
		addrs = strings.Split(rawAddr, ",")
	}

	db, ok := conf.Config["redis_db"]
	if !ok {
		db = "0"
	}
	dbI, err := strconv.Atoi(db)
	if err != nil {
		return nil, fmt.Errorf("redis_db must be an int: %w", err)
	}

	channel, ok := conf.Config["redis_channel"]
	if !ok {
		channel = "vaultEvents"
	}

	opts := &redis.UniversalOptions{
		Addrs:    addrs,
		Username: user,
		Password: pw,
		DB:       dbI,
	}

	rdb := redis.NewUniversalClient(opts)
	resp := rdb.Ping(ctx)
	_, err = resp.Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	// Check if hashing of accessor is disabled
	hmacAccessor := true
	if hmacAccessorRaw, ok := conf.Config["hmac_accessor"]; ok {
		value, err := strconv.ParseBool(hmacAccessorRaw)
		if err != nil {
			return nil, err
		}
		hmacAccessor = value
	}

	// Check if raw logging is enabled
	logRaw := false
	if raw, ok := conf.Config["log_raw"]; ok {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, err
		}
		logRaw = b
	}

	b := &Backend{
		redisClient:  rdb,
		redisChannel: channel,
		saltConfig:   conf.SaltConfig,
		saltView:     conf.SaltView,
		salt:         new(atomic.Value),
		formatConfig: audit.FormatterConfig{
			Raw:          logRaw,
			HMACAccessor: hmacAccessor,
		},
	}

	// Ensure we are working with the right type by explicitly storing a nil of
	// the right type
	b.salt.Store((*salt.Salt)(nil))

	b.formatter.AuditFormatWriter = &audit.JSONFormatWriter{
		Prefix:   conf.Config["prefix"],
		SaltFunc: b.Salt,
	}

	return b, nil
}

// Backend is the audit backend for the redis-based audit store.
type Backend struct {
	redisClient  redis.UniversalClient
	redisChannel string
	embedded     *miniredis.Miniredis

	formatter    audit.AuditFormatter
	formatConfig audit.FormatterConfig

	saltMutex  sync.RWMutex
	salt       *atomic.Value
	saltConfig *salt.Config
	saltView   logical.Storage
}

var _ audit.Backend = (*Backend)(nil)

func (b *Backend) Salt(ctx context.Context) (*salt.Salt, error) {
	s := b.salt.Load().(*salt.Salt)
	if s != nil {
		return s, nil
	}

	b.saltMutex.Lock()
	defer b.saltMutex.Unlock()

	s = b.salt.Load().(*salt.Salt)
	if s != nil {
		return s, nil
	}

	newSalt, err := salt.NewSalt(ctx, b.saltView, b.saltConfig)
	if err != nil {
		b.salt.Store((*salt.Salt)(nil))
		return nil, err
	}

	b.salt.Store(newSalt)
	return newSalt, nil
}

func (b *Backend) GetHash(ctx context.Context, data string) (string, error) {
	salt, err := b.Salt(ctx)
	if err != nil {
		return "", err
	}

	return audit.HashString(salt, data), nil
}

func (b *Backend) LogRequest(ctx context.Context, in *logical.LogInput) error {
	return b.log(ctx, in, "req")
}

func (b *Backend) LogResponse(ctx context.Context, in *logical.LogInput) error {
	return b.log(ctx, in, "resp")
}

func (b *Backend) LogTestMessage(ctx context.Context, in *logical.LogInput, config map[string]string) error {

	var buf bytes.Buffer
	temporaryFormatter := audit.NewTemporaryFormatter(config["format"], config["prefix"])
	if err := temporaryFormatter.FormatRequest(ctx, &buf, b.formatConfig, in); err != nil {
		return err
	}

	return b.redisClient.Publish(ctx, b.redisChannel, buf.String()).Err()
}

func (b *Backend) Reload(_ context.Context) error {
	return nil
}

func (b *Backend) Invalidate(_ context.Context) {
	b.saltMutex.Lock()
	defer b.saltMutex.Unlock()
	b.salt.Store((*salt.Salt)(nil))
}

func (b *Backend) log(ctx context.Context, in *logical.LogInput, op string) error {
	buf := bytes.NewBuffer(make([]byte, 0, 2000))

	switch op {
	case "req":
		err := b.formatter.FormatRequest(ctx, buf, b.formatConfig, in)
		if err != nil {
			return err
		}
	case "resp":
		err := b.formatter.FormatResponse(ctx, buf, b.formatConfig, in)
		if err != nil {
			return err
		}
	default:
		return nil
	}

	return b.redisClient.Publish(ctx, b.redisChannel, buf.String()).Err()
}
