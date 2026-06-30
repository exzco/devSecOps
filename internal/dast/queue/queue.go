package queue

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"devsecops/internal/config"
	"devsecops/internal/dast/logger"
)

type QueueKeys struct {
	Prefix string
}

func NewQueueKeys(prefix string) QueueKeys {
	if prefix == "" {
		prefix = "scan"
	}
	return QueueKeys{Prefix: prefix}
}

func (q QueueKeys) PortJobs() string                  { return q.Prefix + ":port:jobs" }
func (q QueueKeys) FpJobs() string                    { return q.Prefix + ":fp:jobs" }
func (q QueueKeys) PocJobs() string                   { return q.Prefix + ":poc:jobs" }
func (q QueueKeys) StatusKey(taskId string) string    { return q.Prefix + ":status:" + taskId }
func (q QueueKeys) ResultsKey(taskId string) string   { return q.Prefix + ":results:" + taskId }
func (q QueueKeys) AssetsKey(taskId string) string    { return q.Prefix + ":assets:" + taskId }

type QueueClient struct {
	Rdb *redis.Client
}

func NewQueueClient(redisCfg config.RedisConfig, dialTimeout, readTimeout time.Duration) *QueueClient {
	rdb := redis.NewClient(&redis.Options{
		Addr:        redisCfg.Addr,
		Password:    redisCfg.Password,
		DB:          redisCfg.DB,
		DialTimeout: dialTimeout,
		ReadTimeout: readTimeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		panic(fmt.Sprintf("[dast-queue] Redis connect failed addr=%s err=%v", redisCfg.Addr, err))
	}

	logger.Printf("[dast-queue] Redis connected: %s (db=%d)\n", redisCfg.Addr, redisCfg.DB)
	return &QueueClient{Rdb: rdb}
}

func (c *QueueClient) Push(ctx context.Context, key, value string) error {
	return c.Rdb.RPush(ctx, key, value).Err()
}

func (c *QueueClient) BLPop(ctx context.Context, key string) (string, error) {
	res, err := c.Rdb.BLPop(ctx, 0, key).Result()
	if err != nil {
		return "", err
	}
	if len(res) < 2 {
		return "", fmt.Errorf("blpop: unexpected result length %d", len(res))
	}
	return res[1], nil
}

func (c *QueueClient) HSet(ctx context.Context, key string, values ...interface{}) error {
	return c.Rdb.HSet(ctx, key, values...).Err()
}

func (c *QueueClient) HIncrBy(ctx context.Context, key, field string, incr int64) error {
	return c.Rdb.HIncrBy(ctx, key, field, incr).Err()
}

func (c *QueueClient) Subscribe(ctx context.Context, channel string) *redis.PubSub {
	return c.Rdb.Subscribe(ctx, channel)
}

func (c *QueueClient) Close() error {
	return c.Rdb.Close()
}

func (c *QueueClient) Del(ctx context.Context, keys ...string) error {
	return c.Rdb.Del(ctx, keys...).Err()
}

func (c *QueueClient) Ping(ctx context.Context) error {
	return c.Rdb.Ping(ctx).Err()
}

func (c *QueueClient) ReadTimeout() time.Duration {
	return c.Rdb.Options().ReadTimeout
}
