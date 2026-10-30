package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// 全局统一 Redis Streams 管道与消费组规范
const (
	StreamSASTTasks  = "sast.command.tasks"
	GroupSASTWorkers = "sast.worker.group"

	StreamDASTRaw       = "dast.command.raw"
	StreamDASTTarget    = "dast.command.network"
	GroupDASTWorkers    = "dast.worker.group"
	DefaultRawStream    = StreamDASTRaw
	DefaultTargetStream = StreamDASTTarget
	DefaultGroup        = GroupDASTWorkers
)

// SASTTaskMessage SAST 扫描任务流载荷
type SASTTaskMessage struct {
	RepoID uint `json:"repo_id"`
	TaskID uint `json:"task_id"`
}

// StreamClient 通用 Redis Streams 消息客户端
type StreamClient struct {
	rdb *redis.Client
}

func NewStreamClient(rdb *redis.Client) *StreamClient {
	return &StreamClient{rdb: rdb}
}

// Publish 向指定 Stream 投递消息
func (s *StreamClient) Publish(ctx context.Context, stream string, payload any) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload failed: %w", err)
	}
	res, err := s.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: stream,
		Values: map[string]interface{}{"data": string(data)},
	}).Result()
	return res, err
}

// CreateGroup 创建消费组（若已存在则忽略）
func (s *StreamClient) CreateGroup(ctx context.Context, stream, group string) error {
	err := s.rdb.XGroupCreateMkStream(ctx, stream, group, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return err
	}
	return nil
}

// Ack 确认已处理的消息
func (s *StreamClient) Ack(ctx context.Context, stream, group, messageID string) error {
	return s.rdb.XAck(ctx, stream, group, messageID).Err()
}

// ReadGroup 消费组读取消息
func (s *StreamClient) ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]redis.XMessage, error) {
	streams, err := s.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    group,
		Consumer: consumer,
		Streams:  []string{stream, ">"},
		Count:    count,
		Block:    block,
	}).Result()
	if err != nil {
		return nil, err
	}
	if len(streams) > 0 {
		return streams[0].Messages, nil
	}
	return nil, nil
}
