package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"devsecops/internal/dast/model"
)

const (
	DefaultRawStream    = "dast.command.raw"
	DefaultTargetStream = "dast.command.network"
	DefaultGroup        = "worker.group.1"
)

type WorkItem struct {
	ScanRunID   string            `json:"scan_run_id"`
	StageRunID  string            `json:"stage_run_id,omitempty"`
	StageName   string            `json:"stage_name,omitempty"`
	Target      string            `json:"target,omitempty"`
	RawTargets  []string          `json:"raw_targets"`
	Port        int               `json:"port,omitempty"`
	PortRange   string            `json:"port_range,omitempty"`
	Profile     string            `json:"profile,omitempty"`
	Policy      model.Policy      `json:"policy"`
	PayloadData map[string]string `json:"payload_data,omitempty"`
}

type StreamClient struct {
	rdb *redis.Client
}

func NewStreamClient(rdb *redis.Client) *StreamClient {
	return &StreamClient{rdb: rdb}
}

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

func (s *StreamClient) CreateGroup(ctx context.Context, stream, group string) error {
	err := s.rdb.XGroupCreateMkStream(ctx, stream, group, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return err
	}
	return nil
}

func (s *StreamClient) Ack(ctx context.Context, stream, group, messageID string) error {
	return s.rdb.XAck(ctx, stream, group, messageID).Err()
}

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
