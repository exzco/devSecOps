package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"devsecops/internal/config"
	"devsecops/internal/messaging"
	"devsecops/internal/sast/scanner"
	"devsecops/internal/worker"
)

type WorkerRuntime struct {
	streamClient *messaging.StreamClient
	dispatcher   *TaskDispatcher
	reporter     *worker.HeartbeatReporter
	stream       string
	group        string
	consumerID   string
	concurrency  int
	wg           sync.WaitGroup
}

func NewWorkerRuntime(
	rdb *redis.Client,
	cfg *config.Config,
	reporter *worker.HeartbeatReporter,
) *WorkerRuntime {
	concurrency := cfg.Scanner.MaxConcurrent
	if concurrency <= 0 {
		concurrency = 1
	}

	consumerID := ""
	if reporter != nil {
		consumerID = reporter.WorkerID()
	} else {
		hostname, _ := os.Hostname()
		consumerID = fmt.Sprintf("sast-worker-%s-%d", hostname, os.Getpid())
	}

	dispatcher := NewTaskDispatcher(
		scanner.NewScanWorker(&cfg.Scanner),
		NewWorkerClient(&cfg.Worker),
	)

	return &WorkerRuntime{
		streamClient: messaging.NewStreamClient(rdb),
		dispatcher:   dispatcher,
		reporter:     reporter,
		stream:       messaging.StreamSASTTasks,
		group:        messaging.GroupSASTWorkers,
		consumerID:   consumerID,
		concurrency:  concurrency,
	}
}

// Run 启动 Redis Streams 任务消费循环
func (w *WorkerRuntime) Run(ctx context.Context) error {
	if err := w.streamClient.CreateGroup(ctx, w.stream, w.group); err != nil {
		return fmt.Errorf("create sast task stream group: %w", err)
	}

	log.Printf("[worker-sast] Redis Streams 消费者已就绪: Stream=%s Group=%s Consumer=%s 并发数=%d",
		w.stream, w.group, w.consumerID, w.concurrency)

	sem := make(chan struct{}, w.concurrency)

	for {
		select {
		case <-ctx.Done():
			log.Println("[worker-sast] 接收到退出信号，等待正在进行的扫描任务完成...")
			w.wg.Wait()
			return nil
		case sem <- struct{}{}:
		}

		msgs, err := w.streamClient.ReadGroup(ctx, w.stream, w.group, w.consumerID, 1, 2*time.Second)
		if err != nil {
			<-sem
			if err == redis.Nil || ctx.Err() != nil {
				continue
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}

		if len(msgs) == 0 {
			<-sem
			continue
		}

		msg := msgs[0]
		w.wg.Add(1)
		go func(m redis.XMessage) {
			defer func() {
				<-sem
				w.wg.Done()
			}()
			w.processMessage(ctx, m)
		}(msg)
	}
}

func (w *WorkerRuntime) processMessage(ctx context.Context, msg redis.XMessage) {
	if w.reporter != nil {
		w.reporter.IncrActiveTasks()
		defer w.reporter.DecrActiveTasks()
	}

	rawJSON, ok := msg.Values["data"].(string)
	if !ok {
		log.Printf("[worker-sast] 忽略无效消息 (缺少 data 字段): ID=%s", msg.ID)
		_ = w.streamClient.Ack(ctx, w.stream, w.group, msg.ID)
		return
	}

	var payload messaging.SASTTaskMessage
	if err := json.Unmarshal([]byte(rawJSON), &payload); err != nil {
		log.Printf("[worker-sast] 解析任务载荷失败: %v, raw=%s", err, rawJSON)
		_ = w.streamClient.Ack(ctx, w.stream, w.group, msg.ID)
		return
	}

	log.Printf("[worker-sast] 收到扫描任务: TaskID=%d RepoID=%d (MsgID: %s)", payload.TaskID, payload.RepoID, msg.ID)

	if err := w.dispatcher.Dispatch(ctx, payload); err != nil {
		log.Printf("[worker-sast] 任务执行失败 TaskID=%d: %v", payload.TaskID, err)
	} else {
		log.Printf("[worker-sast] 任务执行完成 TaskID=%d", payload.TaskID)
	}

	if err := w.streamClient.Ack(ctx, w.stream, w.group, msg.ID); err != nil {
		log.Printf("[worker-sast] 确认消息失败 MsgID=%s: %v", msg.ID, err)
	}
}

// StartWorker 兼容启动函数，在后台协程运行 WorkerRuntime
func StartWorker(ctx context.Context, cfg *config.Config, rdb *redis.Client, reporter *worker.HeartbeatReporter) (*WorkerRuntime, error) {
	runtime := NewWorkerRuntime(rdb, cfg, reporter)
	go func() {
		if err := runtime.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[worker-sast] 消费运行时退出异常: %v", err)
		}
	}()
	return runtime, nil
}
