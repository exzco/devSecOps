package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"devsecops/internal/config"
)

const (
	pocBucket   = "dast-pocs"
	pocIndexKey = "poc_index.json"
	localPocDir = "./internal/dast/poc"
)

type PocMeta struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags"`
	FilePath    string   `json:"file_path"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type PocService struct {
	minioClient *minio.Client
	bucketName  string
	mu          sync.RWMutex
}

func NewPocService(cfg *config.MinIOConfig) *PocService {
	// 初始化 MinIO 客户端
	endpoint := cfg.Endpoint
	accessKey := cfg.AccessKey
	secretKey := cfg.SecretKey
	useSSL := cfg.UseSSL

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		log.Fatalf("[MinIO-PoC] 无法初始化 MinIO 客户端: %v", err)
	}

	ctx := context.Background()
	// 确保 Bucket 存在
	exists, err := client.BucketExists(ctx, pocBucket)
	if err != nil {
		log.Printf("[MinIO-PoC] 检查 Bucket 存在性失败: %v，尝试继续...", err)
	}
	if !exists {
		err = client.MakeBucket(ctx, pocBucket, minio.MakeBucketOptions{})
		if err != nil {
			log.Printf("[MinIO-PoC] 创建 Bucket 失败: %v", err)
		} else {
			log.Printf("[MinIO-PoC] 成功创建 Bucket: %s", pocBucket)
		}
	}

	svc := &PocService{
		minioClient: client,
		bucketName:  pocBucket,
	}

	// 启动时同步本地初始 PoC 至 MinIO（冷启动同步）
	go svc.bootstrapPocs()

	return svc
}

// bootstrapPocs 扫描本地 ./poc 目录，如果有 PoC 模板而在 MinIO 中不存在，则将其上传到 MinIO
func (s *PocService) bootstrapPocs() {
	ctx := context.Background()
	log.Println("[MinIO-PoC] 开始同步本地 PoC 模板至 MinIO...")

	// 检查 MinIO 中是否已有 poc_index.json
	_, err := s.minioClient.StatObject(ctx, s.bucketName, pocIndexKey, minio.StatObjectOptions{})
	if err == nil {
		log.Println("[MinIO-PoC] MinIO 中已存在 PoC 索引，跳过引导同步。")
		return
	}

	// 否则，读取本地索引并连同 yaml 一起上传
	indexPath := filepath.Join(localPocDir, pocIndexKey)
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		log.Printf("[MinIO-PoC] 本地未找到 poc_index.json: %v，跳过引导同步", err)
		return
	}

	var list []PocMeta
	if err := json.Unmarshal(indexData, &list); err != nil {
		log.Printf("[MinIO-PoC] 本地 poc_index.json 解析失败: %v", err)
		return
	}

	// 上传索引文件
	_, err = s.minioClient.PutObject(ctx, s.bucketName, pocIndexKey, bytes.NewReader(indexData), int64(len(indexData)), minio.PutObjectOptions{
		ContentType: "application/json",
	})
	if err != nil {
		log.Printf("[MinIO-PoC] 上传 poc_index.json 至 MinIO 失败: %v", err)
		return
	}

	// 逐个上传对应的 yaml 文件
	for _, poc := range list {
		pocPath := filepath.Join(localPocDir, poc.FilePath)
		data, err := os.ReadFile(pocPath)
		if err != nil {
			log.Printf("[MinIO-PoC] 读取本地 PoC 文件失败: %s, %v", poc.FilePath, err)
			continue
		}

		_, err = s.minioClient.PutObject(ctx, s.bucketName, poc.FilePath, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
			ContentType: "application/x-yaml",
		})
		if err != nil {
			log.Printf("[MinIO-PoC] 上传 PoC 模板失败: %s, %v", poc.FilePath, err)
		} else {
			log.Printf("[MinIO-PoC] 已成功同步 PoC 模板: %s 至 MinIO", poc.FilePath)
		}
	}
	log.Println("[MinIO-PoC] 本地 PoC 模板引导同步完成！")
}

// readIndexFromMinio 从 MinIO 读取并解析索引文件
func (s *PocService) readIndexFromMinio(ctx context.Context) ([]PocMeta, error) {
	obj, err := s.minioClient.GetObject(ctx, s.bucketName, pocIndexKey, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		// 判断是否是对象不存在
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return []PocMeta{}, nil
		}
		return nil, err
	}

	var list []PocMeta
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// writeIndexToMinio 将索引数据写回 MinIO
func (s *PocService) writeIndexToMinio(ctx context.Context, list []PocMeta) error {
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	_, err = s.minioClient.PutObject(ctx, s.bucketName, pocIndexKey, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
		ContentType: "application/json",
	})
	return err
}

// ListPocs 获取所有 PoC 模板的元数据列表
func (s *PocService) ListPocs(ctx context.Context) ([]PocMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readIndexFromMinio(ctx)
}

// CreatePoc 新增模板并上传至 MinIO
func (s *PocService) CreatePoc(ctx context.Context, name, description, severity string, tags []string, content string) (*PocMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name == "" {
		return nil, fmt.Errorf("模板名称不能为空")
	}
	if content == "" {
		return nil, fmt.Errorf("模板内容不能为空")
	}

	id := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	fileName := id + ".yaml"

	// 1. 上传 YAML 内容至 MinIO
	dataBytes := []byte(content)
	_, err := s.minioClient.PutObject(ctx, s.bucketName, fileName, bytes.NewReader(dataBytes), int64(len(dataBytes)), minio.PutObjectOptions{
		ContentType: "application/x-yaml",
	})
	if err != nil {
		return nil, fmt.Errorf("上传 PoC 模板文件至 MinIO 失败: %w", err)
	}

	// 2. 读取并更新索引
	list, err := s.readIndexFromMinio(ctx)
	if err != nil {
		list = []PocMeta{}
	}

	now := time.Now().Format(time.RFC3339)
	meta := PocMeta{
		ID:          id,
		Name:        name,
		Description: description,
		Severity:    severity,
		Tags:        tags,
		FilePath:    fileName,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	found := false
	for i, m := range list {
		if m.ID == id {
			meta.CreatedAt = m.CreatedAt
			list[i] = meta
			found = true
			break
		}
	}
	if !found {
		list = append(list, meta)
	}

	// 3. 将索引写回 MinIO
	if err := s.writeIndexToMinio(ctx, list); err != nil {
		return nil, fmt.Errorf("更新索引失败: %w", err)
	}

	return &meta, nil
}

// UpdatePoc 更新 PoC 元数据
func (s *PocService) UpdatePoc(ctx context.Context, id, name, description, severity string, tags []string, content string) (*PocMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	list, err := s.readIndexFromMinio(ctx)
	if err != nil {
		return nil, err
	}

	for i, m := range list {
		if m.ID == id {
			list[i].Name = name
			list[i].Description = description
			list[i].Severity = severity
			list[i].Tags = tags
			list[i].UpdatedAt = time.Now().Format(time.RFC3339)

			if content != "" {
				dataBytes := []byte(content)
				_, err := s.minioClient.PutObject(ctx, s.bucketName, m.FilePath, bytes.NewReader(dataBytes), int64(len(dataBytes)), minio.PutObjectOptions{
					ContentType: "application/x-yaml",
				})
				if err != nil {
					return nil, fmt.Errorf("更新 MinIO 中的 PoC 文件失败: %w", err)
				}
			}

			if err := s.writeIndexToMinio(ctx, list); err != nil {
				return nil, err
			}
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("PoC 模板 %s 不存在", id)
}

// GetPocContent 获取 PoC YAML 文件的具体内容
func (s *PocService) GetPocContent(ctx context.Context, id string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list, err := s.readIndexFromMinio(ctx)
	if err != nil {
		return "", err
	}

	var filePath string
	for _, m := range list {
		if m.ID == id {
			filePath = m.FilePath
			break
		}
	}
	if filePath == "" {
		return "", fmt.Errorf("PoC 模板 %s 不存在", id)
	}

	obj, err := s.minioClient.GetObject(ctx, s.bucketName, filePath, minio.GetObjectOptions{})
	if err != nil {
		return "", fmt.Errorf("从 MinIO 获取 PoC 文件失败: %w", err)
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		return "", fmt.Errorf("读取 PoC 文件失败: %w", err)
	}

	return string(data), nil
}

// DeletePoc 删除 PoC 模板
func (s *PocService) DeletePoc(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	list, err := s.readIndexFromMinio(ctx)
	if err != nil {
		return err
	}

	var newList []PocMeta
	var target *PocMeta
	for _, m := range list {
		if m.ID == id {
			cp := m
			target = &cp
		} else {
			newList = append(newList, m)
		}
	}
	if target == nil {
		return fmt.Errorf("PoC 模板 %s 不存在", id)
	}

	// 1. 从 MinIO 中移除 YAML 文件
	err = s.minioClient.RemoveObject(ctx, s.bucketName, target.FilePath, minio.RemoveObjectOptions{})
	if err != nil {
		log.Printf("[MinIO-PoC] 移除 MinIO 实体文件失败: %v", err)
	}

	// 2. 将更新后的索引写回 MinIO
	return s.writeIndexToMinio(ctx, newList)
}

// DownloadPocsToTempDir 将指定的 PoC 文件列表从 MinIO 下载到本地临时目录，用于 nuclei 扫描运行
func (s *PocService) DownloadPocsToTempDir(ctx context.Context, filenames []string) (string, error) {
	tempDir, err := os.MkdirTemp("", "dast-pocs-*")
	if err != nil {
		return "", err
	}

	for _, fname := range filenames {
		obj, err := s.minioClient.GetObject(ctx, s.bucketName, fname, minio.GetObjectOptions{})
		if err != nil {
			log.Printf("[MinIO-PoC] 无法从 MinIO 读取 %s: %v", fname, err)
			continue
		}
		// 不要在这里 defer close，因为在大循环中可能导致连接积压，在内部处理
		s.downloadToFile(obj, tempDir, fname)
	}

	return tempDir, nil
}

func (s *PocService) downloadToFile(obj *minio.Object, tempDir, fname string) {
	defer obj.Close()
	localPath := filepath.Join(tempDir, fname)
	outFile, err := os.Create(localPath)
	if err != nil {
		log.Printf("[MinIO-PoC] 创建本地临时文件失败 %s: %v", localPath, err)
		return
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, obj); err != nil {
		log.Printf("[MinIO-PoC] 下载并写入本地文件失败 %s: %v", localPath, err)
	}
}

// DownloadMatchedPocs 根据扫描标签过滤匹配的模板并从 MinIO 下载到本地临时目录
func (s *PocService) DownloadMatchedPocs(ctx context.Context, scanTags []string) (string, error) {
	list, err := s.readIndexFromMinio(ctx)
	if err != nil {
		return "", err
	}

	var matchedFiles []string
	for _, poc := range list {
		if hasIntersection(scanTags, poc.Tags) {
			matchedFiles = append(matchedFiles, poc.FilePath)
		}
	}

	if len(matchedFiles) == 0 {
		return "", nil // 没有匹配的 PoC
	}

	return s.DownloadPocsToTempDir(ctx, matchedFiles)
}

func hasIntersection(a, b []string) bool {
	m := make(map[string]bool)
	for _, item := range a {
		m[strings.ToLower(item)] = true
	}
	for _, item := range b {
		if m[strings.ToLower(item)] {
			return true
		}
	}
	return false
}
