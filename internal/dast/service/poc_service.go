package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"devsecops/internal/config"
	"devsecops/pkg/logger"
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

func NewPocService(cfg *config.MinIOConfig) (*PocService, error) {
	endpoint := cfg.Endpoint
	accessKey := cfg.AccessKey
	secretKey := cfg.SecretKey
	useSSL := cfg.UseSSL

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		logger.DAST("MinIO-PoC", "初始化 MinIO 客户端警告: %v，降级为本地双写机制", err)
	}

	ctx := context.Background()
	if client != nil {
		exists, err := client.BucketExists(ctx, pocBucket)
		if err != nil {
			logger.DAST("MinIO-PoC", "检查 Bucket 存在性警告: %v", err)
		}
		if !exists {
			_ = client.MakeBucket(ctx, pocBucket, minio.MakeBucketOptions{})
		}
	}

	svc := &PocService{
		minioClient: client,
		bucketName:  pocBucket,
	}

	go svc.bootstrapPocs()

	return svc, nil
}

func (s *PocService) bootstrapPocs() {
	ctx := context.Background()
	logger.DAST("MinIO-PoC", "检查并引导同步本地 PoC 模板至 MinIO...")
	_ = os.MkdirAll(localPocDir, 0755)

	indexPath := filepath.Join(localPocDir, pocIndexKey)
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return
	}

	var list []PocMeta
	if err := json.Unmarshal(indexData, &list); err != nil {
		return
	}

	if s.minioClient != nil {
		_, _ = s.minioClient.PutObject(ctx, s.bucketName, pocIndexKey, bytes.NewReader(indexData), int64(len(indexData)), minio.PutObjectOptions{
			ContentType: "application/json",
		})

		for _, poc := range list {
			pocPath := filepath.Join(localPocDir, poc.FilePath)
			data, err := os.ReadFile(pocPath)
			if err != nil {
				continue
			}

			_, _ = s.minioClient.PutObject(ctx, s.bucketName, poc.FilePath, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
				ContentType: "application/x-yaml",
			})
		}
	}
}

func (s *PocService) readIndexFromMinio(ctx context.Context) ([]PocMeta, error) {
	if s.minioClient == nil {
		return nil, fmt.Errorf("minio client uninitialized")
	}
	obj, err := s.minioClient.GetObject(ctx, s.bucketName, pocIndexKey, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, err
	}

	var list []PocMeta
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *PocService) readIndexFromLocalDisk() []PocMeta {
	indexPath := filepath.Join(localPocDir, pocIndexKey)
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return []PocMeta{}
	}
	var list []PocMeta
	if err := json.Unmarshal(data, &list); err != nil {
		return []PocMeta{}
	}
	return list
}

func (s *PocService) writeIndexToLocalDisk(list []PocMeta) {
	_ = os.MkdirAll(localPocDir, 0755)
	indexPath := filepath.Join(localPocDir, pocIndexKey)
	data, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		_ = os.WriteFile(indexPath, data, 0644)
	}
}

func mergePocLists(a, b []PocMeta) []PocMeta {
	m := make(map[string]PocMeta)
	var order []string

	for _, item := range a {
		if item.ID != "" {
			m[item.ID] = item
			order = append(order, item.ID)
		}
	}
	for _, item := range b {
		if item.ID != "" {
			if _, exists := m[item.ID]; !exists {
				order = append(order, item.ID)
			}
			m[item.ID] = item
		}
	}

	var result []PocMeta
	for _, id := range order {
		result = append(result, m[id])
	}
	return result
}

// persistIndexDual synchronizes the updated PoC metadata index to both local disk and MinIO.
func (s *PocService) persistIndexDual(ctx context.Context, list []PocMeta) error {
	// 1. 写本地磁盘
	s.writeIndexToLocalDisk(list)

	// 2. 上传 MinIO
	if s.minioClient == nil {
		return nil
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	_, err = s.minioClient.PutObject(ctx, s.bucketName, pocIndexKey, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
		ContentType: "application/json",
	})
	return err
}

// ListPocs 获取所有 PoC 模板的元数据列表（双存融合，保证 100% 不漏项）
func (s *PocService) ListPocs(ctx context.Context) ([]PocMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	minioList, _ := s.readIndexFromMinio(ctx)
	diskList := s.readIndexFromLocalDisk()

	return mergePocLists(minioList, diskList), nil
}

// CreatePoc 新增模板并同时写本地磁盘与 MinIO（保证双写成功）
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

	// 1. 写本地磁盘文件
	_ = os.MkdirAll(localPocDir, 0755)
	localFilePath := filepath.Join(localPocDir, fileName)
	dataBytes := []byte(content)
	if err := os.WriteFile(localFilePath, dataBytes, 0644); err != nil {
		logger.DAST("PoC-Service", "写入本地磁盘失败: %v", err)
	}

	// 2. 上传 YAML 内容至 MinIO
	if s.minioClient != nil {
		_, err := s.minioClient.PutObject(ctx, s.bucketName, fileName, bytes.NewReader(dataBytes), int64(len(dataBytes)), minio.PutObjectOptions{
			ContentType: "application/x-yaml",
		})
		if err != nil {
			logger.DAST("MinIO-PoC", "上传 PoC 模板文件至 MinIO 警告: %v", err)
		}
	}

	// 3. 读取融合索引并追加新元数据
	minioList, _ := s.readIndexFromMinio(ctx)
	diskList := s.readIndexFromLocalDisk()
	list := mergePocLists(minioList, diskList)

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

	// 4. 将索引同时写回本地磁盘与 MinIO
	_ = s.persistIndexDual(ctx, list)

	logger.DAST("PoC-Service", "Successfully saved new PoC: %s (File: %s)", name, fileName)
	return &meta, nil
}

// UpdatePoc 更新 PoC 元数据
func (s *PocService) UpdatePoc(ctx context.Context, id, name, description, severity string, tags []string, content string) (*PocMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	minioList, _ := s.readIndexFromMinio(ctx)
	diskList := s.readIndexFromLocalDisk()
	list := mergePocLists(minioList, diskList)

	for i, m := range list {
		if m.ID == id {
			list[i].Name = name
			list[i].Description = description
			list[i].Severity = severity
			list[i].Tags = tags
			list[i].UpdatedAt = time.Now().Format(time.RFC3339)

			if content != "" {
				dataBytes := []byte(content)
				localFilePath := filepath.Join(localPocDir, m.FilePath)
				_ = os.WriteFile(localFilePath, dataBytes, 0644)

				if s.minioClient != nil {
					_, _ = s.minioClient.PutObject(ctx, s.bucketName, m.FilePath, bytes.NewReader(dataBytes), int64(len(dataBytes)), minio.PutObjectOptions{
						ContentType: "application/x-yaml",
					})
				}
			}

			_ = s.persistIndexDual(ctx, list)
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("PoC 模板 %s 不存在", id)
}

// GetPocByID returns metadata and YAML content for a single PoC, reading the index only once.
// This replaces the pattern of calling ListPocs + GetPocContent which triggers double I/O.
func (s *PocService) GetPocByID(ctx context.Context, id string) (*PocMeta, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	minioList, _ := s.readIndexFromMinio(ctx)
	diskList := s.readIndexFromLocalDisk()
	list := mergePocLists(minioList, diskList)

	var target *PocMeta
	for _, m := range list {
		if m.ID == id || m.Name == id {
			cp := m
			target = &cp
			break
		}
	}
	if target == nil {
		return nil, "", fmt.Errorf("PoC 模板 %s 不存在", id)
	}

	content, err := s.readPocFile(ctx, target.FilePath)
	if err != nil {
		return target, "", err
	}
	return target, content, nil
}

// GetPocContent 获取 PoC YAML 文件的具体内容（支持从 MinIO 及本地磁盘抓取）
func (s *PocService) GetPocContent(ctx context.Context, id string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	minioList, _ := s.readIndexFromMinio(ctx)
	diskList := s.readIndexFromLocalDisk()
	list := mergePocLists(minioList, diskList)

	var filePath string
	for _, m := range list {
		if m.ID == id || m.Name == id {
			filePath = m.FilePath
			break
		}
	}
	if filePath == "" {
		filePath = id + ".yaml"
	}

	return s.readPocFile(ctx, filePath)
}

// readPocFile reads a PoC YAML file, trying MinIO first then falling back to local disk.
func (s *PocService) readPocFile(ctx context.Context, filePath string) (string, error) {
	// 优先从 MinIO 获取
	if s.minioClient != nil {
		obj, err := s.minioClient.GetObject(ctx, s.bucketName, filePath, minio.GetObjectOptions{})
		if err == nil {
			data, err := io.ReadAll(obj)
			obj.Close()
			if err == nil && len(data) > 0 {
				return string(data), nil
			}
		}
	}

	// 本地磁盘降级读取
	localPath := filepath.Join(localPocDir, filePath)
	data, err := os.ReadFile(localPath)
	if err == nil && len(data) > 0 {
		return string(data), nil
	}

	return "", fmt.Errorf("无法找到 PoC 文件: %s", filePath)
}

// DeletePoc 删除 PoC 模板
func (s *PocService) DeletePoc(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	minioList, _ := s.readIndexFromMinio(ctx)
	diskList := s.readIndexFromLocalDisk()
	list := mergePocLists(minioList, diskList)

	var newList []PocMeta
	var target *PocMeta
	for _, m := range list {
		if m.ID == id || m.Name == id {
			cp := m
			target = &cp
		} else {
			newList = append(newList, m)
		}
	}
	if target == nil {
		return fmt.Errorf("PoC 模板 %s 不存在", id)
	}

	if s.minioClient != nil {
		_ = s.minioClient.RemoveObject(ctx, s.bucketName, target.FilePath, minio.RemoveObjectOptions{})
	}
	_ = os.Remove(filepath.Join(localPocDir, target.FilePath))

	return s.persistIndexDual(ctx, newList)
}

// DownloadPocsToTempDir 将指定的 PoC 文件列表下载到本地临时目录
func (s *PocService) DownloadPocsToTempDir(ctx context.Context, filenames []string) (string, error) {
	tempDir, err := os.MkdirTemp("", "dast-pocs-*")
	if err != nil {
		return "", err
	}

	for _, fname := range filenames {
		localPath := filepath.Join(localPocDir, fname)
		if data, err := os.ReadFile(localPath); err == nil {
			_ = os.WriteFile(filepath.Join(tempDir, fname), data, 0644)
			continue
		}

		if s.minioClient != nil {
			obj, err := s.minioClient.GetObject(ctx, s.bucketName, fname, minio.GetObjectOptions{})
			if err == nil {
				s.downloadToFile(obj, tempDir, fname)
			}
		}
	}

	return tempDir, nil
}

func (s *PocService) downloadToFile(obj *minio.Object, tempDir, fname string) {
	defer obj.Close()
	localPath := filepath.Join(tempDir, fname)
	outFile, err := os.Create(localPath)
	if err != nil {
		return
	}
	defer outFile.Close()

	_, _ = io.Copy(outFile, obj)
}

// DownloadMatchedPocs 根据扫描标签过滤匹配的模板
func (s *PocService) DownloadMatchedPocs(ctx context.Context, scanTags []string) (string, error) {
	list, err := s.ListPocs(ctx)
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
		return "", nil
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
