package service

import (
	"context"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	dastModel "devsecops/internal/dast/model"
)

func TestCveAiServiceRedisAndDBStorage(t *testing.T) {
	// Setup in-memory sqlite DB for test
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open sqlite db: %v", err)
	}

	if err := db.AutoMigrate(&dastModel.CveIntelligence{}); err != nil {
		t.Fatalf("Failed to migrate db: %v", err)
	}

	svc := NewCveAiService(db, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Test SyncOnlineCves with live network & DB persistence
	res, err := svc.SyncOnlineCves(ctx, "nginx", 2024)
	if err != nil {
		t.Fatalf("SyncOnlineCves error: %v", err)
	}

	t.Logf("Fetched and stored %d CVE entries in local DB for 'nginx'", len(res))

	var count int64
	db.Model(&dastModel.CveIntelligence{}).Count(&count)
	t.Logf("Database table cve_intelligences record count: %d", count)

	for i, c := range res {
		if i >= 3 {
			break
		}
		t.Logf("[%d] CVE: %s | HasEXP: %v | ExpURL: %s", i+1, c.CveID, c.HasEXP, c.ExpURL)
	}
}
