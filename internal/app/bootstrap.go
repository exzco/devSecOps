package app

import (
	"fmt"
	"os"

	"gorm.io/gorm"

	"devsecops/internal/config"
	dastModel "devsecops/internal/dast/model"
	dastpkg "devsecops/internal/dast"
	"devsecops/internal/model"
	sastModel "devsecops/internal/sast/model"
	scaModel "devsecops/internal/sca/model"
	"devsecops/pkg/logger"
)

func LoadConfigFromEnv() (*config.Config, error) {
	configPath := os.Getenv("CONFIG_FILE")
	if configPath == "" {
		candidates := []string{
			"configs/config.local.yaml",
			"configs/example.yaml",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				configPath = c
				break
			}
		}
	}
	if configPath == "" {
		configPath = "configs/example.yaml"
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", configPath, err)
	}

	logger.APP("Bootstrap", "Config loaded: %s", configPath)
	return cfg, nil
}

func InitDatabase(cfg *config.Config) (*gorm.DB, error) {
	db, err := config.InitDB(&cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("initialize database: %w", err)
	}

	logger.APP("Bootstrap", "Database connected")
	return db, nil
}

func MigrateDatabase(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&model.User{},
		&model.AuditLog{},
		&sastModel.Repository{},
		&sastModel.ScanTask{},
		&sastModel.Vulnerability{},
		&dastpkg.PocTemplate{},
		&dastModel.CveIntelligence{},
		&scaModel.ScaProject{},
		&scaModel.ScaScanTask{},
		&scaModel.ScaDependency{},
		&scaModel.ScaVulnerability{},
		&scaModel.ScaOsvVulnerability{},
	); err != nil {
		return fmt.Errorf("migrate domain models: %w", err)
	}
	return nil
}
