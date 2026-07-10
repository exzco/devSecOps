package model

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"devsecops/internal/config"
)

func InitDB(cfg *config.DatabaseConfig) (*gorm.DB, error) {
	if err := createDatabase(cfg); err != nil {
		return nil, err
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN()), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error),
	})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(
		&User{},
		&AuditLog{},
	); err != nil {
		return nil, err
	}

	return db, nil
}

func createDatabase(cfg *config.DatabaseConfig) error {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.SSLMode)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	var count int64
	db.Raw("SELECT count(*) FROM pg_database WHERE datname = ?", cfg.DBName).Scan(&count)
	if count == 0 {
		if err := db.Exec(fmt.Sprintf("CREATE DATABASE %s", cfg.DBName)).Error; err != nil {
			sqlDB, _ := db.DB()
			_ = sqlDB.Close()
			return err
		}
	}

	sqlDB, _ := db.DB()
	return sqlDB.Close()
}
