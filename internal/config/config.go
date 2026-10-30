package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

func ResolvePath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if fromEnv := os.Getenv("CONFIG_FILE"); fromEnv != "" {
		return fromEnv
	}
	if _, err := os.Stat("configs/config.local.yaml"); err == nil {
		return "configs/config.local.yaml"
	}
	return "configs/example.yaml"
}

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Scanner  ScannerConfig  `mapstructure:"scanner"`
	Dast     DastConfig     `mapstructure:"dast"`
	Worker   WorkerConfig   `mapstructure:"worker"`
}

type ServerConfig struct {
	Port int    `mapstructure:"port"`
	Mode string `mapstructure:"mode"`
}

type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	SSLMode  string `mapstructure:"sslmode"`
}

func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode)
}

type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type ScannerConfig struct {
	CodeQLPath     string                        `mapstructure:"codeql_path"`
	CodeQLQueries  string                        `mapstructure:"codeql_queries"`
	WorkDir        string                        `mapstructure:"work_dir"`
	MaxConcurrent  int                           `mapstructure:"max_concurrent"`
	TimeoutMinutes int                           `mapstructure:"timeout_minutes"`
	DefaultProfile string                        `mapstructure:"default_profile"`
	RuleProfiles   map[string]ScannerRuleProfile `mapstructure:"rule_profiles"`
}

type ScannerRuleProfile struct {
	Description    string   `mapstructure:"description"`
	IncludeDefault bool     `mapstructure:"include_default"`
	Targets        []string `mapstructure:"targets"`
}

type DastConfig struct {
	PocDir       string `mapstructure:"poc_dir"`
	DefaultPorts string `mapstructure:"default_ports"`
	QueuePrefix  string `mapstructure:"queue_prefix"`
}

type WorkerConfig struct {
	CallbackURL string `mapstructure:"callback_url"`
	Token       string `mapstructure:"token"`
}

func LoadConfig(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Apply default values if empty
	if cfg.Scanner.WorkDir == "" {
		cfg.Scanner.WorkDir = "./data/sast"
	}
	if cfg.Scanner.MaxConcurrent <= 0 {
		cfg.Scanner.MaxConcurrent = 2
	}
	if cfg.Scanner.TimeoutMinutes <= 0 {
		cfg.Scanner.TimeoutMinutes = 30
	}
	if cfg.Dast.PocDir == "" {
		cfg.Dast.PocDir = "./data/pocs"
	}
	if cfg.Dast.DefaultPorts == "" {
		cfg.Dast.DefaultPorts = "top1000"
	}
	if cfg.Dast.QueuePrefix == "" {
		cfg.Dast.QueuePrefix = "scan"
	}
	if cfg.Worker.CallbackURL == "" {
		cfg.Worker.CallbackURL = "http://localhost:22211"
	}
	return &cfg, nil
}
