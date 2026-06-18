package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Scanner  ScannerConfig  `mapstructure:"scanner"`
	Dast     DastConfig     `mapstructure:"dast"`
	MinIO    MinIOConfig    `mapstructure:"minio"`
	OpenAI   OpenAIConfig   `mapstructure:"openai"`
	JWT      JWTConfig      `mapstructure:"jwt"`
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
	CodeQLPath         string                        `mapstructure:"codeql_path"`
	CodeQLQueries      string                        `mapstructure:"codeql_queries"`
	WorkDir            string                        `mapstructure:"work_dir"`
	MaxConcurrent      int                           `mapstructure:"max_concurrent"`
	TimeoutMinutes     int                           `mapstructure:"timeout_minutes"`
	Cron               string                        `mapstructure:"cron"`
	SupportedLanguages []string                      `mapstructure:"supported_languages"`
	DefaultProfile     string                        `mapstructure:"default_profile"`
	RuleProfiles       map[string]ScannerRuleProfile `mapstructure:"rule_profiles"`
}

type ScannerRuleProfile struct {
	Description    string   `mapstructure:"description"`
	IncludeDefault bool     `mapstructure:"include_default"`
	Targets        []string `mapstructure:"targets"`
}

type DastConfig struct {
	RedisDialTimeout int    `mapstructure:"redis_dial_timeout"`
	RedisReadTimeout int    `mapstructure:"redis_read_timeout"`
	PocDir           string `mapstructure:"poc_dir"`
	DefaultPorts     string `mapstructure:"default_ports"`
	QueuePrefix      string `mapstructure:"queue_prefix"`
	PortScanRate     int    `mapstructure:"portscan_rate"`
	PortScanTimeout  int    `mapstructure:"portscan_timeout"`
	PortScanThreads  int    `mapstructure:"portscan_threads"`
	PortScanType     string `mapstructure:"portscan_type"`
	ConsoleLog       bool   `mapstructure:"console_log"`
}

type MinIOConfig struct {
	Endpoint  string `mapstructure:"endpoint"`
	AccessKey string `mapstructure:"access_key"`
	SecretKey string `mapstructure:"secret_key"`
	Bucket    string `mapstructure:"bucket"`
	UseSSL    bool   `mapstructure:"use_ssl"`
}

type OpenAIConfig struct {
	APIKey  string `mapstructure:"api_key"`
	BaseURL string `mapstructure:"base_url"`
	Model   string `mapstructure:"model"`
}

type JWTConfig struct {
	Secret      string `mapstructure:"secret"`
	ExpireHours int    `mapstructure:"expire_hours"`
}

var GlobalConfig *Config

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
	if cfg.Dast.PocDir == "" {
		cfg.Dast.PocDir = "./poc"
	}
	if cfg.Dast.DefaultPorts == "" {
		cfg.Dast.DefaultPorts = "top1000"
	}
	if cfg.Dast.QueuePrefix == "" {
		cfg.Dast.QueuePrefix = "scan"
	}
	if cfg.Dast.PortScanRate == 0 {
		cfg.Dast.PortScanRate = 1000
	}
	if cfg.Dast.PortScanTimeout == 0 {
		cfg.Dast.PortScanTimeout = 5
	}
	if cfg.Dast.PortScanThreads == 0 {
		cfg.Dast.PortScanThreads = 25
	}
	if cfg.Dast.PortScanType == "" {
		cfg.Dast.PortScanType = "connect"
	}

	GlobalConfig = &cfg
	return &cfg, nil
}

// Convert DastConfig to the format needed by the DAST subsystems
func (c *Config) DastRedisConfig() RedisConfig {
	return c.Redis
}

func (c *Config) DastDialTimeout() time.Duration {
	return time.Duration(c.Dast.RedisDialTimeout) * time.Second
}

func (c *Config) DastReadTimeout() time.Duration {
	return time.Duration(c.Dast.RedisReadTimeout) * time.Second
}

func (c *Config) DastPortScanTimeout() time.Duration {
	return time.Duration(c.Dast.PortScanTimeout) * time.Second
}
