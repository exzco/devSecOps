package model

import "gorm.io/gorm"

type PocTemplate struct {
	gorm.Model
	Name        string `gorm:"uniqueIndex;not null" json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`                          // critical, high, medium, low, info
	Content     string `gorm:"type:text;not null" json:"content"` // Nuclei YAML configuration template
}
