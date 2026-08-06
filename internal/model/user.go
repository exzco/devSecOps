package model

import (
	"time"

	"gorm.io/gorm"
)

// User roles
const (
	RoleAdmin     = "admin"
	RoleSecurity  = "security"
	RoleDeveloper = "developer"
)

type User struct {
	ID           uint           `json:"id" gorm:"primaryKey"`
	Username     string         `json:"username" gorm:"size:128;uniqueIndex;not null"`
	Email        string         `json:"email" gorm:"size:256"`
	Role         string         `json:"role" gorm:"size:32;default:developer"`
	PasswordHash string         `json:"-" gorm:"size:256"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`
}
