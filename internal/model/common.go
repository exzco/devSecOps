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

type AuditLog struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	VulnerabilityID uint      `json:"vulnerability_id" gorm:"index"`
	OperatorID      uint      `json:"operator_id"`       // 0 = AI
	Operator        *User     `json:"operator,omitempty" gorm:"foreignKey:OperatorID"`
	Action          string    `json:"action" gorm:"size:64"`
	OldStatus       string    `json:"old_status" gorm:"size:32"`
	NewStatus       string    `json:"new_status" gorm:"size:32"`
	Comment         string    `json:"comment" gorm:"type:text"`
	CreatedAt       time.Time `json:"created_at"`
}

// PaginatedResponse wraps paginated results
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int64       `json:"total"`
	Page       int         `json:"page"`
	PerPage    int         `json:"per_page"`
	TotalPages int         `json:"total_pages"`
}

// APIResponse is the standard API response
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
