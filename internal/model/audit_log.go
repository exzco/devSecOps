package model

import "time"

type AuditLog struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	VulnerabilityID uint      `json:"vulnerability_id" gorm:"index"`
	OperatorID      uint      `json:"operator_id"` // 0 = AI
	Operator        *User     `json:"operator,omitempty" gorm:"foreignKey:OperatorID"`
	Action          string    `json:"action" gorm:"size:64"`
	OldStatus       string    `json:"old_status" gorm:"size:32"`
	NewStatus       string    `json:"new_status" gorm:"size:32"`
	Comment         string    `json:"comment" gorm:"type:text"`
	CreatedAt       time.Time `json:"createdAt"`
}
