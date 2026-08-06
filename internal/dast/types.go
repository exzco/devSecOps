package dast

import "gorm.io/gorm"

type PortJob struct {
	TaskId string `json:"taskId"`
	IP     string `json:"ip"`
	Ports  string `json:"ports"`
}

type FpJob struct {
	TaskId     string `json:"taskId"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Retry      int    `json:"retry"`
	FailReason string `json:"failReason,omitempty"`
}

type PocJob struct {
	TaskId     string   `json:"taskId"`
	Target     string   `json:"target"`
	Proto      string   `json:"proto"`
	Tags       []string `json:"tags"`
	Retry      int      `json:"retry"`
	FailReason string   `json:"failReason,omitempty"`
}

type DastAsset struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Proto       string   `json:"proto"`
	Service     string   `json:"service"`
	Product     string   `json:"product"`
	Version     string   `json:"version"`
	CPEs        []string `json:"cpes"`
	RawResponse string   `json:"raw_response"`
	Timestamp   string   `json:"timestamp"`
}

type PocTemplate struct {
	gorm.Model
	Name        string `gorm:"uniqueIndex;not null" json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Content     string `gorm:"type:text;not null" json:"content"`
}
