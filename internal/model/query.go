package model

import "math"

// PaginatedResponse 包装通用分页数据结构
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Items      interface{} `json:"items,omitempty"`
	Total      int64       `json:"total"`
	Page       int         `json:"page"`
	PerPage    int         `json:"per_page"`
	PageSize   int         `json:"page_size,omitempty"`
	TotalPages int         `json:"total_pages"`
}

// NormalizePagination 规范化分页入参
func NormalizePagination(page, perPage int) (int, int) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	return page, perPage
}

// NewPaginatedResponse 构建分页响应结构
func NewPaginatedResponse(data any, total int64, page, perPage int) *PaginatedResponse {
	page, perPage = NormalizePagination(page, perPage)
	return &PaginatedResponse{
		Data:       data,
		Items:      data,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		PageSize:   perPage,
		TotalPages: int(math.Ceil(float64(total) / float64(perPage))),
	}
}

// ListQuery 全局通用列表查询参数
type ListQuery struct {
	RepoID   uint   `form:"repo_id"`
	TaskID   uint   `form:"task_id"`
	Status   string `form:"status"`
	Severity string `form:"severity"`
	RuleID   string `form:"rule_id"`
	Page     int    `form:"page,default=1"`
	PerPage  int    `form:"per_page,default=20"`
}
