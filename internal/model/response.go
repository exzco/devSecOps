package model

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
