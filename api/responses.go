package api

import (
	"encoding/json"
	"net/http"
)

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// PaginatedResponse represents a paginated API response
type PaginatedResponse struct {
	Success    bool        `json:"success"`
	Data       interface{} `json:"data"`
	Page       int         `json:"page"`
	PerPage    int         `json:"per_page"`
	TotalItems int         `json:"total_items"`
	TotalPages int         `json:"total_pages"`
}

// SendJSON sends a JSON response
func SendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// SendSuccess sends a success response
func SendSuccess(w http.ResponseWriter, message string, data interface{}) {
	SendJSON(w, http.StatusOK, Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// SendCreated sends a created response
func SendCreated(w http.ResponseWriter, message string, data interface{}) {
	SendJSON(w, http.StatusCreated, Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// SendError sends an error response
func SendError(w http.ResponseWriter, status int, message string) {
	SendJSON(w, status, Response{
		Success: false,
		Error:   message,
	})
}

// SendBadRequest sends a 400 error response
func SendBadRequest(w http.ResponseWriter, message string) {
	SendError(w, http.StatusBadRequest, message)
}

// SendUnauthorized sends a 401 error response
func SendUnauthorized(w http.ResponseWriter, message string) {
	SendError(w, http.StatusUnauthorized, message)
}

// SendForbidden sends a 403 error response
func SendForbidden(w http.ResponseWriter, message string) {
	SendError(w, http.StatusForbidden, message)
}

// SendNotFound sends a 404 error response
func SendNotFound(w http.ResponseWriter, message string) {
	SendError(w, http.StatusNotFound, message)
}

// SendInternalError sends a 500 error response
func SendInternalError(w http.ResponseWriter, message string) {
	SendError(w, http.StatusInternalServerError, message)
}

// SendPaginated sends a paginated response
func SendPaginated(w http.ResponseWriter, data interface{}, page, perPage, totalItems int) {
	totalPages := (totalItems + perPage - 1) / perPage

	SendJSON(w, http.StatusOK, PaginatedResponse{
		Success:    true,
		Data:       data,
		Page:       page,
		PerPage:    perPage,
		TotalItems: totalItems,
		TotalPages: totalPages,
	})
}
