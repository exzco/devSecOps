package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestInternalHandlerAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewInternalHandler(nil, "worker-secret", t.TempDir())
	router := gin.New()
	router.GET("/internal", handler.AuthMiddleware(), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	unauthorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/internal", nil)
	router.ServeHTTP(unauthorized, request)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	authorized := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/internal", nil)
	request.Header.Set("X-Worker-Token", "worker-secret")
	router.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusNoContent {
		t.Fatalf("authorized status = %d, want %d", authorized.Code, http.StatusNoContent)
	}
}

func TestInternalHandlerRejectsEmptyConfiguredToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewInternalHandler(nil, "", t.TempDir())
	router := gin.New()
	router.GET("/internal", handler.AuthMiddleware(), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/internal", nil)
	request.Header.Set("X-Worker-Token", "")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("empty configured token status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}
