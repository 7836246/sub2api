package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// CursorOAuthHandler handles Cursor OAuth and token import API endpoints.
type CursorOAuthHandler struct {
	cursorOAuthService *service.CursorOAuthService
}

// NewCursorOAuthHandler creates a new CursorOAuthHandler.
func NewCursorOAuthHandler(cursorOAuthService *service.CursorOAuthService) *CursorOAuthHandler {
	return &CursorOAuthHandler{cursorOAuthService: cursorOAuthService}
}

// ============================================================
// OAuth Flow: Step 1 — Generate Login URL
// ============================================================

type CursorGenerateLoginURLRequest struct {
	ProxyID *int64 `json:"proxy_id"`
}

// GenerateLoginURL generates a Cursor PKCE login URL.
// POST /api/v1/admin/cursor/oauth/login-url
func (h *CursorOAuthHandler) GenerateLoginURL(c *gin.Context) {
	var req CursorGenerateLoginURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	result, err := h.cursorOAuthService.GenerateLoginURL(c.Request.Context(), req.ProxyID)
	if err != nil {
		response.InternalError(c, "生成登录链接失败: "+err.Error())
		return
	}

	response.Success(c, result)
}

// ============================================================
// OAuth Flow: Step 2 — Poll for Token
// ============================================================

type CursorPollRequest struct {
	SessionID string `json:"session_id" binding:"required"`
}

// PollForToken polls for authentication completion.
// POST /api/v1/admin/cursor/oauth/poll
func (h *CursorOAuthHandler) PollForToken(c *gin.Context) {
	var req CursorPollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	result, err := h.cursorOAuthService.PollForToken(c.Request.Context(), req.SessionID)
	if err != nil {
		response.InternalError(c, "轮询失败: "+err.Error())
		return
	}

	response.Success(c, result)
}

// ============================================================
// Token Import (Direct)
// ============================================================

type CursorValidateTokenRequest struct {
	AccessToken  string `json:"access_token" binding:"required"`
	MachineID    string `json:"machine_id"`
	MacMachineID string `json:"mac_machine_id"`
}

// ValidateToken validates a directly imported Cursor token.
// POST /api/v1/admin/cursor/oauth/validate-token
func (h *CursorOAuthHandler) ValidateToken(c *gin.Context) {
	var req CursorValidateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	tokenInfo, err := h.cursorOAuthService.ValidateToken(c.Request.Context(), &service.CursorTokenImportInput{
		AccessToken:  req.AccessToken,
		MachineID:    req.MachineID,
		MacMachineID: req.MacMachineID,
	})
	if err != nil {
		response.BadRequest(c, "Token验证失败: "+err.Error())
		return
	}

	response.Success(c, tokenInfo)
}

// ============================================================
// Refresh Token Import
// ============================================================

type CursorValidateRefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// ValidateRefreshToken exchanges a refresh token for an access token, validates it,
// and returns token info for account creation.
// POST /api/v1/admin/cursor/oauth/validate-refresh-token
func (h *CursorOAuthHandler) ValidateRefreshToken(c *gin.Context) {
	var req CursorValidateRefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	tokenInfo, err := h.cursorOAuthService.ValidateRefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		response.BadRequest(c, "Refresh Token 验证失败: "+err.Error())
		return
	}

	response.Success(c, tokenInfo)
}
