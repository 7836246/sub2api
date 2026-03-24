package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	pkghttputil "github.com/Wei-Shaw/sub2api/internal/pkg/httputil"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// CursorGatewayHandler handles Cursor API gateway requests (OpenAI-compatible).
type CursorGatewayHandler struct {
	gatewayService        *service.GatewayService
	cursorGatewayService  *service.CursorGatewayService
	billingCacheService   *service.BillingCacheService
	usageService          *service.UsageService
	apiKeyService         *service.APIKeyService
	usageRecordWorkerPool *service.UsageRecordWorkerPool
	concurrencyHelper     *ConcurrencyHelper
	cfg                   *config.Config
}

// NewCursorGatewayHandler creates a new CursorGatewayHandler.
func NewCursorGatewayHandler(
	gatewayService *service.GatewayService,
	cursorGatewayService *service.CursorGatewayService,
	billingCacheService *service.BillingCacheService,
	usageService *service.UsageService,
	apiKeyService *service.APIKeyService,
	usageRecordWorkerPool *service.UsageRecordWorkerPool,
	concurrencyService *service.ConcurrencyService,
	cfg *config.Config,
) *CursorGatewayHandler {
	pingInterval := 0
	if cfg != nil {
		pingInterval = cfg.Concurrency.PingInterval
	}

	return &CursorGatewayHandler{
		gatewayService:        gatewayService,
		cursorGatewayService:  cursorGatewayService,
		billingCacheService:   billingCacheService,
		usageService:          usageService,
		apiKeyService:         apiKeyService,
		usageRecordWorkerPool: usageRecordWorkerPool,
		concurrencyHelper:     NewConcurrencyHelper(concurrencyService, SSEPingFormatComment, time.Duration(pingInterval)*time.Second),
		cfg:                   cfg,
	}
}

// ChatCompletions handles POST /cursor/v1/chat/completions
func (h *CursorGatewayHandler) ChatCompletions(c *gin.Context) {
	apiKey, ok := middleware2.GetAPIKeyFromContext(c)
	if !ok {
		h.errorResponse(c, http.StatusUnauthorized, "unauthorized", "Invalid API key")
		return
	}

	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		h.errorResponse(c, http.StatusInternalServerError, "internal_error", "User context not found")
		return
	}

	reqLog := requestLogger(
		c,
		"handler.cursor_gateway.chat_completions",
		zap.Int64("user_id", subject.UserID),
		zap.Int64("api_key_id", apiKey.ID),
		zap.Any("group_id", apiKey.GroupID),
	)

	// Read request body
	body, err := pkghttputil.ReadRequestBodyWithPrealloc(c.Request)
	if err != nil {
		if maxErr, ok := extractMaxBytesError(err); ok {
			h.errorResponse(c, http.StatusRequestEntityTooLarge, "invalid_request_error", buildBodyTooLargeMessage(maxErr.Limit))
			return
		}
		h.errorResponse(c, http.StatusBadRequest, "invalid_request_error", "Failed to read request body")
		return
	}

	if len(body) == 0 {
		h.errorResponse(c, http.StatusBadRequest, "invalid_request_error", "Request body is empty")
		return
	}

	setOpsRequestContext(c, "", false, body)

	// Get subscription info
	subscription, _ := middleware2.GetSubscriptionFromContext(c)

	// Check billing eligibility
	if err := h.billingCacheService.CheckBillingEligibility(c.Request.Context(), apiKey.User, apiKey, apiKey.Group, subscription); err != nil {
		reqLog.Info("cursor_gateway.billing_check_failed", zap.Error(err))
		status, code, message := billingErrorDetails(err)
		h.errorResponse(c, status, code, message)
		return
	}

	// Acquire user concurrency slot
	streamStarted := false
	userReleaseFunc, err := h.concurrencyHelper.AcquireUserSlotWithWait(c, subject.UserID, subject.Concurrency, false, &streamStarted)
	if err != nil {
		reqLog.Warn("cursor_gateway.user_slot_acquire_failed", zap.Error(err))
		h.handleConcurrencyError(c, err, "user", false)
		return
	}
	userReleaseFunc = wrapReleaseOnDone(c.Request.Context(), userReleaseFunc)
	if userReleaseFunc != nil {
		defer userReleaseFunc()
	}

	// Select account
	selection, err := h.gatewayService.SelectAccountWithLoadAwareness(c.Request.Context(), apiKey.GroupID, "", "", nil, "")
	if err != nil {
		h.errorResponse(c, http.StatusServiceUnavailable, "no_accounts", "No available Cursor accounts: "+err.Error())
		return
	}
	account := selection.Account
	setOpsSelectedAccount(c, account.ID, account.Platform)

	// Acquire account concurrency slot
	accountReleaseFunc := selection.ReleaseFunc
	if !selection.Acquired {
		if selection.WaitPlan == nil {
			h.errorResponse(c, http.StatusServiceUnavailable, "no_accounts", "No available accounts")
			return
		}
		streamStarted := false
		accountReleaseFunc, err = h.concurrencyHelper.AcquireAccountSlotWithWaitTimeout(
			c,
			account.ID,
			selection.WaitPlan.MaxConcurrency,
			selection.WaitPlan.Timeout,
			false,
			&streamStarted,
		)
		if err != nil {
			reqLog.Warn("cursor_gateway.account_slot_acquire_failed", zap.Int64("account_id", account.ID), zap.Error(err))
			h.handleConcurrencyError(c, err, "account", false)
			return
		}
	}
	accountReleaseFunc = wrapReleaseOnDone(c.Request.Context(), accountReleaseFunc)
	if accountReleaseFunc != nil {
		defer accountReleaseFunc()
	}

	// Warmup interception for Cursor accounts
	if account.IsInterceptWarmupEnabled() && isCursorWarmupRequest(body) {
		if selection.Acquired && selection.ReleaseFunc != nil {
			selection.ReleaseFunc()
		}
		h.sendMockCursorResponse(c)
		return
	}

	// Forward to Cursor API
	result, err := h.cursorGatewayService.ForwardChatCompletions(c.Request.Context(), c, account, body)
	if err != nil {
		reqLog.Error("cursor_gateway.forward_failed",
			zap.Int64("account_id", account.ID),
			zap.Error(err),
		)
		// If response headers haven't been sent yet, write error
		if !c.Writer.Written() {
			h.errorResponse(c, http.StatusBadGateway, "upstream_error", "Cursor API request failed")
		}
		return
	}

	// Record usage asynchronously
	userAgent := c.GetHeader("User-Agent")
	clientIP := ip.GetClientIP(c)
	inboundEndpoint := GetInboundEndpoint(c)
	upstreamEndpoint := GetUpstreamEndpoint(c, account.Platform)

	if h.usageRecordWorkerPool != nil && result != nil {
		h.usageRecordWorkerPool.Submit(func(ctx context.Context) {
			if err := h.gatewayService.RecordUsage(ctx, &service.RecordUsageInput{
				Result:           result,
				APIKey:           apiKey,
				User:             apiKey.User,
				Account:          account,
				Subscription:     subscription,
				InboundEndpoint:  inboundEndpoint,
				UpstreamEndpoint: upstreamEndpoint,
				UserAgent:        userAgent,
				IPAddress:        clientIP,
				APIKeyService:    h.apiKeyService,
			}); err != nil {
				reqLog.Error("cursor_gateway.record_usage_failed", zap.Error(err))
			}
		})
	}
}

// Models handles GET /cursor/v1/models
func (h *CursorGatewayHandler) Models(c *gin.Context) {
	apiKey, ok := middleware2.GetAPIKeyFromContext(c)
	if !ok {
		h.errorResponse(c, http.StatusUnauthorized, "unauthorized", "Invalid API key")
		return
	}

	// Select an account to get models from
	selection, err := h.gatewayService.SelectAccountWithLoadAwareness(c.Request.Context(), apiKey.GroupID, "", "", nil, "")
	if err != nil {
		h.errorResponse(c, http.StatusServiceUnavailable, "no_accounts", "No available Cursor accounts")
		return
	}
	account := selection.Account
	if selection.ReleaseFunc != nil {
		defer selection.ReleaseFunc()
	}

	modelsJSON, err := h.cursorGatewayService.GetModels(c.Request.Context(), account)
	if err != nil {
		h.errorResponse(c, http.StatusBadGateway, "upstream_error", "Failed to get models: "+err.Error())
		return
	}

	c.Data(http.StatusOK, "application/json", modelsJSON)
}

func (h *CursorGatewayHandler) errorResponse(c *gin.Context, status int, errType, message string) {
	c.JSON(status, gin.H{
		"error": gin.H{
			"message": message,
			"type":    errType,
			"code":    status,
		},
	})
}

func (h *CursorGatewayHandler) handleConcurrencyError(c *gin.Context, err error, scope string, streamStarted bool) {
	h.errorResponse(c, http.StatusTooManyRequests, "rate_limit_error", "Too many concurrent requests ("+scope+")")
}

// isCursorWarmupRequest checks if an OpenAI-format chat completion request
// is a warmup/title-generation probe.
func isCursorWarmupRequest(body []byte) bool {
	bodyStr := string(body)
	if strings.Contains(bodyStr, "Warmup") {
		return true
	}
	if strings.Contains(bodyStr, "Please write a 5-10 word title for the following conversation:") {
		return true
	}
	if strings.Contains(bodyStr, "nalyze if this message indicates a new conversation topic. If it does, extract a 2-3 word title") {
		return true
	}
	return false
}

// sendMockCursorResponse writes a minimal OpenAI chat completion response
// for intercepted warmup requests.
func (h *CursorGatewayHandler) sendMockCursorResponse(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":      "chatcmpl-warmup",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   "cursor",
		"choices": []gin.H{
			{
				"index": 0,
				"message": gin.H{
					"role":    "assistant",
					"content": "New Conversation",
				},
				"finish_reason": "stop",
			},
		},
		"usage": gin.H{
			"prompt_tokens":     1,
			"completion_tokens": 2,
			"total_tokens":      3,
		},
	})
}
