package service

import (
	"context"
	"fmt"
	"time"
)

const (
	// cursorRefreshWindow Cursor token 提前刷新窗口：30分钟
	// Cursor access tokens 有效期相对较长，提前30分钟刷新
	cursorRefreshWindow = 30 * time.Minute
)

// CursorTokenRefresher 实现 TokenRefresher 接口用于 Cursor 平台 token 刷新
type CursorTokenRefresher struct {
	cursorOAuthService *CursorOAuthService
}

func NewCursorTokenRefresher(cursorOAuthService *CursorOAuthService) *CursorTokenRefresher {
	return &CursorTokenRefresher{
		cursorOAuthService: cursorOAuthService,
	}
}

// CacheKey 返回用于分布式锁的缓存键
func (r *CursorTokenRefresher) CacheKey(account *Account) string {
	return fmt.Sprintf("cursor:token_refresh:%d", account.ID)
}

// CanRefresh 检查是否可以刷新此账户
// 只处理 cursor 平台的 oauth/setup-token 类型账号
func (r *CursorTokenRefresher) CanRefresh(account *Account) bool {
	return account.Platform == PlatformCursor && account.IsOAuth()
}

// NeedsRefresh 检查账户是否需要刷新
// Cursor 使用固定的30分钟刷新窗口，忽略全局配置
// 如果没有 expires_at 但有 refresh_token，则按每天刷新一次
func (r *CursorTokenRefresher) NeedsRefresh(account *Account, _ time.Duration) bool {
	if !r.CanRefresh(account) {
		return false
	}

	// 没有 refresh_token 则无法刷新
	refreshToken := account.GetCredential("refresh_token")
	if refreshToken == "" {
		return false
	}

	// 检查 expires_at
	expiresAt := account.GetCredentialAsTime("expires_at")
	if expiresAt != nil {
		return time.Until(*expiresAt) < cursorRefreshWindow
	}

	// 没有 expires_at：按 last refresh time 判断（每天刷新一次）
	lastRefresh := account.GetCredentialAsTime("last_refresh_at")
	if lastRefresh != nil {
		return time.Since(*lastRefresh) > 24*time.Hour
	}

	// 从未刷新过，需要刷新
	return true
}

// Refresh 执行 token 刷新
func (r *CursorTokenRefresher) Refresh(ctx context.Context, account *Account) (map[string]any, error) {
	refreshToken := account.GetCredential("refresh_token")
	if refreshToken == "" {
		return nil, fmt.Errorf("cursor: no refresh_token available for account %d", account.ID)
	}

	client := NewCursorSDKClient()
	newAccessToken, newRefreshToken, err := client.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("cursor: token refresh failed: %w", err)
	}

	// Build new credentials, preserving existing fields
	newCredentials := make(map[string]any)
	for k, v := range account.Credentials {
		newCredentials[k] = v
	}

	newCredentials["access_token"] = newAccessToken
	if newRefreshToken != "" {
		newCredentials["refresh_token"] = newRefreshToken
	}
	newCredentials["last_refresh_at"] = time.Now().Format(time.RFC3339)

	return newCredentials, nil
}
