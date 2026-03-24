package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ============================================================
// Constants
// ============================================================

const (
	// CursorLoginBaseURL is the Cursor login page URL.
	CursorLoginBaseURL = "https://cursor.com/loginDeepControl"

	// CursorAuthPollURL is the auth polling endpoint.
	CursorAuthPollURL = "https://api2.cursor.sh/auth/poll"

	// PKCE code verifier length (32 raw bytes → 43 base64url chars).
	cursorCodeVerifierLen = 32

	// OAuth session TTL.
	cursorSessionTTL = 10 * time.Minute

	// Poll interval and max duration.
	cursorPollInterval = 3 * time.Second
	cursorPollTimeout  = 5 * time.Minute
)

// ============================================================
// OAuth Session Store
// ============================================================

// CursorOAuthSession represents an in-flight OAuth login session.
type CursorOAuthSession struct {
	UUID         string    // UUID v4 sent to Cursor
	CodeVerifier string    // PKCE code_verifier (kept secret)
	ProxyURL     string    // Optional proxy for API calls
	CreatedAt    time.Time
}

// CursorOAuthSessionStore is a thread-safe in-memory session store.
type CursorOAuthSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*CursorOAuthSession // keyed by session_id
	stopCh   chan struct{}
}

// NewCursorOAuthSessionStore creates a new session store with automatic cleanup.
func NewCursorOAuthSessionStore() *CursorOAuthSessionStore {
	store := &CursorOAuthSessionStore{
		sessions: make(map[string]*CursorOAuthSession),
		stopCh:   make(chan struct{}),
	}
	go store.cleanupLoop()
	return store
}

// Set stores a session.
func (s *CursorOAuthSessionStore) Set(sessionID string, session *CursorOAuthSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = session
}

// Get retrieves a session by ID. Returns nil, false if not found or expired.
func (s *CursorOAuthSessionStore) Get(sessionID string) (*CursorOAuthSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	if !ok || time.Since(sess.CreatedAt) > cursorSessionTTL {
		return nil, false
	}
	return sess, true
}

// Delete removes a session.
func (s *CursorOAuthSessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// Stop stops the cleanup goroutine.
func (s *CursorOAuthSessionStore) Stop() {
	close(s.stopCh)
}

func (s *CursorOAuthSessionStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			for id, sess := range s.sessions {
				if time.Since(sess.CreatedAt) > cursorSessionTTL {
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		case <-s.stopCh:
			return
		}
	}
}

// ============================================================
// PKCE Helpers
// ============================================================

// generateCursorCodeVerifier generates a PKCE code_verifier.
// Returns a 43-char base64url string (from 32 random bytes).
func generateCursorCodeVerifier() (string, error) {
	b := make([]byte, cursorCodeVerifierLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate code_verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateCursorCodeChallenge computes the PKCE code_challenge from a code_verifier.
// Method: S256 = base64url(SHA256(code_verifier))
func generateCursorCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// ============================================================
// CursorOAuthService
// ============================================================

// CursorOAuthService manages the Cursor PKCE + polling OAuth flow.
type CursorOAuthService struct {
	sessionStore *CursorOAuthSessionStore
	proxyRepo    ProxyRepository
	httpClient   *http.Client
	logger       *slog.Logger
}

// NewCursorOAuthService creates a new Cursor OAuth service.
func NewCursorOAuthService(proxyRepo ProxyRepository) *CursorOAuthService {
	return &CursorOAuthService{
		sessionStore: NewCursorOAuthSessionStore(),
		proxyRepo:    proxyRepo,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
		logger:       slog.Default(),
	}
}

// ============================================================
// Step 1: Generate Login URL
// ============================================================

// CursorLoginURLResult is returned when generating a login URL.
type CursorLoginURLResult struct {
	LoginURL  string `json:"login_url"`
	SessionID string `json:"session_id"`
	UUID      string `json:"uuid"`
}

// GenerateLoginURL generates a Cursor PKCE login URL.
// The frontend should open this URL in a new browser tab for the user.
func (s *CursorOAuthService) GenerateLoginURL(ctx context.Context, proxyID *int64) (*CursorLoginURLResult, error) {
	// Generate PKCE parameters
	codeVerifier, err := generateCursorCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("cursor: generate code_verifier: %w", err)
	}

	codeChallenge := generateCursorCodeChallenge(codeVerifier)
	loginUUID := uuid.New().String()
	sessionID := uuid.New().String()

	// Resolve proxy
	var proxyURL string
	if proxyID != nil {
		proxy, proxyErr := s.proxyRepo.GetByID(ctx, *proxyID)
		if proxyErr == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	// Store the session
	s.sessionStore.Set(sessionID, &CursorOAuthSession{
		UUID:         loginUUID,
		CodeVerifier: codeVerifier,
		ProxyURL:     proxyURL,
		CreatedAt:    time.Now(),
	})

	// Build the login URL
	loginURL := fmt.Sprintf("%s?challenge=%s&uuid=%s&mode=login",
		CursorLoginBaseURL,
		url.QueryEscape(codeChallenge),
		url.QueryEscape(loginUUID),
	)

	s.logger.Info("cursor: generated login URL",
		"session_id", sessionID,
		"uuid", loginUUID,
	)

	return &CursorLoginURLResult{
		LoginURL:  loginURL,
		SessionID: sessionID,
		UUID:      loginUUID,
	}, nil
}

// ============================================================
// Step 2: Poll for Token
// ============================================================

// CursorTokenInfo contains the token info obtained after successful auth.
type CursorTokenInfo struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	AuthID       string `json:"auth_id,omitempty"`
	Email        string `json:"email,omitempty"`
}

// CursorPollResult is the result of polling.
type CursorPollResult struct {
	Status    string           `json:"status"` // "pending" | "success" | "error" | "expired"
	TokenInfo *CursorTokenInfo `json:"token_info,omitempty"`
	Error     string           `json:"error,omitempty"`
}

// PollForToken polls Cursor's /auth/poll endpoint for authentication completion.
// This is designed to be called once per frontend request (non-blocking).
// Returns immediately with the current status.
func (s *CursorOAuthService) PollForToken(ctx context.Context, sessionID string) (*CursorPollResult, error) {
	session, ok := s.sessionStore.Get(sessionID)
	if !ok {
		return &CursorPollResult{
			Status: "expired",
			Error:  "session not found or expired",
		}, nil
	}

	// Check session age
	if time.Since(session.CreatedAt) > cursorPollTimeout {
		s.sessionStore.Delete(sessionID)
		return &CursorPollResult{
			Status: "expired",
			Error:  "session timeout",
		}, nil
	}

	// Call Cursor's poll endpoint
	pollURL := fmt.Sprintf("%s?uuid=%s&verifier=%s",
		CursorAuthPollURL,
		url.QueryEscape(session.UUID),
		url.QueryEscape(session.CodeVerifier),
	)

	req, err := http.NewRequestWithContext(ctx, "GET", pollURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cursor: create poll request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cursor: poll request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cursor: read poll response: %w", err)
	}

	// Cursor returns HTTP 404 / "Not found" when user hasn't completed login yet.
	// Treat non-2xx as pending.
	if resp.StatusCode == http.StatusNotFound {
		return &CursorPollResult{Status: "pending"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		s.logger.Debug("cursor: poll non-200",
			"status", resp.StatusCode,
			"body", string(body),
		)
		return &CursorPollResult{Status: "pending"}, nil
	}

	// Parse response — only expected when status is 200
	var pollResp map[string]any
	if err := json.Unmarshal(body, &pollResp); err != nil {
		// If body is not JSON even on 200, treat as pending
		s.logger.Warn("cursor: poll response not JSON",
			"body", string(body),
		)
		return &CursorPollResult{Status: "pending"}, nil
	}

	// Check if still pending
	if status, ok := pollResp["status"].(string); ok && status == "pending" {
		return &CursorPollResult{Status: "pending"}, nil
	}

	// Check for access token (success)
	accessToken, hasAT := pollResp["accessToken"].(string)
	if hasAT && accessToken != "" {
		// Success! Clean up session
		s.sessionStore.Delete(sessionID)

		tokenInfo := &CursorTokenInfo{
			AccessToken: accessToken,
		}
		if rt, ok := pollResp["refreshToken"].(string); ok {
			tokenInfo.RefreshToken = rt
		}
		if aid, ok := pollResp["authId"].(string); ok {
			tokenInfo.AuthID = aid
		}
		if email, ok := pollResp["email"].(string); ok {
			tokenInfo.Email = email
		}

		s.logger.Info("cursor: OAuth success",
			"session_id", sessionID,
			"email", tokenInfo.Email,
		)

		return &CursorPollResult{
			Status:    "success",
			TokenInfo: tokenInfo,
		}, nil
	}

	// Unknown response — return as pending
	return &CursorPollResult{Status: "pending"}, nil
}

// ============================================================
// Token Import (Direct)
// ============================================================

// CursorTokenImportInput represents a token to import directly.
type CursorTokenImportInput struct {
	AccessToken  string `json:"access_token"`
	MachineID    string `json:"machine_id"`
	MacMachineID string `json:"mac_machine_id"`
}

// ValidateToken validates an access token by pinging the Cursor API.
// Returns token info (email, membership type) if valid.
func (s *CursorOAuthService) ValidateToken(ctx context.Context, input *CursorTokenImportInput) (*CursorTokenInfo, error) {
	if strings.TrimSpace(input.AccessToken) == "" {
		return nil, fmt.Errorf("access_token is required")
	}

	// Create SDK client and try to ping
	client := NewCursorSDKClient(s.logger)
	creds := CursorCredentials{
		AccessToken:  input.AccessToken,
		MachineID:    input.MachineID,
		MacMachineID: input.MacMachineID,
	}

	// Try to get usable models to validate the token
	modelsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err := client.GetUsableModels(modelsCtx, creds)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Try to get profile info
	tokenInfo := &CursorTokenInfo{
		AccessToken: input.AccessToken,
	}

	profileCtx, profileCancel := context.WithTimeout(ctx, 10*time.Second)
	defer profileCancel()

	profile, _, profileErr := client.GetStripeProfile(profileCtx, creds)
	if profileErr == nil && profile != nil {
		// Email might be embedded in the JWT token, but we don't decode it here
		s.logger.Info("cursor: token validated",
			"membership_type", profile.MembershipType,
		)
	}

	return tokenInfo, nil
}

// ============================================================
// Account Credentials Builder
// ============================================================

// BuildAccountCredentials creates the credentials map for storing in the account.
func (s *CursorOAuthService) BuildAccountCredentials(tokenInfo *CursorTokenInfo, machineID, macMachineID string) map[string]any {
	creds := map[string]any{
		"access_token": tokenInfo.AccessToken,
	}
	if tokenInfo.RefreshToken != "" {
		creds["refresh_token"] = tokenInfo.RefreshToken
	}
	if tokenInfo.Email != "" {
		creds["email"] = tokenInfo.Email
	}
	if tokenInfo.AuthID != "" {
		creds["auth_id"] = tokenInfo.AuthID
	}
	if machineID != "" {
		creds["machine_id"] = machineID
	}
	if macMachineID != "" {
		creds["mac_machine_id"] = macMachineID
	}
	return creds
}

// ValidateRefreshToken exchanges a refresh token for an access token, validates
// it against the Cursor API, and returns token info ready for account creation.
// This allows adding Cursor accounts without going through the full OAuth browser flow.
func (s *CursorOAuthService) ValidateRefreshToken(ctx context.Context, refreshToken string) (*CursorTokenInfo, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh_token is required")
	}

	// 1. Exchange refresh token for access token
	client := NewCursorSDKClient(s.logger)
	refreshCtx, refreshCancel := context.WithTimeout(ctx, 15*time.Second)
	defer refreshCancel()

	newAccessToken, _, err := client.RefreshToken(refreshCtx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token exchange failed: %w", err)
	}

	// 2. Validate the new access token by fetching models
	creds := CursorCredentials{AccessToken: newAccessToken}
	validateCtx, validateCancel := context.WithTimeout(ctx, 10*time.Second)
	defer validateCancel()

	_, err = client.GetUsableModels(validateCtx, creds)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// 3. Try to get profile info (email, membership)
	tokenInfo := &CursorTokenInfo{
		AccessToken:  newAccessToken,
		RefreshToken: newAccessToken, // Cursor uses access_token as refresh_token
	}

	profileCtx, profileCancel := context.WithTimeout(ctx, 10*time.Second)
	defer profileCancel()

	profile, _, profileErr := client.GetStripeProfile(profileCtx, creds)
	if profileErr == nil && profile != nil {
		s.logger.Info("cursor: refresh token validated",
			"membership_type", profile.MembershipType,
		)
	}

	return tokenInfo, nil
}

// Stop stops the OAuth service and cleans up resources.
func (s *CursorOAuthService) Stop() {
	s.sessionStore.Stop()
}
