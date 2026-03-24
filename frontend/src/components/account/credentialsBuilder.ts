export function applyInterceptWarmup(
  credentials: Record<string, unknown>,
  enabled: boolean,
  mode: 'create' | 'edit'
): void {
  if (enabled) {
    credentials.intercept_warmup_requests = true
  } else if (mode === 'edit') {
    delete credentials.intercept_warmup_requests
  }
}

/**
 * Apply cursor_auto_fallback to credentials.
 * Backend defaults to true (enabled), so we only write false when user disables it.
 */
export function applyCursorAutoFallback(
  credentials: Record<string, unknown>,
  enabled: boolean,
  _mode: 'create' | 'edit'
): void {
  if (!enabled) {
    credentials.cursor_auto_fallback = false
  } else {
    delete credentials.cursor_auto_fallback // let backend default to true
  }
}
