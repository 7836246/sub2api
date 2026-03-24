import { ref, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAppStore } from '@/stores/app'
import { adminAPI } from '@/api/admin'
import type { CursorTokenInfo, CursorPollResult } from '@/api/admin/cursor'

export function useCursorOAuth() {
  const appStore = useAppStore()
  const { t } = useI18n()

  const loginUrl = ref('')
  const sessionId = ref('')
  const loading = ref(false)
  const polling = ref(false)
  const error = ref('')
  let pollTimer: ReturnType<typeof setInterval> | null = null

  const resetState = () => {
    loginUrl.value = ''
    sessionId.value = ''
    loading.value = false
    polling.value = false
    error.value = ''
    stopPolling()
  }

  const stopPolling = () => {
    if (pollTimer) {
      clearInterval(pollTimer)
      pollTimer = null
    }
    polling.value = false
  }

  // Cleanup on unmount
  onBeforeUnmount(() => {
    stopPolling()
  })

  /**
   * Step 1: Generate a Cursor login URL (PKCE challenge).
   * Returns the login URL to open in a new tab.
   */
  const generateLoginURL = async (proxyId?: number | null): Promise<boolean> => {
    loading.value = true
    loginUrl.value = ''
    sessionId.value = ''
    error.value = ''

    try {
      const payload: Record<string, unknown> = {}
      if (proxyId) payload.proxy_id = proxyId

      const result = await adminAPI.cursor.generateLoginURL(payload as any)
      loginUrl.value = result.login_url
      sessionId.value = result.session_id
      return true
    } catch (err: any) {
      error.value =
        err.response?.data?.detail || t('admin.accounts.oauth.cursor.failedToGenerateUrl')
      appStore.showError(error.value)
      return false
    } finally {
      loading.value = false
    }
  }

  /**
   * Step 2: Start polling for Cursor auth completion.
   * Returns a promise that resolves when auth is done or times out.
   */
  const startPolling = (): Promise<CursorTokenInfo | null> => {
    if (!sessionId.value) {
      error.value = 'No session ID available for polling'
      return Promise.resolve(null)
    }

    stopPolling() // Stop any existing polling
    polling.value = true

    return new Promise((resolve) => {
      let attempts = 0
      const maxAttempts = 100 // ~5 minutes at 3s interval

      pollTimer = setInterval(async () => {
        attempts++
        if (attempts > maxAttempts) {
          stopPolling()
          error.value = t('admin.accounts.oauth.cursor.pollTimeout')
          resolve(null)
          return
        }

        try {
          const result: CursorPollResult = await adminAPI.cursor.pollForToken({
            session_id: sessionId.value
          })

          if (result.status === 'success' && result.token_info) {
            stopPolling()
            resolve(result.token_info)
            return
          }

          if (result.status === 'expired' || result.status === 'error') {
            stopPolling()
            error.value = result.error || t('admin.accounts.oauth.cursor.pollFailed')
            resolve(null)
            return
          }

          // status === 'pending' → continue polling
        } catch (err: any) {
          stopPolling()
          error.value =
            err.response?.data?.detail || t('admin.accounts.oauth.cursor.pollFailed')
          resolve(null)
        }
      }, 3000)
    })
  }

  /**
   * Validate & import a directly pasted Cursor access token.
   */
  const validateToken = async (
    accessToken: string,
    machineId?: string,
    macMachineId?: string
  ): Promise<CursorTokenInfo | null> => {
    if (!accessToken.trim()) {
      error.value = t('admin.accounts.oauth.cursor.pleaseEnterToken')
      return null
    }

    loading.value = true
    error.value = ''

    try {
      const tokenInfo = await adminAPI.cursor.validateToken({
        access_token: accessToken.trim(),
        machine_id: machineId,
        mac_machine_id: macMachineId
      })
      return tokenInfo
    } catch (err: any) {
      error.value =
        err.response?.data?.detail || t('admin.accounts.oauth.cursor.failedToValidateToken')
      return null
    } finally {
      loading.value = false
    }
  }

  /**
   * Validate & import a Cursor refresh token.
   * Exchanges it for an access token, validates it, and returns token info.
   */
  const validateRefreshToken = async (
    refreshToken: string
  ): Promise<CursorTokenInfo | null> => {
    if (!refreshToken.trim()) {
      error.value = t('admin.accounts.oauth.cursor.pleaseEnterToken')
      return null
    }

    loading.value = true
    error.value = ''

    try {
      const tokenInfo = await adminAPI.cursor.validateRefreshToken({
        refresh_token: refreshToken.trim()
      })
      return tokenInfo
    } catch (err: any) {
      error.value =
        err.response?.data?.detail || t('admin.accounts.oauth.cursor.failedToValidateToken')
      return null
    } finally {
      loading.value = false
    }
  }

  /**
   * Build credentials map from token info for storing as Account credentials.
   */
  const buildCredentials = (
    tokenInfo: CursorTokenInfo,
    machineId?: string,
    macMachineId?: string
  ): Record<string, unknown> => {
    const creds: Record<string, unknown> = {
      access_token: tokenInfo.access_token
    }
    if (tokenInfo.refresh_token) creds.refresh_token = tokenInfo.refresh_token
    if (tokenInfo.email) creds.email = tokenInfo.email
    if (tokenInfo.auth_id) creds.auth_id = tokenInfo.auth_id
    if (machineId) creds.machine_id = machineId
    if (macMachineId) creds.mac_machine_id = macMachineId
    return creds
  }

  return {
    loginUrl,
    sessionId,
    loading,
    polling,
    error,
    resetState,
    stopPolling,
    generateLoginURL,
    startPolling,
    validateToken,
    validateRefreshToken,
    buildCredentials
  }
}
