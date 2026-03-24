/**
 * Admin Cursor API endpoints
 * Handles Cursor OAuth flows and token import for administrators
 */

import { apiClient } from '../client'

export interface CursorLoginURLResult {
  login_url: string
  session_id: string
  uuid: string
}

export interface CursorLoginURLRequest {
  proxy_id?: number
}

export interface CursorPollRequest {
  session_id: string
}

export interface CursorTokenInfo {
  access_token: string
  refresh_token?: string
  auth_id?: string
  email?: string
  [key: string]: unknown
}

export interface CursorPollResult {
  status: 'pending' | 'success' | 'error' | 'expired'
  token_info?: CursorTokenInfo
  error?: string
}

export interface CursorValidateTokenRequest {
  access_token: string
  machine_id?: string
  mac_machine_id?: string
}

export interface CursorValidateRefreshTokenRequest {
  refresh_token: string
}

export async function generateLoginURL(
  payload: CursorLoginURLRequest
): Promise<CursorLoginURLResult> {
  const { data } = await apiClient.post<CursorLoginURLResult>(
    '/admin/cursor/oauth/login-url',
    payload
  )
  return data
}

export async function pollForToken(
  payload: CursorPollRequest
): Promise<CursorPollResult> {
  const { data } = await apiClient.post<CursorPollResult>(
    '/admin/cursor/oauth/poll',
    payload
  )
  return data
}

export async function validateToken(
  payload: CursorValidateTokenRequest
): Promise<CursorTokenInfo> {
  const { data } = await apiClient.post<CursorTokenInfo>(
    '/admin/cursor/oauth/validate-token',
    payload
  )
  return data
}

export async function validateRefreshToken(
  payload: CursorValidateRefreshTokenRequest
): Promise<CursorTokenInfo> {
  const { data } = await apiClient.post<CursorTokenInfo>(
    '/admin/cursor/oauth/validate-refresh-token',
    payload
  )
  return data
}

export default { generateLoginURL, pollForToken, validateToken, validateRefreshToken }
