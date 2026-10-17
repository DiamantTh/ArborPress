import {
  base64URLStringToBuffer,
  bufferToBase64URLString,
  startAuthentication,
} from '@simplewebauthn/browser'

type AuthenticationOptions = Parameters<typeof startAuthentication>[0]

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isBase64Url(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false
  try {
    return bufferToBase64URLString(base64URLStringToBuffer(value)) === value
  } catch {
    return false
  }
}

/** Validate the JSON response before handing it to the browser WebAuthn API. */
export function parseAuthenticationOptions(value: unknown): AuthenticationOptions {
  if (!isRecord(value) || !isBase64Url(value.challenge)) {
    throw new Error('Der WebAuthn-Server hat eine ungültige Challenge geliefert.')
  }
  if (value.userVerification !== 'required') {
    throw new Error('Die erforderliche Benutzerverifikation ist nicht verfügbar.')
  }
  if (value.allowCredentials !== undefined) {
    if (!Array.isArray(value.allowCredentials)) {
      throw new Error('Der WebAuthn-Server hat ungültige Credentials geliefert.')
    }
    for (const credential of value.allowCredentials) {
      if (
        !isRecord(credential)
        || credential.type !== 'public-key'
        || !isBase64Url(credential.id)
      ) {
        throw new Error('Der WebAuthn-Server hat ungültige Credentials geliefert.')
      }
    }
  }
  return value as unknown as AuthenticationOptions
}

/** Return a safe, human-readable message without exposing an HTML error page. */
export async function getResponseError(response: Response, fallback: string): Promise<Error> {
  if (response.headers.get('content-type')?.includes('application/json')) {
    try {
      const payload: unknown = await response.json()
      if (isRecord(payload)) {
        for (const key of ['description', 'message']) {
          const message = payload[key]
          if (typeof message === 'string' && message.trim()) return new Error(message)
        }
      }
    } catch {
      // Use the fallback for malformed JSON; never surface a raw response body.
    }
  }
  return new Error(fallback)
}
