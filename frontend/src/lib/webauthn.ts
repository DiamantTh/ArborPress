import {
  base64URLStringToBuffer,
  bufferToBase64URLString,
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser'

type AuthenticationOptions = Parameters<typeof startAuthentication>[0]
type RegistrationOptions = Parameters<typeof startRegistration>[0]

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

/** Validate registration JSON before passing it to the browser WebAuthn API. */
export function parseRegistrationOptions(value: unknown): RegistrationOptions {
  if (!isRecord(value) || !isBase64Url(value.challenge)) {
    throw new Error('Der WebAuthn-Server hat eine ungültige Registrierungs-Challenge geliefert.')
  }

  if (!isRecord(value.user) || !isBase64Url(value.user.id)) {
    throw new Error('Der WebAuthn-Server hat eine ungültige Benutzerkennung geliefert.')
  }
  if (typeof value.user.name !== 'string' || typeof value.user.displayName !== 'string') {
    throw new Error('Der WebAuthn-Server hat ungültige Benutzerdaten geliefert.')
  }

  if (!isRecord(value.authenticatorSelection)
    || value.authenticatorSelection.userVerification !== 'required') {
    throw new Error('Die erforderliche Benutzerverifikation ist nicht verfügbar.')
  }

  if (value.excludeCredentials !== undefined) {
    if (!Array.isArray(value.excludeCredentials)) {
      throw new Error('Der WebAuthn-Server hat ungültige Credentials geliefert.')
    }
    for (const credential of value.excludeCredentials) {
      if (
        !isRecord(credential)
        || credential.type !== 'public-key'
        || !isBase64Url(credential.id)
      ) {
        throw new Error('Der WebAuthn-Server hat ungültige Credentials geliefert.')
      }
    }
  }

  return value as unknown as RegistrationOptions
}

export type JsonObject = Record<string, unknown>

/** Send a same-origin JSON action and expose only structured server errors. */
export async function postAuthJson(
  url: string,
  payload: unknown = {},
  fallback = 'Die Aktion konnte nicht abgeschlossen werden.',
): Promise<JsonObject> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) throw await getResponseError(response, fallback)

  const result: unknown = await response.json().catch(() => ({}))
  if (!isRecord(result)) throw new Error('Der Server hat eine ungültige Antwort geliefert.')
  return result
}

/** Return a safe, human-readable message without exposing an HTML error page. */
export async function getResponseError(response: Response, fallback: string): Promise<Error> {
  if (response.headers.get('content-type')?.includes('application/json')) {
    try {
      const payload: unknown = await response.json()
      if (isRecord(payload)) {
        for (const key of ['description', 'message', 'error']) {
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
