export interface CaptchaQuestion {
  q: string
  a: string
}

/** Parse only the public question fields embedded by the server for the island. */
export function parseCaptchaQuestions(value: string): CaptchaQuestion[] {
  const parsed: unknown = JSON.parse(value)
  if (!Array.isArray(parsed)) {
    throw new Error('Captcha questions must be an array')
  }
  return parsed.map((item: unknown) => {
    if (
      typeof item !== 'object'
      || item === null
      || !('q' in item)
      || !('a' in item)
      || typeof item.q !== 'string'
      || typeof item.a !== 'string'
    ) {
      throw new Error('Captcha question has an invalid shape')
    }
    return { q: item.q, a: item.a }
  })
}
