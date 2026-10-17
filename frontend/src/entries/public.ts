function installCommentQuoting(): void {
  const quoteId = document.querySelector<HTMLInputElement>('#quote_of_id')
  const commentBody = document.querySelector<HTMLTextAreaElement>('#comment-body')
  const preview = document.querySelector<HTMLElement>('#quote-preview')
  const label = document.querySelector<HTMLElement>('#quote-label')
  const quoteText = document.querySelector<HTMLElement>('#quote-text')
  const formAnchor = document.querySelector<HTMLElement>('#comment-form')

  if (!quoteId || !commentBody || !preview || !label || !quoteText || !formAnchor) return

  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-comment-quote]')) {
    button.disabled = false
    button.addEventListener('click', () => {
      const { commentId, author, body } = button.dataset
      if (!commentId) return

      quoteId.value = commentId
      label.textContent = `Antwort auf ${author ?? ''}`
      quoteText.textContent = body ?? ''
      preview.hidden = false
      formAnchor.scrollIntoView({ behavior: 'smooth', block: 'start' })
      commentBody.focus()
    })
  }

  document.querySelector<HTMLButtonElement>('[data-comment-quote-clear]')?.addEventListener('click', () => {
    quoteId.value = ''
    preview.hidden = true
    commentBody.focus()
  })

  const noScriptNote = document.querySelector<HTMLElement>('[data-comment-quote-note]')
  if (noScriptNote) noScriptNote.hidden = true
}

installCommentQuoting()
