<script lang="ts">
  import type { CaptchaQuestion } from '../admin-data.js'

  export let initialQuestions: CaptchaQuestion[]

  let questions = initialQuestions.length
    ? initialQuestions.map(({ q, a }) => ({ q, a }))
    : [{ q: '', a: '' }]

  function addQuestion(): void {
    questions = [...questions, { q: '', a: '' }]
  }

  function removeQuestion(index: number): void {
    questions = questions.filter((_, itemIndex) => itemIndex !== index)
    if (questions.length === 0) questions = [{ q: '', a: '' }]
  }
</script>

<div class="captcha-questions">
  {#each questions as question, index (index)}
    <fieldset class="q-row">
      <legend>Frage {index + 1}</legend>
      <label>
        Frage
        <input type="text" name={`q_${index}`} bind:value={question.q} required>
      </label>
      <label>
        Antwort (case-insensitiv)
        <input type="text" name={`a_${index}`} bind:value={question.a} required>
      </label>
      <button type="button" class="btn btn-danger btn--small" on:click={() => removeQuestion(index)}>
        Frage {index + 1} entfernen
      </button>
    </fieldset>
  {/each}
  <button type="button" class="btn" on:click={addQuestion}>+ Frage hinzufügen</button>
</div>

<style>
  .q-row { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr) auto; align-items: end; gap: .5rem; margin: 0 0 .75rem; }
  .q-row legend { font-weight: 600; }
  @media (max-width: 640px) { .q-row { grid-template-columns: 1fr; } }
</style>
