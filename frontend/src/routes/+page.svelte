<script lang="ts">
  import LoginForm from '$lib/components/LoginForm.svelte';
</script>

<svelte:head>
  <title>ArborPress – Login</title>
</svelte:head>

<main>
  <h1>ArborPress</h1>
  <LoginForm />
</main>

<style>
  main {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    font-family: system-ui, sans-serif;
  }

  h1 {
    font-size: 2rem;
    margin-bottom: 2rem;
    letter-spacing: -0.02em;
  }
</style>
