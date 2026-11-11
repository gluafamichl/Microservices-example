<script lang="ts">
	import { enhance } from '$app/forms';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	async function registerPasskey() {
		// 1. Get options from server
		const beginRes = await fetch('/api/passkey/register/begin', { method: 'POST' });
		if (!beginRes.ok) { alert('Could not start passkey registration.'); return; }
		const options = await beginRes.json();

		// 2. Invoke the browser's WebAuthn API (via SimpleWebAuthn if installed, or native)
		let credential;
		try {
			const { startRegistration } = await import('@simplewebauthn/browser');
			credential = await startRegistration({ optionsJSON: options.options });
		} catch (e) {
			alert('Passkey creation cancelled or not supported.');
			return;
		}

		// 3. Send the result back to the server
		const name = prompt('Name this passkey (e.g. "MacBook Touch ID")', 'Passkey') ?? 'Passkey';
		const finishRes = await fetch('/api/passkey/register/finish', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ challenge_id: options.challenge_id, credential, name })
		});
		if (finishRes.ok) {
			window.location.reload();
		} else {
			alert('Passkey registration failed.');
		}
	}
</script>

<svelte:head><title>Passkeys</title></svelte:head>

<h1>Passkeys</h1>
<p>Passkeys let you sign in without a password using Face ID, Touch ID or a security key.</p>

<button type="button" onclick={registerPasskey}>Add a passkey</button>

{#if data.passkeys.length === 0}
	<p>No passkeys registered yet.</p>
{:else}
	<ul>
		{#each data.passkeys as pk}
			<li>
				<strong>{pk.name}</strong>
				<form method="POST" action="?/delete" use:enhance>
					<input type="hidden" name="passkey_id" value={pk.id} />
					<button type="submit">Remove</button>
				</form>
			</li>
		{/each}
	</ul>
{/if}
