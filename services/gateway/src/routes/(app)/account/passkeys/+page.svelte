<script lang="ts">
	import { enhance } from '$app/forms';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	let registerError = $state('');
	let registerBusy = $state(false);

	async function registerPasskey() {
		registerError = '';
		registerBusy = true;
		try {
			// 1. Get registration options from server
			const beginRes = await fetch('/api/passkey/register/begin', { method: 'POST' });
			if (!beginRes.ok) {
				registerError = beginRes.status === 401
					? 'You must be signed in to add a passkey.'
					: `Could not start registration (${beginRes.status}).`;
				return;
			}
			const envelope = await beginRes.json();

			// 2. Ask the browser / platform authenticator to create a credential
			const { startRegistration } = await import('@simplewebauthn/browser');
			let credential;
			try {
				credential = await startRegistration({ optionsJSON: envelope.options });
			} catch (e: unknown) {
				const msg = e instanceof Error ? e.message : String(e);
				registerError = msg.includes('cancel') || msg.includes('abort')
					? 'Passkey creation was cancelled.'
					: `Passkey creation failed: ${msg}`;
				return;
			}

			// 3. Send credential back to server for verification and storage
			const name = prompt('Name this passkey (e.g. "MacBook Touch ID")', 'Passkey') ?? 'Passkey';
			const finishRes = await fetch('/api/passkey/register/finish', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ challenge_id: envelope.challenge_id, credential, name })
			});
			if (finishRes.ok) {
				window.location.reload();
			} else {
				const text = await finishRes.text().catch(() => '');
				registerError = `Registration failed (${finishRes.status})${text ? ': ' + text : ''}.`;
			}
		} catch (e: unknown) {
			registerError = `Unexpected error: ${e instanceof Error ? e.message : String(e)}`;
		} finally {
			registerBusy = false;
		}
	}
</script>

<svelte:head><title>Passkeys</title></svelte:head>

<h1>Passkeys</h1>
<p>Passkeys let you sign in without a password using Face ID, Touch ID or a security key.</p>

<button type="button" onclick={registerPasskey} disabled={registerBusy}>
	{registerBusy ? 'Creating passkey…' : 'Add a passkey'}
</button>
{#if registerError}
	<p style="color:red">{registerError}</p>
{/if}

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
