import { json } from '@sveltejs/kit';
import { clients } from '#lib/server/clients.js';
import { setTokens } from '#lib/server/session.js';
import type { RequestHandler } from './$types';

/**
 * POST /api/passkey/authenticate/finish
 * Body: { challenge_id: string, assertion: object }
 * On success: sets session cookies and returns { ok: true }.
 * This endpoint is public — no access token required.
 */
export const POST: RequestHandler = async ({ request, cookies }) => {
	const body = await request.json();
	const assertionJson = new TextEncoder().encode(JSON.stringify(body));

	const res = await clients().passkey.passkeyFinishAuthentication({ assertionJson });
	if (!res.tokens) throw new Error('passkey authentication returned no tokens');
	setTokens(cookies, res.tokens);
	return json({ ok: true });
};
