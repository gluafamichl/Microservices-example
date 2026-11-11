import { json } from '@sveltejs/kit';
import { clients } from '#lib/server/clients.js';
import type { RequestHandler } from './$types';

/**
 * POST /api/passkey/authenticate/begin
 * Body: { username?: string }
 * Returns the PublicKeyCredentialRequestOptions envelope (challenge_id + options).
 * This endpoint is public — no access token required.
 */
export const POST: RequestHandler = async ({ request }) => {
	const body = await request.json().catch(() => ({}));
	const res = await clients().passkey.passkeyBeginAuthentication({
		username: body.username ?? ''
	});
	return json(JSON.parse(new TextDecoder().decode(res.optionsJson)));
};
