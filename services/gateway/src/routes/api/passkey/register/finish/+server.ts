import { json, error } from '@sveltejs/kit';
import { clients } from '#lib/server/clients.js';
import type { RequestHandler } from './$types';

/**
 * POST /api/passkey/register/finish
 * Body: { challenge_id: string, credential: object, name?: string }
 * Requires authentication.
 */
export const POST: RequestHandler = async ({ request, locals }) => {
	if (!locals.session) error(401, 'Not authenticated');
	const body = await request.json();
	const credentialJson = new TextEncoder().encode(JSON.stringify(body));

	const res = await clients(locals.session.accessToken).passkey.passkeyFinishRegistration({
		userId: locals.session.userId,
		credentialJson,
		name: body.name ?? ''
	});
	return json({ passkey: res.passkey });
};
