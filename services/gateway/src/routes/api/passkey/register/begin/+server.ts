import { json, error } from '@sveltejs/kit';
import { clients } from '#lib/server/clients.js';
import type { RequestHandler } from './$types';

/**
 * POST /api/passkey/register/begin
 * Requires authentication. Returns the PublicKeyCredentialCreationOptions envelope.
 */
export const POST: RequestHandler = async ({ locals }) => {
	if (!locals.session) error(401, 'Not authenticated');
	const res = await clients(locals.session.accessToken).passkey.passkeyBeginRegistration({
		userId: locals.session.userId
	});
	return json(JSON.parse(new TextDecoder().decode(res.optionsJson)));
};
