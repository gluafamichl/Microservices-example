import { json, error } from '@sveltejs/kit';
import { api } from '#lib/server/clients.js';
import type { RequestHandler } from './$types';

/**
 * POST /api/passkey/register/begin
 * Requires authentication. Returns the PublicKeyCredentialCreationOptions envelope.
 */
export const POST: RequestHandler = async ({ locals }) => {
	if (!locals.session) error(401, 'Not authenticated');
	const res = await api(locals).passkey.passkeyBeginRegistration({
		userId: locals.session.userId
	});
	return json(JSON.parse(new TextDecoder().decode(res.optionsJson)));
};
