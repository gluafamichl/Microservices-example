import { json, error } from '@sveltejs/kit';
import { api } from '#lib/server/clients.js';
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

	const res = await api(locals).passkey.passkeyFinishRegistration({
		userId: locals.session.userId,
		credentialJson,
		name: body.name ?? ''
	});

	// Protobuf Timestamps contain bigint fields that JSON.stringify cannot handle.
	// Return only the fields the client actually needs.
	const pk = res.passkey;
	return json({
		passkey: pk
			? {
					id: pk.id,
					name: pk.name,
					createdAt: pk.createdAt ? new Date(Number(pk.createdAt.seconds) * 1000).toISOString() : null
				}
			: null
	});
};
