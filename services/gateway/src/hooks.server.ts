import { redirect } from '@sveltejs/kit';
import type { Handle } from '@sveltejs/kit/hooks';
import { resolveSession } from '#lib/server/session.js';

const publicPaths = [
	'/login',
	'/signup',
	'/verify',
	'/forgot',
	'/reset',
	// Passkey authentication is public (no session required to start or finish login)
	'/api/passkey/authenticate'
];

export const handle: Handle = async ({ event, resolve }) => {
	event.locals.session = await resolveSession(event.cookies);

	const { pathname, search } = event.url;
	const isPublic = publicPaths.some((p) => pathname === p || pathname.startsWith(`${p}/`));
	if (!event.locals.session && !isPublic) {
		redirect(303, `/login?next=${encodeURIComponent(pathname + search)}`);
	}
	return resolve(event);
};
