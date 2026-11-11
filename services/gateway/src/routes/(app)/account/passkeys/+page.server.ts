import { fail } from '@sveltejs/kit';
import { api } from '#lib/server/clients.js';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals }) => {
	const res = await api(locals).passkey.listPasskeys({ userId: locals.session!.userId });
	return { passkeys: res.passkeys };
};

export const actions: Actions = {
	delete: async ({ request, locals }) => {
		const data = await request.formData();
		const passkeyId = String(data.get('passkey_id') ?? '');
		if (!passkeyId) return fail(400, { message: 'passkey_id required' });
		await api(locals).passkey.deletePasskey({ userId: locals.session!.userId, passkeyId });
		return { deleted: true };
	}
};
