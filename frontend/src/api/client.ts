const BASE_URL = import.meta.env.VITE_API_BASE_URL || "";
const TOKEN_KEY = "netpack_access_token";
const USER_KEY = "netpack_user";

export interface StoredUser {
	id: string;
	email: string;
	display_name: string;
	role: string;
	is_active: boolean;
}

export function getAccessToken(): string | null {
	return localStorage.getItem(TOKEN_KEY);
}

export function getStoredUser(): StoredUser | null {
	const raw = localStorage.getItem(USER_KEY);
	if (!raw) return null;
	try {
		return JSON.parse(raw) as StoredUser;
	} catch {
		return null;
	}
}

export function setAuthState(token: string, user: StoredUser) {
	localStorage.setItem(TOKEN_KEY, token);
	localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearAuthState() {
	localStorage.removeItem(TOKEN_KEY);
	localStorage.removeItem(USER_KEY);
}

export async function apiFetch(
	path: string,
	options: RequestInit = {},
): Promise<Response> {
	const headers = new Headers(options.headers || {});
	const token = getAccessToken();
	if (token) {
		headers.set("Authorization", `Bearer ${token}`);
	}

	if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
		headers.set("Content-Type", "application/json");
	}

	const normalizedBase = BASE_URL.replace(/\/$/, "");
	const normalizedPath = path.startsWith("/") ? path : `/${path}`;
	const url = normalizedBase ? `${normalizedBase}${normalizedPath}` : normalizedPath;

	return fetch(url, {
		...options,
		headers,
	});
}

export { BASE_URL };
