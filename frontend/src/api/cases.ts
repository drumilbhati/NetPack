import { apiFetch } from "./client";

export async function fetchCases() {
	const response = await apiFetch(`/cases/`);
	if (!response.ok) {
		throw new Error("Failed to fetch cases");
	}
	return response.json();
}
