import { apiFetch } from "./client";

export async function fetchCases(limit: number = 50, offset: number = 0) {
	const response = await apiFetch(`/cases/?limit=${limit}&offset=${offset}`);
	if (!response.ok) {
		throw new Error("Failed to fetch cases");
	}
	return response.json();
}

export async function closeCase(caseId: string) {
	const response = await apiFetch(`/cases/${caseId}/close`, {
		method: "PATCH",
	});
	if (!response.ok) {
		const errorData = await response.json().catch(() => ({}));
		throw new Error(errorData.detail || "Failed to close case");
	}
	return response.json();
}
