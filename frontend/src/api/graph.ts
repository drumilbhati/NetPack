import { apiFetch } from "./client";

export async function fetchGraphData() {
	const response = await apiFetch(`/graph/`);
	if (!response.ok) {
		throw new Error("Failed to fetch graph data");
	}
	return response.json();
}
