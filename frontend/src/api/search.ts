import { type SearchResult } from "../types";

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export interface SearchParams {
	case_id?: string;
	source_ip?: string;
	destination_ip?: string;
	source_port?: number;
	destination_port?: number;
	protocol?: string;
	user_agent?: string;
	http_host?: string;
	tls_sni?: string;
	dns_query?: string;
	start_time?: string;
	end_time?: string;
	is_anomaly?: boolean;
	size?: number;
	from?: number;
}

export const searchPackets = async (
	params: SearchParams,
): Promise<SearchResult[]> => {
	const query = new URLSearchParams();

	Object.entries(params).forEach(([key, value]) => {
		if (value !== undefined && value !== "") {
			query.append(key, String(value));
		}
	});

	const response = await fetch(`${BASE_URL}/search/?${query.toString()}`);
	if (!response.ok) {
		const errorData = await response.json().catch(() => ({}));
		throw new Error(errorData.detail || "Failed to fetch search results");
	}
	return response.json();
};
