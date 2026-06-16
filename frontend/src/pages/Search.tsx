import React, { useState } from "react";

interface SearchResult {
	timestamp: string;
	source_ip: string;
	destination_ip: string;
	source_port?: number;
	destination_port?: number;
	protocol: string;
	http_url?: string;
	dns_query?: string;
	payload_signatures?: string[];
}

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const Search: React.FC = () => {
	const [query, setQuery] = useState("");
	const [results, setResults] = useState<SearchResult[]>([]);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const handleSearch = async (e: React.FormEvent) => {
		e.preventDefault();
		if (!query) return;

		setLoading(true);
		setError(null);

		try {
			// Basic heuristic: if it looks like an IP, search by IP. Otherwise, search by protocol or keyword.
			let url = `${BASE_URL}/search/`;
			const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;

			if (ipRegex.test(query)) {
				url += `?source_ip=${query}`;
			} else if (
				[
					"TCP",
					"UDP",
					"HTTP",
					"DNS",
					"FTP",
					"SMTP",
					"SMB",
					"SMB2",
					"ICMP",
				].includes(query.toUpperCase())
			) {
				url += `?protocol=${query.toUpperCase()}`;
			} else {
				// Fallback to DNS query or User agent
				url += `?dns_query=${query}`;
			}

			const res = await fetch(url);
			if (!res.ok) throw new Error("Search failed");
			const data = await res.json();
			setResults(data);
		} catch (err: any) {
			setError(err.message);
		} finally {
			setLoading(false);
		}
	};

	return (
		<div>
			<div className="card">
				<h3 style={{ marginTop: 0 }}>Network Search</h3>
				<form onSubmit={handleSearch} className="search-container">
					<input
						type="text"
						placeholder="Search by IP (e.g. 10.0.0.1), Protocol (e.g. HTTP), or Domain..."
						className="search-input"
						value={query}
						onChange={(e) => setQuery(e.target.value)}
					/>
					<button type="submit" className="btn-primary" disabled={loading}>
						{loading ? "Searching..." : "Search"}
					</button>
				</form>
			</div>

			{error && (
				<div className="card" style={{ color: "red", marginTop: "1rem" }}>
					{error}
				</div>
			)}

			<div className="card" style={{ marginTop: "1.5rem", padding: 0 }}>
				<table>
					<thead>
						<tr>
							<th>Timestamp</th>
							<th>Source</th>
							<th>Destination</th>
							<th>Protocol</th>
							<th>Details</th>
						</tr>
					</thead>
					<tbody>
						{results.length === 0 ? (
							<tr>
								<td
									colSpan={5}
									style={{
										textAlign: "center",
										color: "var(--text-secondary)",
										padding: "2rem",
									}}
								>
									{loading
										? "Performing deep search..."
										: "No results to display. Try searching for an IP or Protocol."}
								</td>
							</tr>
						) : (
							results.map((res, i) => (
								<tr key={i}>
									<td style={{ fontSize: "0.75rem" }}>
										{new Date(res.timestamp).toLocaleString()}
									</td>
									<td>
										{res.source_ip}
										{res.source_port ? `:${res.source_port}` : ""}
									</td>
									<td>
										{res.destination_ip}
										{res.destination_port ? `:${res.destination_port}` : ""}
									</td>
									<td>
										<span
											style={{ fontWeight: 600, color: "var(--primary-color)" }}
										>
											{res.protocol}
										</span>
									</td>
									<td>
										<div style={{ fontSize: "0.75rem" }}>
											{res.http_url && (
												<div title={res.http_url}>
													URL: {res.http_url.substring(0, 40)}...
												</div>
											)}
											{res.dns_query && <div>DNS: {res.dns_query}</div>}
											{res.payload_signatures &&
												res.payload_signatures.map((s) => (
													<span
														key={s}
														style={{
															color: "#ef4444",
															fontWeight: 600,
															marginRight: "0.5rem",
														}}
													>
														[{s}]
													</span>
												))}
										</div>
									</td>
								</tr>
							))
						)}
					</tbody>
				</table>
			</div>
		</div>
	);
};

export default Search;
