import React, { useState, useEffect } from "react";
import {
	Search as SearchIcon,
	ChevronDown,
	ChevronUp,
	Database,
} from "lucide-react";

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
	metadata: any;
}

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const Search: React.FC = () => {
	const [results, setResults] = useState<SearchResult[]>([]);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [expandedRow, setExpandedRow] = useState<number | null>(null);

	// Filters
	const [srcIp, setSrcIp] = useState("");
	const [dstIp, setDstIp] = useState("");
	const [protocol, setProtocol] = useState("");
	const [dnsQuery, setDnsQuery] = useState("");
	const [userAgent, setUserAgent] = useState("");

	// Pagination
	const [page, setPage] = useState(0);
	const pageSize = 50;

	const handleSearch = async (e?: React.FormEvent, resetPage = true) => {
		if (e) e.preventDefault();

		const currentPage = resetPage ? 0 : page;
		if (resetPage) setPage(0);

		setLoading(true);
		setError(null);

		try {
			const params = new URLSearchParams();
			if (srcIp) params.append("source_ip", srcIp);
			if (dstIp) params.append("destination_ip", dstIp);
			if (protocol) params.append("protocol", protocol.toUpperCase());
			if (dnsQuery) params.append("dns_query", dnsQuery);
			if (userAgent) params.append("user_agent", userAgent);

			params.append("size", pageSize.toString());
			params.append("from", (currentPage * pageSize).toString());

			const res = await fetch(`${BASE_URL}/search/?${params.toString()}`);
			if (!res.ok) throw new Error("Search failed");
			const data = await res.json();
			setResults(data);
		} catch (err: any) {
			setError(err.message);
		} finally {
			setLoading(false);
		}
	};

	useEffect(() => {
		if (page > 0) handleSearch(undefined, false);
	}, [page]);

	return (
		<div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
			{/* Search & Filter Bar */}
			<div className="card">
				<h3
					style={{
						marginTop: 0,
						display: "flex",
						alignItems: "center",
						gap: "0.5rem",
					}}
				>
					<SearchIcon size={20} /> Advanced Forensic Search
				</h3>
				<form onSubmit={(e) => handleSearch(e, true)}>
					<div
						style={{
							display: "grid",
							gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
							gap: "1rem",
							marginBottom: "1rem",
						}}
					>
						<div>
							<label
								style={{
									fontSize: "0.75rem",
									fontWeight: 700,
									textTransform: "uppercase",
								}}
							>
								Source IP
							</label>
							<input
								type="text"
								className="search-input"
								style={{ width: "100%" }}
								value={srcIp}
								onChange={(e) => setSrcIp(e.target.value)}
								placeholder="e.g. 192.168.1.1"
							/>
						</div>
						<div>
							<label
								style={{
									fontSize: "0.75rem",
									fontWeight: 700,
									textTransform: "uppercase",
								}}
							>
								Dest IP
							</label>
							<input
								type="text"
								className="search-input"
								style={{ width: "100%" }}
								value={dstIp}
								onChange={(e) => setDstIp(e.target.value)}
								placeholder="e.g. 8.8.8.8"
							/>
						</div>
						<div>
							<label
								style={{
									fontSize: "0.75rem",
									fontWeight: 700,
									textTransform: "uppercase",
								}}
							>
								Protocol
							</label>
							<select
								className="select-input"
								style={{ width: "100%" }}
								value={protocol}
								onChange={(e) => setProtocol(e.target.value)}
							>
								<option value="">All Protocols</option>
								<option value="TCP">TCP</option>
								<option value="UDP">UDP</option>
								<option value="HTTP">HTTP</option>
								<option value="DNS">DNS</option>
								<option value="FTP">FTP</option>
								<option value="SMTP">SMTP</option>
								<option value="SMB">SMB</option>
								<option value="ICMP">ICMP</option>
							</select>
						</div>
						<div>
							<label
								style={{
									fontSize: "0.75rem",
									fontWeight: 700,
									textTransform: "uppercase",
								}}
							>
								DNS/Domain
							</label>
							<input
								type="text"
								className="search-input"
								style={{ width: "100%" }}
								value={dnsQuery}
								onChange={(e) => setDnsQuery(e.target.value)}
								placeholder="e.g. example.com"
							/>
						</div>
					</div>
					<div
						style={{ display: "flex", justifyContent: "flex-end", gap: "1rem" }}
					>
						<button
							type="button"
							className="btn-primary"
							style={{ background: "var(--text-secondary)" }}
							onClick={() => {
								setSrcIp("");
								setDstIp("");
								setProtocol("");
								setDnsQuery("");
								setUserAgent("");
							}}
						>
							Clear
						</button>
						<button type="submit" className="btn-primary" disabled={loading}>
							{loading ? "Searching..." : "Perform Search"}
						</button>
					</div>
				</form>
			</div>

			{error && <div className="card text-red-500">Error: {error}</div>}

			{/* Results Table */}
			<div className="card" style={{ padding: 0 }}>
				<table style={{ tableLayout: "fixed" }}>
					<thead>
						<tr>
							<th style={{ width: "40px" }}></th>
							<th style={{ width: "180px" }}>Timestamp</th>
							<th>Source</th>
							<th>Destination</th>
							<th style={{ width: "100px" }}>Protocol</th>
							<th>Details</th>
						</tr>
					</thead>
					<tbody>
						{results.length === 0 ? (
							<tr>
								<td
									colSpan={6}
									style={{
										textAlign: "center",
										padding: "3rem",
										color: "var(--text-secondary)",
									}}
								>
									{loading
										? "Querying Elasticsearch clusters..."
										: "No records found. Use the filters above to search."}
								</td>
							</tr>
						) : (
							results.map((res, i) => (
								<React.Fragment key={i}>
									<tr
										style={{
											cursor: "pointer",
											background: expandedRow === i ? "#f9fafb" : "transparent",
										}}
										onClick={() => setExpandedRow(expandedRow === i ? null : i)}
									>
										<td style={{ textAlign: "center" }}>
											{expandedRow === i ? (
												<ChevronUp size={16} />
											) : (
												<ChevronDown size={16} />
											)}
										</td>
										<td style={{ fontSize: "0.75rem" }}>
											{new Date(res.timestamp).toLocaleString()}
										</td>
										<td
											style={{
												overflow: "hidden",
												textOverflow: "ellipsis",
												whiteSpace: "nowrap",
											}}
										>
											{res.source_ip}
											{res.source_port ? `:${res.source_port}` : ""}
										</td>
										<td
											style={{
												overflow: "hidden",
												textOverflow: "ellipsis",
												whiteSpace: "nowrap",
											}}
										>
											{res.destination_ip}
											{res.destination_port ? `:${res.destination_port}` : ""}
										</td>
										<td>
											<span
												style={{
													fontWeight: 600,
													color: "var(--primary-color)",
												}}
											>
												{res.protocol}
											</span>
										</td>
										<td
											style={{
												overflow: "hidden",
												textOverflow: "ellipsis",
												whiteSpace: "nowrap",
											}}
										>
											<div style={{ fontSize: "0.75rem" }}>
												{res.dns_query && (
													<span style={{ color: "#059669" }}>
														DNS: {res.dns_query}{" "}
													</span>
												)}
												{res.http_url && (
													<span style={{ color: "#2563eb" }}>
														URL: {res.http_url}{" "}
													</span>
												)}
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
									{expandedRow === i && (
										<tr>
											<td
												colSpan={6}
												style={{ padding: "1.5rem", background: "#f9fafb" }}
											>
												<div
													style={{
														display: "flex",
														gap: "1rem",
														alignItems: "flex-start",
													}}
												>
													<div style={{ flex: 1 }}>
														<h4
															style={{
																margin: "0 0 1rem 0",
																display: "flex",
																alignItems: "center",
																gap: "0.5rem",
															}}
														>
															<Database size={16} /> Raw Forensic Metadata
														</h4>
														<pre
															style={{
																background: "#1f2937",
																color: "#f3f4f6",
																padding: "1rem",
																borderRadius: "0.5rem",
																fontSize: "0.75rem",
																overflow: "auto",
																maxHeight: "300px",
															}}
														>
															{JSON.stringify(res.metadata, null, 2)}
														</pre>
													</div>
												</div>
											</td>
										</tr>
									)}
								</React.Fragment>
							))
						)}
					</tbody>
				</table>

				{/* Pagination Controls */}
				{results.length > 0 && (
					<div
						style={{
							padding: "1rem",
							borderTop: "1px solid var(--border-color)",
							display: "flex",
							justifyContent: "space-between",
							alignItems: "center",
						}}
					>
						<span
							style={{ fontSize: "0.875rem", color: "var(--text-secondary)" }}
						>
							Showing {results.length} records
						</span>
						<div style={{ display: "flex", gap: "0.5rem" }}>
							<button
								className="btn-primary btn-sm"
								disabled={page === 0}
								onClick={() => setPage(page - 1)}
							>
								Previous
							</button>
							<span
								style={{
									display: "flex",
									alignItems: "center",
									padding: "0 1rem",
								}}
							>
								Page {page + 1}
							</span>
							<button
								className="btn-primary btn-sm"
								disabled={results.length < pageSize}
								onClick={() => setPage(page + 1)}
							>
								Next
							</button>
						</div>
					</div>
				)}
			</div>
		</div>
	);
};

export default Search;
