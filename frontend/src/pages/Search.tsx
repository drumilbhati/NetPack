import React, { useState } from "react";
import {
	ChevronDown,
	ChevronUp,
	Database,
	Search as SearchIcon,
} from "lucide-react";

import { searchPackets } from "../api/search";
import { type SearchResult } from "../types";
import JsonView from "../components/JsonView";

type FilterState = {
	caseId: string;
	sourceIp: string;
	destinationIp: string;
	sourcePort: string;
	destinationPort: string;
	protocol: string;
	dnsQuery: string;
	userAgent: string;
	httpHost: string;
	tlsSni: string;
	startTime: string;
	endTime: string;
	anomalyOnly: boolean;
};

const DEFAULT_FILTERS: FilterState = {
	caseId: "",
	sourceIp: "",
	destinationIp: "",
	sourcePort: "",
	destinationPort: "",
	protocol: "",
	dnsQuery: "",
	userAgent: "",
	httpHost: "",
	tlsSni: "",
	startTime: "",
	endTime: "",
	anomalyOnly: false,
};

const pageSize = 25;

const protocolOptions = [
	"",
	"TCP",
	"UDP",
	"HTTP",
	"DNS",
	"TLS",
	"FTP",
	"SMTP",
	"SMB",
	"ICMP",
];

const Search: React.FC = () => {
	const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);
	const [results, setResults] = useState<SearchResult[]>([]);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [expandedRow, setExpandedRow] = useState<number | null>(null);
	const [page, setPage] = useState(0);

	const executeSearch = async (nextPage = 0, nextFilters = filters) => {
		setLoading(true);
		setError(null);
		setExpandedRow(null);

		try {
			const query = await searchPackets({
				case_id: nextFilters.caseId.trim() || undefined,
				source_ip: nextFilters.sourceIp.trim() || undefined,
				destination_ip: nextFilters.destinationIp.trim() || undefined,
				source_port: nextFilters.sourcePort.trim()
					? Number(nextFilters.sourcePort)
					: undefined,
				destination_port: nextFilters.destinationPort.trim()
					? Number(nextFilters.destinationPort)
					: undefined,
				protocol: nextFilters.protocol.trim() || undefined,
				dns_query: nextFilters.dnsQuery.trim() || undefined,
				user_agent: nextFilters.userAgent.trim() || undefined,
				http_host: nextFilters.httpHost.trim() || undefined,
				tls_sni: nextFilters.tlsSni.trim() || undefined,
				start_time: nextFilters.startTime.trim() || undefined,
				end_time: nextFilters.endTime.trim() || undefined,
				is_anomaly: nextFilters.anomalyOnly ? true : undefined,
				size: pageSize,
				from: nextPage * pageSize,
			});

			setResults(query);
			setPage(nextPage);
		} catch (requestError) {
			setError(
				requestError instanceof Error ? requestError.message : "Search failed",
			);
		} finally {
			setLoading(false);
		}
	};

	const handleSubmit = (event: React.FormEvent) => {
		event.preventDefault();
		void executeSearch(0, filters);
	};

	const handleClear = () => {
		setFilters(DEFAULT_FILTERS);
		setResults([]);
		setExpandedRow(null);
		setPage(0);
		setError(null);
	};

	const formatBytes = (value?: number) => {
		if (value === undefined || value === null) return "—";
		if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(2)} MB`;
		if (value >= 1024) return `${(value / 1024).toFixed(2)} KB`;
		return `${value} B`;
	};

	const formatTimestamp = (value?: string) => {
		if (!value) return "—";
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
	};

	const displaySignalTags = (result: SearchResult) => {
		const tags: Array<{ label: string; color: string }> = [];

		if (result.dns_query)
			tags.push({ label: `DNS: ${result.dns_query}`, color: "#059669" });
		if (result.http_url)
			tags.push({ label: `URL: ${result.http_url}`, color: "#2563eb" });
		if (result.http_host)
			tags.push({ label: `Host: ${result.http_host}`, color: "#7c3aed" });
		if (result.tls_sni)
			tags.push({ label: `SNI: ${result.tls_sni}`, color: "#0f766e" });
		if (result.is_anomaly) tags.push({ label: "Anomaly", color: "#dc2626" });
		(result.payload_signatures || []).forEach((signature) => {
			tags.push({ label: `[${signature}]`, color: "#ef4444" });
		});

		return tags;
	};

	const detailRows = (result: SearchResult) => [
		["Case ID", result.case_id],
		["Evidence ID", result.evidence_id],
		["SHA-256", result.sha256],
		["HTTP URL", result.http_url],
		["HTTP Host", result.http_host],
		["HTTP User-Agent", result.http_user_agent],
		["TLS SNI", result.tls_sni],
		["DNS Query", result.dns_query],
		["FTP Command", result.ftp_command],
		["SMTP Command", result.smtp_command],
		["SMB Command", result.smb_command],
		["Bytes Sent", formatBytes(result.bytes_sent)],
		["Bytes Received", formatBytes(result.bytes_received)],
		[
			"Duration",
			result.duration !== undefined ? `${result.duration.toFixed(3)}s` : "—",
		],
		[
			"Packet Count",
			result.packet_count !== undefined ? String(result.packet_count) : "—",
		],
		[
			"Anomaly Score",
			result.anomaly_score !== undefined ? String(result.anomaly_score) : "—",
		],
		[
			"Anomaly Flag",
			result.is_anomaly === undefined
				? "—"
				: result.is_anomaly
					? "true"
					: "false",
		],
	];

	return (
		<div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
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
				<form onSubmit={handleSubmit} style={{ marginTop: "1rem" }}>
					<div
						style={{
							display: "grid",
							gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))",
							gap: "1rem 1.5rem",
							marginBottom: "1.5rem",
						}}
					>
						{[
							{
								label: "Case ID",
								value: filters.caseId,
								setter: (value: string) =>
									setFilters((prev) => ({ ...prev, caseId: value })),
							},
							{
								label: "Source IP",
								value: filters.sourceIp,
								setter: (value: string) =>
									setFilters((prev) => ({ ...prev, sourceIp: value })),
							},
							{
								label: "Destination IP",
								value: filters.destinationIp,
								setter: (value: string) =>
									setFilters((prev) => ({ ...prev, destinationIp: value })),
							},
							{
								label: "Source Port",
								value: filters.sourcePort,
								inputType: "number",
								setter: (value: string) =>
									setFilters((prev) => ({ ...prev, sourcePort: value })),
							},
							{
								label: "Destination Port",
								value: filters.destinationPort,
								inputType: "number",
								setter: (value: string) =>
									setFilters((prev) => ({ ...prev, destinationPort: value })),
							},
							{
								label: "DNS Query",
								value: filters.dnsQuery,
								setter: (value: string) =>
									setFilters((prev) => ({ ...prev, dnsQuery: value })),
							},
							{
								label: "HTTP User-Agent",
								value: filters.userAgent,
								setter: (value: string) =>
									setFilters((prev) => ({ ...prev, userAgent: value })),
							},
							{
								label: "HTTP Host",
								value: filters.httpHost,
								setter: (value: string) =>
									setFilters((prev) => ({ ...prev, httpHost: value })),
							},
							{
								label: "TLS SNI",
								value: filters.tlsSni,
								setter: (value: string) =>
									setFilters((prev) => ({ ...prev, tlsSni: value })),
							},
						].map((field) => (
							<div key={field.label} style={{ maxWidth: "300px" }}>
								<label
									style={{
										fontSize: "0.7rem",
										fontWeight: 700,
										color: "var(--text-secondary)",
										textTransform: "uppercase",
										display: "block",
										marginBottom: "0.4rem",
										letterSpacing: "0.025em"
									}}
								>
									{field.label}
								</label>
								<input
									type={field.inputType ?? "text"}
									className="search-input"
									style={{ width: "100%", height: "34px", fontSize: "0.85rem" }}
									value={field.value}
									onChange={(event) => field.setter(event.target.value)}
								/>
							</div>
						))}

						<div style={{ maxWidth: "300px" }}>
							<label
								style={{
									fontSize: "0.7rem",
									fontWeight: 700,
									color: "var(--text-secondary)",
									textTransform: "uppercase",
									display: "block",
									marginBottom: "0.4rem",
									letterSpacing: "0.025em"
								}}
							>
								Protocol
							</label>
							<select
								className="select-input"
								style={{ width: "100%", height: "34px", fontSize: "0.85rem" }}
								value={filters.protocol}
								onChange={(event) =>
									setFilters((prev) => ({
										...prev,
										protocol: event.target.value,
									}))
								}
							>
								{protocolOptions.map((option) => (
									<option key={option || "all"} value={option}>
										{option || "All Protocols"}
									</option>
								))}
							</select>
						</div>

						<div style={{ maxWidth: "300px" }}>
							<label
								style={{
									fontSize: "0.7rem",
									fontWeight: 700,
									color: "var(--text-secondary)",
									textTransform: "uppercase",
									display: "block",
									marginBottom: "0.4rem",
									letterSpacing: "0.025em"
								}}
							>
								Start Time
							</label>
							<input
								type="datetime-local"
								className="search-input"
								style={{ width: "100%", height: "34px", fontSize: "0.85rem" }}
								value={filters.startTime}
								onChange={(event) =>
									setFilters((prev) => ({
										...prev,
										startTime: event.target.value,
									}))
								}
							/>
						</div>

						<div style={{ maxWidth: "300px" }}>
							<label
								style={{
									fontSize: "0.7rem",
									fontWeight: 700,
									color: "var(--text-secondary)",
									textTransform: "uppercase",
									display: "block",
									marginBottom: "0.4rem",
									letterSpacing: "0.025em"
								}}
							>
								End Time
							</label>
							<input
								type="datetime-local"
								className="search-input"
								style={{ width: "100%", height: "34px", fontSize: "0.85rem" }}
								value={filters.endTime}
								onChange={(event) =>
									setFilters((prev) => ({
										...prev,
										endTime: event.target.value,
									}))
								}
							/>
						</div>

						<div style={{ display: "flex", alignItems: "flex-end", paddingBottom: "6px" }}>
							<label
								style={{
									display: "flex",
									alignItems: "center",
									gap: "0.5rem",
									cursor: "pointer",
								}}
							>
								<input
									type="checkbox"
									style={{ width: "16px", height: "16px" }}
									checked={filters.anomalyOnly}
									onChange={(event) =>
										setFilters((prev) => ({
											...prev,
											anomalyOnly: event.target.checked,
										}))
									}
								/>
								<span style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--text-color)" }}>
									Anomaly only
								</span>
							</label>
						</div>
					</div>

					<div
						style={{ 
							display: "flex", 
							justifyContent: "flex-end", 
							gap: "1rem",
							paddingTop: "0.75rem",
							borderTop: "1px solid var(--border-color)"
						}}
					>
						<button
							type="button"
							className="btn-primary"
							style={{ background: "var(--text-secondary)" }}
							onClick={handleClear}
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

			<div className="card" style={{ padding: 0 }}>
				<div className="table-responsive">
					<table style={{ tableLayout: "fixed", minWidth: "1200px" }}>
						<thead>
							<tr>
								<th style={{ width: "60px" }} />
								<th style={{ width: "180px" }}>Timestamp</th>
								<th style={{ width: "260px" }}>Case / Evidence</th>
								<th style={{ width: "220px" }}>Source</th>
								<th style={{ width: "220px" }}>Destination</th>
								<th style={{ width: "100px" }}>Protocol</th>
								<th>Signals</th>
							</tr>
						</thead>
						<tbody>
							{loading && results.length === 0 ? (
								<tr>
									<td
										colSpan={7}
										style={{ textAlign: "center", padding: "3rem" }}
									>
										Loading search results...
									</td>
								</tr>
							) : results.length === 0 ? (
								<tr>
									<td
										colSpan={7}
										style={{
											textAlign: "center",
											padding: "3rem",
											color: "var(--text-secondary)",
										}}
									>
										No records found. Adjust the filters above to search.
									</td>
								</tr>
							) : (
								results.map((result, index) => {
									const rowKey = `${result.evidence_id ?? "evidence"}-${result.timestamp ?? index}-${index}`;
									const isExpanded = expandedRow === index;
									const tags = displaySignalTags(result);
									const rowHighlight = result.is_anomaly
										? "#fef2f2"
										: "transparent";

									return (
										<React.Fragment key={rowKey}>
											<tr
												style={{
													cursor: "pointer",
													background: isExpanded ? "#f9fafb" : rowHighlight,
													verticalAlign: "top"
												}}
												onClick={() => {
													setExpandedRow(isExpanded ? null : index);
												}}
											>
												<td style={{ textAlign: "center", padding: "1.25rem 0.5rem" }}>
													{isExpanded ? (
														<ChevronUp size={16} />
													) : (
														<ChevronDown size={16} />
													)}
												</td>
												<td style={{ fontSize: "0.75rem", padding: "1.25rem 1rem" }}>
													{formatTimestamp(result.timestamp)}
												</td>
												<td style={{ padding: "1rem" }}>
													<div className="text-truncate" style={{ fontWeight: 600, maxWidth: "220px" }} title={result.case_id}>
														{result.case_id ?? "—"}
													</div>
													<div
														className="text-truncate"
														style={{
															color: "var(--text-secondary)",
															fontSize: "0.75rem",
															maxWidth: "220px"
														}}
														title={result.evidence_id}
													>
														{result.evidence_id ?? "No evidence ID"}
													</div>
												</td>
												<td
													style={{
														overflow: "hidden",
														textOverflow: "ellipsis",
														whiteSpace: "nowrap",
														padding: "1.25rem 1rem"
													}}
												>
													{result.source_ip ?? "—"}
													{result.source_port ? `:${result.source_port}` : ""}
												</td>
												<td
													style={{
														overflow: "hidden",
														textOverflow: "ellipsis",
														whiteSpace: "nowrap",
														padding: "1.25rem 1rem"
													}}
												>
													{result.destination_ip ?? "—"}
													{result.destination_port
														? `:${result.destination_port}`
														: ""}
												</td>
												<td style={{ padding: "1.25rem 1rem" }}>
													<span
														style={{
															fontWeight: 700,
															color: "var(--primary-color)",
														}}
													>
														{result.protocol ?? "—"}
													</span>
												</td>
												<td
													style={{ overflow: "hidden", textOverflow: "ellipsis", padding: "1rem" }}
												>
													<div
														style={{
															display: "flex",
															flexWrap: "wrap",
															gap: "0.35rem",
														}}
													>
														{tags.length > 0 ? (
															tags.map((tag) => (
																<span
																	key={`${rowKey}-${tag.label}`}
																	style={{
																		background: `${tag.color}1A`,
																		color: tag.color,
																		padding: "0.15rem 0.4rem",
																		borderRadius: "999px",
																		fontSize: "0.7rem",
																		fontWeight: 700,
																	}}
																>
																	{tag.label}
																</span>
															))
														) : (
															<span style={{ color: "var(--text-secondary)" }}>
																No indicators
															</span>
														)}
													</div>
												</td>
											</tr>
											{isExpanded && (
												<tr>
													<td
														colSpan={7}
														style={{ padding: "1.5rem", background: "#f9fafb" }}
													>
														<div
															style={{
																display: "grid",
																gap: "2rem",
																gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
															}}
														>
															<div>
																<h4
																	style={{
																		margin: "0 0 1rem 0",
																		display: "flex",
																		alignItems: "center",
																		gap: "0.5rem",
																	}}
																>
																	<Database size={16} /> Result Details
																</h4>
																<div
																	style={{
																		display: "grid",
																		gridTemplateColumns:
																			"repeat(auto-fit, minmax(140px, 1fr))",
																		gap: "0.75rem",
																	}}
																>
																	{detailRows(result).map(([label, value]) => (
																		<div key={`${rowKey}-${label}`}>
																			<div
																				style={{
																					fontSize: "0.7rem",
																					color: "var(--text-secondary)",
																					textTransform: "uppercase",
																					fontWeight: 700,
																				}}
																			>
																				{label}
																			</div>
																			<div
																				className="text-break"
																				style={{
																					fontSize: "0.875rem",
																				}}
																			>
																				{value ?? "—"}
																			</div>
																		</div>
																	))}
																</div>
															</div>
															<div style={{ minWidth: 0 }}>
																<h4 style={{ margin: "0 0 1rem 0" }}>
																	Raw Metadata
																</h4>
																<JsonView data={result.metadata ?? {}} maxHeight="320px" />
															</div>
														</div>
													</td>
												</tr>
											)}
										</React.Fragment>
									);
								})
							)}
						</tbody>
					</table>
				</div>

				{results.length > 0 && (
					<div
						style={{
							padding: "1rem",
							borderTop: "1px solid var(--border-color)",
							display: "flex",
							justifyContent: "space-between",
							alignItems: "center",
							gap: "1rem",
						}}
					>
						<span
							style={{ fontSize: "0.875rem", color: "var(--text-secondary)" }}
						>
							Showing {results.length} records on page {page + 1}
						</span>
						<div style={{ display: "flex", gap: "0.5rem" }}>
							<button
								className="btn-primary btn-sm"
								disabled={page === 0 || loading}
								onClick={() => void executeSearch(page - 1, filters)}
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
								disabled={results.length < pageSize || loading}
								onClick={() => void executeSearch(page + 1, filters)}
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
