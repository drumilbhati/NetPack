import React, { useEffect, useState } from "react";
import { CheckCircle, XCircle, Eye, ChevronDown, ChevronUp } from "lucide-react";

import { apiFetch } from "../api/client";
import Loader from "../components/Loader";

interface Alert {
	id: string;
	title: string;
	severity: string;
	status: string;
	source: string;
	created_at: string;
	explanation: any;
	flow_reference: any;
}

const Alerts: React.FC = () => {
	const [alerts, setAlerts] = useState<Alert[]>([]);
	const [filterSeverity, setFilterSeverity] = useState("");
	const [filterStatus, setFilterStatus] = useState("open");
	const [loading, setLoading] = useState(true);
	const [expandedRow, setExpandedRow] = useState<string | null>(null);

	useEffect(() => {
		const fetchAlerts = async () => {
			setLoading(true);
			try {
				let url = `/alerts/?status=${filterStatus}`;
				if (filterSeverity) url += `&severity=${filterSeverity}`;

				const res = await apiFetch(url);
				const data = await res.json();
				setAlerts(data);
			} catch (err) {
				console.error("Failed to fetch alerts:", err);
			} finally {
				setLoading(false);
			}
		};

		fetchAlerts();
	}, [filterSeverity, filterStatus]);

	const updateStatus = async (alertId: string, newStatus: string) => {
		try {
			const res = await apiFetch(`/alerts/${alertId}/status`, {
				method: "PATCH",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ status: newStatus }),
			});
			if (res.ok) {
				setAlerts((prevAlerts) =>
					prevAlerts.map((a) =>
						a.id === alertId ? { ...a, status: newStatus } : a,
					),
				);
			}
		} catch (err) {
			console.error("Failed to update alert status:", err);
		}
	};

	const getSeverityClass = (severity: string) => {
		return `severity-${severity.toLowerCase()}`;
	};

	return (
		<div>
			<div className="alerts-filter-bar">
				<div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
					<label style={{ fontSize: "0.875rem", fontWeight: 600 }}>
						Status:
					</label>
					<select
						className="select-input"
						value={filterStatus}
						onChange={(e) => setFilterStatus(e.target.value)}
					>
						<option value="">All Statuses</option>
						<option value="open">Open</option>
						<option value="investigating">Investigating</option>
						<option value="confirmed">Confirmed</option>
						<option value="false_positive">False Positive</option>
						<option value="closed">Closed</option>
					</select>
				</div>
				<div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
					<label style={{ fontSize: "0.875rem", fontWeight: 600 }}>
						Severity:
					</label>
					<select
						className="select-input"
						value={filterSeverity}
						onChange={(e) => setFilterSeverity(e.target.value)}
					>
						<option value="">All Severities</option>
						<option value="high">High</option>
						<option value="medium">Medium</option>
						<option value="low">Low</option>
					</select>
				</div>
			</div>

			<div className="card" style={{ padding: 0 }}>
				<div className="table-responsive">
					<table>
						<thead>
							<tr>
								<th style={{ width: "60px" }} />
								<th>Alert Title</th>
								<th>Severity</th>
								<th>Status</th>
								<th>Detected At</th>
								<th>Actions</th>
							</tr>
						</thead>
						<tbody>
							{loading ? (
								<tr>
									<td
										colSpan={6}
										style={{ textAlign: "center", padding: "3rem" }}
									>
										<Loader message="Gathering anomalies" />
									</td>
								</tr>
							) : alerts.length === 0 ? (
								<tr>
									<td
										colSpan={6}
										style={{
											textAlign: "center",
											padding: "3rem",
											color: "var(--text-secondary)",
										}}
									>
										No alerts found.
									</td>
								</tr>
							) : (
								alerts.map((alert) => {
									const isExpanded = expandedRow === alert.id;
									return (
										<React.Fragment key={alert.id}>
											<tr
												style={{ cursor: "pointer", background: isExpanded ? "#f9fafb" : "transparent" }}
												onClick={() => setExpandedRow(isExpanded ? null : alert.id)}
											>
												<td style={{ textAlign: "center", padding: "1.25rem 0.5rem" }}>
													{isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
												</td>
												<td>
													<div style={{ fontWeight: 600 }}>{alert.title}</div>
													<div
														style={{
															fontSize: "0.75rem",
															color: "var(--text-secondary)",
														}}
													>
														Source: {alert.source}
													</div>
												</td>
												<td>
													<span className={getSeverityClass(alert.severity)}>
														{alert.severity.toUpperCase()}
													</span>
												</td>
												<td>
													<span className={`status-badge status-${alert.status}`}>
														{alert.status.replace("_", " ")}
													</span>
												</td>
												<td style={{ whiteSpace: "nowrap" }}>{new Date(alert.created_at).toLocaleString()}</td>
												<td onClick={(e) => e.stopPropagation()}>
													<div className="alert-actions">
														{alert.status === "open" && (
															<button
																className="btn-primary btn-sm"
																onClick={() =>
																	updateStatus(alert.id, "investigating")
																}
																title="Start Investigating"
															>
																<Eye size={16} />
															</button>
														)}
														{(alert.status === "open" ||
															alert.status === "investigating") && (
															<>
																<button
																	className="btn-primary btn-sm"
																	style={{ background: "#10b981" }}
																	onClick={() => updateStatus(alert.id, "confirmed")}
																	title="Confirm Alert"
																>
																	<CheckCircle size={16} />
																</button>
																<button
																	className="btn-primary btn-sm"
																	style={{ background: "#6b7280" }}
																	onClick={() =>
																		updateStatus(alert.id, "false_positive")
																	}
																	title="Mark as False Positive"
																>
																	<XCircle size={16} />
																</button>
															</>
														)}
													</div>
												</td>
											</tr>
											{isExpanded && (
												<tr>
													<td colSpan={6} style={{ padding: "1.5rem", background: "#f9fafb" }}>
														<div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: "2rem" }}>
															<div>
																<h4 style={{ margin: "0 0 1rem 0" }}>Explanation</h4>
																<div style={{
																	background: "white",
																	padding: "1rem",
																	borderRadius: "0.375rem",
																	border: "1px solid var(--border-color)",
																	fontSize: "0.875rem",
																	lineHeight: 1.6
																}}>
																	{alert.explanation?.reason ? (
																		<>
																			<p style={{ margin: "0 0 0.5rem 0" }}>
																				<strong>Reason:</strong> {alert.explanation.reason}
																			</p>
																			{alert.explanation.confidence !== undefined && (
																				<p style={{ margin: 0 }}>
																					<strong>Confidence:</strong> {(alert.explanation.confidence * 100).toFixed(1)}%
																				</p>
																			)}
																		</>
																	) : (
																		<p style={{ margin: 0, color: "var(--text-secondary)" }}>
																			{typeof alert.explanation === 'string' 
																				? alert.explanation 
																				: "No detailed explanation provided by the detection engine."}
																		</p>
																	)}
																</div>
															</div>
															<div>
																<h4 style={{ margin: "0 0 1rem 0" }}>Flow Reference</h4>
																<div style={{
																	background: "white",
																	padding: "1rem",
																	borderRadius: "0.375rem",
																	border: "1px solid var(--border-color)",
																	fontSize: "0.875rem",
																	lineHeight: 1.6
																}}>
																	{alert.flow_reference && typeof alert.flow_reference === 'object' && Object.keys(alert.flow_reference).length > 0 ? (
																		<div style={{ display: "grid", gridTemplateColumns: "1fr", gap: "0.5rem" }}>
																			{Object.entries(alert.flow_reference).map(([key, value]) => (
																				<div key={key}>
																					<strong style={{ textTransform: "capitalize" }}>{key.replace(/_/g, ' ')}:</strong> {String(value)}
																				</div>
																			))}
																		</div>
																	) : (
																		<p style={{ margin: 0, color: "var(--text-secondary)" }}>
																			{typeof alert.flow_reference === 'string' && alert.flow_reference
																				? alert.flow_reference 
																				: "No specific flow reference provided."}
																		</p>
																	)}
																</div>
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
			</div>
		</div>
	);
};

export default Alerts;
