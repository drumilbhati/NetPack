import React, { useEffect, useState } from "react";
import { CheckCircle, XCircle, Eye } from "lucide-react";

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

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const Alerts: React.FC = () => {
	const [alerts, setAlerts] = useState<Alert[]>([]);
	const [filterSeverity, setFilterSeverity] = useState("");
	const [filterStatus, setFilterStatus] = useState("open");
	const [loading, setLoading] = useState(true);

	const fetchAlerts = async () => {
		setLoading(true);
		try {
			let url = `${BASE_URL}/alerts/?status=${filterStatus}`;
			if (filterSeverity) url += `&severity=${filterSeverity}`;

			const res = await fetch(url);
			const data = await res.json();
			setAlerts(data);
		} catch (err) {
			console.error("Failed to fetch alerts:", err);
		} finally {
			setLoading(false);
		}
	};

	useEffect(() => {
		fetchAlerts();
	}, [filterSeverity, filterStatus]);

	const updateStatus = async (alertId: string, newStatus: string) => {
		try {
			const res = await fetch(`${BASE_URL}/alerts/${alertId}/status`, {
				method: "PATCH",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ status: newStatus }),
			});
			if (res.ok) {
				setAlerts(
					alerts.map((a) =>
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

			<div className="card">
				{loading ? (
					<p>Loading alerts...</p>
				) : alerts.length === 0 ? (
					<p>No alerts found matching the filters.</p>
				) : (
					<table>
						<thead>
							<tr>
								<th>Alert Title</th>
								<th>Severity</th>
								<th>Status</th>
								<th>Detected At</th>
								<th>Actions</th>
							</tr>
						</thead>
						<tbody>
							{alerts.map((alert) => (
								<tr key={alert.id}>
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
									<td>{new Date(alert.created_at).toLocaleString()}</td>
									<td>
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
							))}
						</tbody>
					</table>
				)}
			</div>
		</div>
	);
};

export default Alerts;
