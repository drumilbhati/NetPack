import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Shield, Clock, HardDrive, ArrowLeft } from "lucide-react";

interface Evidence {
	id: string;
	original_filename: string;
	status: string;
	byte_size: number;
	uploaded_at: string;
	parsed_at?: string;
	sha256: string;
}

interface CustodyLog {
	id: string;
	action: string;
	occurred_at: string;
	actor_name: string;
	details: any;
}

interface CaseDetailsData {
	case: {
		id: string;
		case_number: string;
		title: string;
		description: string;
		status: string;
		created_at: string;
	};
	evidence: Evidence[];
	custody_logs: CustodyLog[];
}

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const CaseDetails: React.FC = () => {
	const { caseId } = useParams<{ caseId: string }>();
	const [data, setData] = useState<CaseDetailsData | null>(null);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		if (!caseId) return;

		fetch(`${BASE_URL}/cases/${caseId}/details`)
			.then((res) => {
				if (!res.ok) throw new Error("Failed to fetch case details");
				return res.json();
			})
			.then((data) => {
				setData(data);
				setLoading(false);
			})
			.catch((err) => {
				setError(err.message);
				setLoading(false);
			});
	}, [caseId]);

	if (loading) return <div className="card">Loading case details...</div>;
	if (error || !data)
		return (
			<div className="card text-red-500">Error: {error || "No data found"}</div>
		);

	const { case: caseInfo, evidence, custody_logs } = data;

	return (
		<div style={{ display: "flex", flexDirection: "column", gap: "2rem" }}>
			{/* Header */}
			<div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
				<Link
					to="/cases"
					className="btn-primary btn-sm"
					style={{
						background: "var(--text-secondary)",
						display: "flex",
						alignItems: "center",
						gap: "0.25rem",
					}}
				>
					<ArrowLeft size={16} /> Back
				</Link>
				<h2 style={{ margin: 0 }}>Case: {caseInfo.case_number}</h2>
				<span
					className={`status-badge status-${caseInfo.status}`}
					style={{ fontSize: "0.75rem" }}
				>
					{caseInfo.status}
				</span>
			</div>

			{/* Case Info Summary */}
			<div className="card">
				<h3 style={{ marginTop: 0 }}>{caseInfo.title}</h3>
				<p style={{ color: "var(--text-secondary)" }}>
					{caseInfo.description || "No description provided."}
				</p>
				<div
					style={{
						display: "flex",
						gap: "2rem",
						fontSize: "0.875rem",
						marginTop: "1rem",
					}}
				>
					<div>
						<strong>Created:</strong>{" "}
						{new Date(caseInfo.created_at).toLocaleString()}
					</div>
					<div>
						<strong>Evidence Count:</strong> {evidence.length}
					</div>
				</div>
			</div>

			{/* Evidence Files */}
			<div className="card" style={{ padding: 0 }}>
				<div
					style={{
						padding: "1.5rem",
						borderBottom: "1px solid var(--border-color)",
					}}
				>
					<h3
						style={{
							margin: 0,
							display: "flex",
							alignItems: "center",
							gap: "0.5rem",
						}}
					>
						<HardDrive size={20} /> Evidence Files
					</h3>
				</div>
				<table>
					<thead>
						<tr>
							<th>Filename</th>
							<th>Size</th>
							<th>Status</th>
							<th>Uploaded At</th>
							<th>SHA-256 Hash</th>
						</tr>
					</thead>
					<tbody>
						{evidence.length === 0 ? (
							<tr>
								<td colSpan={5} style={{ textAlign: "center" }}>
									No evidence files associated.
								</td>
							</tr>
						) : (
							evidence.map((ev) => (
								<tr key={ev.id}>
									<td style={{ fontWeight: 600 }}>{ev.original_filename}</td>
									<td>{(ev.byte_size / (1024 * 1024)).toFixed(2)} MB</td>
									<td>
										<span className={`status-badge status-${ev.status}`}>
											{ev.status}
										</span>
									</td>
									<td>{new Date(ev.uploaded_at).toLocaleString()}</td>
									<td
										style={{
											fontSize: "0.7rem",
											color: "var(--text-secondary)",
										}}
									>
										{ev.sha256}
									</td>
								</tr>
							))
						)}
					</tbody>
				</table>
			</div>

			{/* Chain of Custody Audit Logs */}
			<div className="card" style={{ padding: 0 }}>
				<div
					style={{
						padding: "1.5rem",
						borderBottom: "1px solid var(--border-color)",
					}}
				>
					<h3
						style={{
							margin: 0,
							display: "flex",
							alignItems: "center",
							gap: "0.5rem",
						}}
					>
						<Shield size={20} /> Chain of Custody Audit
					</h3>
				</div>
				<div className="timeline-container" style={{ padding: "1.5rem" }}>
					{custody_logs.length === 0 ? (
						<p style={{ textAlign: "center", color: "var(--text-secondary)" }}>
							No custody events recorded.
						</p>
					) : (
						custody_logs.map((log) => (
							<div
								key={log.id}
								className="timeline-item"
								style={{ marginBottom: "1rem" }}
							>
								<div className="timeline-icon">
									<Clock size={18} />
								</div>
								<div className="timeline-content">
									<div className="timeline-header">
										<span
											className="timeline-title"
											style={{ textTransform: "capitalize" }}
										>
											{log.action}
										</span>
										<span className="timeline-time">
											{new Date(log.occurred_at).toLocaleString()}
										</span>
									</div>
									<div className="timeline-details">
										<span>Actor: {log.actor_name || "System"}</span>
										<span>Details: {JSON.stringify(log.details)}</span>
									</div>
								</div>
							</div>
						))
					)}
				</div>
			</div>
		</div>
	);
};

export default CaseDetails;
