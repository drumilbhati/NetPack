import React, { useEffect, useState } from "react";
import Loader from "../components/Loader";

import { apiFetch } from "../api/client";
import {
	Clock,
	AlertTriangle,
	FileUp,
	Activity,
	ChevronDown,
	ChevronUp,
	Database,
} from "lucide-react";
import JsonView from "../components/JsonView";

interface TimelineEvent {
	id: string;
	title: string;
	timestamp: string;
	type: "evidence" | "alert" | "session";
	severity?: string;
	protocol?: string;
	source?: string;
	bytes_sent?: number;
	bytes_received?: number;
	source_ip?: string;
	destination_ip?: string;
	source_port?: number;
	destination_port?: number;
	is_anomaly?: boolean;
	explanation?: any;
	flow_reference?: any;
	raw?: any;
}

const Timeline: React.FC = () => {
	const [events, setEvents] = useState<TimelineEvent[]>([]);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [expandedId, setExpandedId] = useState<string | null>(null);

	useEffect(() => {
		apiFetch(`/timeline/`)
			.then((res) => {
				if (!res.ok) throw new Error("Failed to fetch timeline");
				return res.json();
			})
			.then((data) => {
				setEvents(data);
				setLoading(false);
			})
			.catch((err) => {
				console.error(err);
				setError(err.message);
				setLoading(false);
			});
	}, []);

	const getIcon = (type: string) => {
		switch (type) {
			case "evidence":
				return (
					<FileUp
						size={20}
						className="text-primary"
						style={{ color: "#2563eb" }}
					/>
				);
			case "alert":
				return (
					<AlertTriangle
						size={20}
						className="text-red-500"
						style={{ color: "#ef4444" }}
					/>
				);
			case "session":
				return (
					<Activity
						size={20}
						className="text-green-500"
						style={{ color: "#10b981" }}
					/>
				);
			default:
				return <Clock size={20} />;
		}
	};

	const getSeverityClass = (severity?: string) => {
		if (!severity) return "";
		return `severity-${severity.toLowerCase()}`;
	};

	const formatBytes = (bytes?: number) => {
		if (bytes === undefined || bytes === null) return "0 B";
		if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
		if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
		return `${bytes} B`;
	};

	if (loading) return <Loader message="Reconstructing TCP streams" />;
	if (error) return <div className="card text-red-500">Error: {error}</div>;

	return (
		<div className="timeline-container">
			{events.length === 0 ? (
				<div className="card">No temporal data available yet.</div>
			) : (
				events.map((event) => {
					const isExpanded = expandedId === event.id;
					return (
						<div
							key={`${event.type}-${event.id}`}
							className="timeline-item"
							style={{
								flexDirection: "column",
								cursor: "pointer",
								background: isExpanded ? "#f9fafb" : "#fff",
							}}
							onClick={() => setExpandedId(isExpanded ? null : event.id)}
						>
							<div style={{ display: "flex", gap: "1rem", width: "100%" }}>
								<div className="timeline-icon">{getIcon(event.type)}</div>
								<div className="timeline-content">
									<div className="timeline-header">
										<span className="timeline-title">{event.title}</span>
										<div
											style={{
												display: "flex",
												alignItems: "center",
												gap: "1rem",
											}}
										>
											<span className="timeline-time">
												{new Date(event.timestamp).toLocaleString()}
											</span>
											{isExpanded ? (
												<ChevronUp size={16} />
											) : (
												<ChevronDown size={16} />
											)}
										</div>
									</div>
									<div className="timeline-details">
										<span
											style={{
												textTransform: "uppercase",
												fontWeight: 700,
												fontSize: "0.7rem",
											}}
										>
											{event.type}
										</span>
										{event.type === "alert" && (
											<>
												<span className={getSeverityClass(event.severity)}>
													{event.severity}
												</span>
												<span>Source: {event.source}</span>
											</>
										)}
										{event.type === "session" && (
											<>
												<span>Protocol: {event.protocol}</span>
												{event.is_anomaly && (
													<span className="severity-high">ANOMALY</span>
												)}
											</>
										)}
									</div>
								</div>
							</div>

							{isExpanded && (
								<div
									style={{
										marginTop: "1rem",
										padding: "1rem",
										borderTop: "1px solid var(--border-color)",
										width: "100%",
									}}
									onClick={(e) => e.stopPropagation()}
								>
									<div
										style={{
											display: "grid",
											gridTemplateColumns: "1fr 1fr",
											gap: "2rem",
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
												<Database size={16} /> Forensic Context
											</h4>
											<div
												style={{
													display: "grid",
													gridTemplateColumns: "1fr 1fr",
													gap: "0.75rem",
													fontSize: "0.875rem",
												}}
											>
												{event.type === "session" && (
													<>
														<div>
															<strong>Source:</strong> {event.source_ip}:
															{event.source_port}
														</div>
														<div>
															<strong>Destination:</strong> {event.destination_ip}:
															{event.destination_port}
														</div>
														<div>
															<strong>Bytes Sent:</strong>{" "}
															{formatBytes(event.bytes_sent)}
														</div>
														<div>
															<strong>Bytes Received:</strong>{" "}
															{formatBytes(event.bytes_received)}
														</div>
													</>
												)}
												{event.type === "alert" && (
													<>
														<div style={{ gridColumn: "span 2" }}>
															<strong>Explanation:</strong>{" "}
															{JSON.stringify(event.explanation)}
														</div>
														<div style={{ gridColumn: "span 2" }}>
															<strong>Flow Ref:</strong>{" "}
															{JSON.stringify(event.flow_reference)}
														</div>
													</>
												)}
												<div>
													<strong>Event ID:</strong> {event.id}
												</div>
											</div>
										</div>
										<div style={{ minWidth: 0 }}>
											<h4 style={{ margin: "0 0 1rem 0" }}>Raw JSON</h4>
											<JsonView data={event.raw || event} maxHeight="200px" />
										</div>
									</div>
								</div>
							)}
						</div>
					);
				})
			)}
		</div>
	);
};

export default Timeline;
