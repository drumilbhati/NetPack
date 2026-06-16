import React, { useEffect, useState } from "react";
import { Clock, AlertTriangle, FileUp, Activity } from "lucide-react";

interface TimelineEvent {
	id: string;
	title: string;
	timestamp: string;
	type: "evidence" | "alert" | "session";
	severity?: string;
	protocol?: string;
	source?: string;
}

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const Timeline: React.FC = () => {
	const [events, setEvents] = useState<TimelineEvent[]>([]);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		fetch(`${BASE_URL}/timeline/`)
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

	if (loading) return <div className="card">Loading temporal view...</div>;
	if (error) return <div className="card text-red-500">Error: {error}</div>;

	return (
		<div className="timeline-container">
			{events.length === 0 ? (
				<div className="card">No temporal data available yet.</div>
			) : (
				events.map((event) => (
					<div key={`${event.type}-${event.id}`} className="timeline-item">
						<div className="timeline-icon">{getIcon(event.type)}</div>
						<div className="timeline-content">
							<div className="timeline-header">
								<span className="timeline-title">{event.title}</span>
								<span className="timeline-time">
									{new Date(event.timestamp).toLocaleString()}
								</span>
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
									</>
								)}
							</div>
						</div>
					</div>
				))
			)}
		</div>
	);
};

export default Timeline;
