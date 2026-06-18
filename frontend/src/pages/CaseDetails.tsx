import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { 
	Shield, 
	Clock, 
	HardDrive, 
	ArrowLeft, 
	Lock, 
	ShieldAlert, 
	AlertTriangle, 
	AlertCircle, 
	Info, 
	CheckCircle, 
	XCircle, 
	Eye, 
	ChevronDown, 
	ChevronUp, 
	Network, 
	TrendingUp, 
	Activity,
	Terminal
} from "lucide-react";
import Loader from "../components/Loader";
import JsonView from "../components/JsonView";

import { apiFetch } from "../api/client";
import { closeCase } from "../api/cases";
import { useAuth } from "../auth/AuthContext";

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

interface Alert {
	id: string;
	evidence_id: string;
	source: string;
	rule_or_model_id: string;
	severity: string;
	status: string;
	title: string;
	explanation: any;
	flow_reference: any;
	created_at: string;
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
	alerts: Alert[];
}

const CaseDetails: React.FC = () => {
	const { caseId } = useParams<{ caseId: string }>();
	const [data, setData] = useState<CaseDetailsData | null>(null);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [isClosing, setIsClosing] = useState(false);
	const [expandedAlerts, setExpandedAlerts] = useState<Record<string, boolean>>({});
	const [showRawAlert, setShowRawAlert] = useState<Record<string, boolean>>({});
	const [updatingAlertId, setUpdatingAlertId] = useState<string | null>(null);
	const { user } = useAuth();

	const fetchDetails = () => {
		if (!caseId) return;

		apiFetch(`/cases/${caseId}/details`)
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
	};

	useEffect(() => {
		fetchDetails();
	}, [caseId]);

	useEffect(() => {
		if (!data || !data.evidence) return;
		const hasActiveAnalysis = data.evidence.some(
			(ev) => ev.status === "registered" || ev.status === "parsing"
		);
		if (hasActiveAnalysis) {
			const timer = setInterval(() => {
				fetchDetails();
			}, 3000);
			return () => clearInterval(timer);
		}
	}, [data, caseId]);

	const handleCloseCase = async () => {
		if (!caseId || !window.confirm("Are you sure you want to close this case? This action cannot be undone and signifies the end of the investigation.")) {
			return;
		}

		setIsClosing(true);
		try {
			await closeCase(caseId);
			fetchDetails(); // Reload data to show updated status and new custody logs
		} catch (err) {
			console.error(err);
			alert(err instanceof Error ? err.message : "Failed to close case");
		} finally {
			setIsClosing(false);
		}
	};

	const handleUpdateAlertStatus = async (alertId: string, newStatus: string) => {
		setUpdatingAlertId(alertId);
		try {
			const res = await apiFetch(`/alerts/${alertId}/status`, {
				method: "PATCH",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ status: newStatus }),
			});
			if (res.ok) {
				fetchDetails(); // Reload details to reflect updated alert status
			} else {
				const errData = await res.json().catch(() => ({}));
				alert(errData.detail || "Failed to update alert status");
			}
		} catch (err) {
			console.error(err);
			alert("Failed to update alert status");
		} finally {
			setUpdatingAlertId(null);
		}
	};

	const toggleAlertExpand = (alertId: string) => {
		setExpandedAlerts(prev => ({
			...prev,
			[alertId]: !prev[alertId]
		}));
	};

	const toggleRawAlert = (alertId: string, event: React.MouseEvent) => {
		event.stopPropagation();
		setShowRawAlert(prev => ({
			...prev,
			[alertId]: !prev[alertId]
		}));
	};

	if (loading) return <Loader message="Investigating leads and parsing forensic alerts" />;
	if (error || !data)
		return (
			<div className="card text-red-500" style={{ padding: "2rem", textAlign: "center", color: "#ef4444", fontWeight: 600 }}>
				<ShieldAlert size={48} style={{ margin: "0 auto 1rem" }} />
				Error: {error || "No case data found"}
			</div>
		);

	const { case: caseInfo, evidence, custody_logs } = data;
	const alerts = data.alerts || [];
	const canCloseCase = caseInfo.status !== 'closed' && (user?.role === 'admin' || user?.role === 'investigator');

	// Threat level calculation
	const calculateThreatScoreAndLevel = (caseAlerts: Alert[]) => {
		if (!caseAlerts || caseAlerts.length === 0) {
			return { score: 0, level: "SAFE", color: "#10b981", bg: "#dcfce7", description: "No alerts or threat indicators have been flagged for this case environment." };
		}
		
		let score = 0;
		let hasCritical = false;
		let hasHigh = false;
		let hasMedium = false;
		let hasLow = false;
		
		caseAlerts.forEach(a => {
			const sev = a.severity.toLowerCase();
			if (sev === "critical") {
				score += 50;
				hasCritical = true;
			} else if (sev === "high") {
				score += 25;
				hasHigh = true;
			} else if (sev === "medium") {
				score += 10;
				hasMedium = true;
			} else {
				score += 5;
				hasLow = true;
			}
		});
		
		score = Math.min(score, 100);
		
		let level = "INFORMATIONAL";
		let color = "#3b82f6";
		let bg = "#dbeafe";
		let description = "Low-level system events and metadata logs monitored.";
		
		if (hasCritical) {
			level = "CRITICAL";
			color = "#ef4444";
			bg = "#fee2e2";
			description = "Severe active exploitation attempts or system compromise signatures detected. Immediate response required.";
		} else if (hasHigh) {
			level = "HIGH";
			color = "#f97316";
			bg = "#ffedd5";
			description = "Suspicious network channels, suspected interactive shells, or potential command access tunnels active.";
		} else if (hasMedium) {
			level = "MEDIUM";
			color = "#eab308";
			bg = "#fef9c3";
			description = "Statistical anomalies, abnormal traffic volumes, or potential host reconnaissance sweeps detected.";
		} else if (hasLow) {
			level = "LOW";
			color = "#3b82f6";
			bg = "#dbeafe";
			description = "Minor compliance violations, standard signature mismatches, or non-malicious anomalies.";
		}
		
		return { score, level, color, bg, description };
	};

	const { score: threatScore, level: threatLevel, color: threatColor, bg: threatBg, description: threatDesc } = calculateThreatScoreAndLevel(alerts);

	const getSeverityBadge = (severity: string) => {
		const sev = severity.toLowerCase();
		let color = "#3b82f6";
		let bg = "#dbeafe";
		let Icon = Info;
		
		if (sev === "critical") {
			color = "#ef4444";
			bg = "#fee2e2";
			Icon = ShieldAlert;
		} else if (sev === "high") {
			color = "#f97316";
			bg = "#ffedd5";
			Icon = AlertTriangle;
		} else if (sev === "medium") {
			color = "#eab308";
			bg = "#fef9c3";
			Icon = AlertCircle;
		}
		
		return (
			<span style={{
				display: "inline-flex",
				alignItems: "center",
				gap: "0.25rem",
				padding: "0.25rem 0.5rem",
				borderRadius: "0.25rem",
				fontSize: "0.7rem",
				fontWeight: 700,
				color: color,
				backgroundColor: bg,
				textTransform: "uppercase"
			}}>
				<Icon size={12} /> {severity}
			</span>
		);
	};

	const getAlertStatusBadge = (status: string) => {
		const st = status.toLowerCase();
		let color = "#6b7280";
		let bg = "#f3f4f6";
		
		if (st === "open") {
			color = "#ef4444";
			bg = "#fee2e2";
		} else if (st === "investigating") {
			color = "#f59e0b";
			bg = "#fef3c7";
		} else if (st === "confirmed") {
			color = "#10b981";
			bg = "#dcfce7";
		} else if (st === "false_positive") {
			color = "#6b7280";
			bg = "#e5e7eb";
		} else if (st === "closed") {
			color = "#1f2937";
			bg = "#e5e7eb";
		}
		
		return (
			<span style={{
				display: "inline-flex",
				alignItems: "center",
				padding: "0.2rem 0.5rem",
				borderRadius: "1rem",
				fontSize: "0.7rem",
				fontWeight: 600,
				color: color,
				backgroundColor: bg,
				textTransform: "uppercase",
				border: `1px solid ${color}33`
			}}>
				{status.replace("_", " ")}
			</span>
		);
	};

	const formatBytes = (bytes: number) => {
		if (bytes === 0 || !bytes) return "0 Bytes";
		const k = 1024;
		const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
	};

	const criticalAlertsCount = alerts.filter(a => a.severity.toLowerCase() === "critical").length;
	const highAlertsCount = alerts.filter(a => a.severity.toLowerCase() === "high").length;
	const mediumAlertsCount = alerts.filter(a => a.severity.toLowerCase() === "medium").length;
	const lowAlertsCount = alerts.filter(a => ["low", "info"].includes(a.severity.toLowerCase())).length;

	// Risk Vectors Analysis
	const hasExfil = alerts.some(a => 
		a.title.toLowerCase().includes("exfil") || 
		(a.explanation?.reason && a.explanation.reason.toLowerCase().includes("exfil")) ||
		(a.explanation?.pattern && a.explanation.pattern.toLowerCase().includes("exfil"))
	);
	const hasC2Channel = alerts.some(a => 
		a.title.toLowerCase().includes("c2") || a.title.toLowerCase().includes("beacon") ||
		(a.explanation?.reason && (a.explanation.reason.toLowerCase().includes("c2") || a.explanation.reason.toLowerCase().includes("beacon"))) ||
		(a.explanation?.pattern && (a.explanation.pattern.toLowerCase().includes("c2") || a.explanation.pattern.toLowerCase().includes("beacon")))
	);
	const hasPortScanning = alerts.some(a => 
		a.title.toLowerCase().includes("scan") || a.title.toLowerCase().includes("sweep") ||
		(a.explanation?.reason && (a.explanation.reason.toLowerCase().includes("scan") || a.explanation.reason.toLowerCase().includes("sweep")))
	);
	const hasAccessCrack = alerts.some(a => 
		a.title.toLowerCase().includes("brute") || a.title.toLowerCase().includes("credential") || a.title.toLowerCase().includes("dump") ||
		(a.explanation?.reason && (a.explanation.reason.toLowerCase().includes("brute") || a.explanation.reason.toLowerCase().includes("credential") || a.explanation.reason.toLowerCase().includes("dump")))
	);

	// Collect unique source and destination IPs flagged in alerts
	const suspectHosts = Array.from(new Set(alerts.map(a => a.flow_reference?.src_ip || a.flow_reference?.srcIp || a.flow_reference?.srcIp).filter(Boolean)));
	const externalThreatIPs = Array.from(new Set(alerts.map(a => a.flow_reference?.dst_ip || a.flow_reference?.dstIp || a.flow_reference?.dstIp).filter(Boolean)));

	return (
		<div style={{ display: "flex", flexDirection: "column", gap: "2rem", width: "100%" }}>
			{/* Header */}
			<div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
				<div style={{ display: "flex", alignItems: "center", gap: "1rem", flexWrap: "wrap" }}>
					<Link
						to="/cases"
						className="btn-primary btn-sm"
						style={{
							background: "var(--text-secondary)",
							display: "flex",
							alignItems: "center",
							gap: "0.25rem",
							padding: "0.4rem 0.8rem",
							textDecoration: "none",
							color: "white",
							borderRadius: "0.375rem",
							fontWeight: 500,
							fontSize: "0.875rem"
						}}
					>
						<ArrowLeft size={16} /> Back to Cases
					</Link>
					<h2 style={{ margin: 0, fontSize: "1.75rem", fontWeight: 700 }}>Case: {caseInfo.case_number}</h2>
					<span
						className={`status-badge status-${caseInfo.status}`}
						style={{ fontSize: "0.75rem", padding: "0.35rem 0.75rem", borderRadius: "1rem" }}
					>
						{caseInfo.status}
					</span>
					
					{/* Overall Threat Badge */}
					<span style={{
						display: "inline-flex",
						alignItems: "center",
						gap: "0.35rem",
						padding: "0.35rem 0.75rem",
						borderRadius: "1rem",
						fontSize: "0.75rem",
						fontWeight: 800,
						color: threatColor,
						backgroundColor: threatBg,
						border: `1px solid ${threatColor}44`
					}}>
						<ShieldAlert size={14} /> Threat Level: {threatLevel}
					</span>
				</div>
				{canCloseCase && (
					<button 
						className="btn-primary" 
						onClick={handleCloseCase} 
						disabled={isClosing}
						style={{ 
							background: "#ef4444", 
							display: "flex", 
							alignItems: "center", 
							gap: "0.5rem",
							padding: "0.5rem 1.25rem",
							border: "none",
							borderRadius: "0.375rem",
							color: "white",
							fontWeight: 600,
							cursor: "pointer",
							boxShadow: "0 2px 4px rgba(239, 68, 68, 0.2)"
						}}
					>
						<Lock size={16} /> {isClosing ? "Closing Case..." : "Close Investigation"}
					</button>
				)}
			</div>

			{/* Main Grid Content */}
			<div style={{
				display: "flex",
				flexWrap: "wrap",
				gap: "2rem",
				width: "100%"
			}}>
				{/* Left Side: Case Details, Alerts List, Evidence Files */}
				<div style={{
					flex: "2 1 600px",
					display: "flex",
					flexDirection: "column",
					gap: "2rem",
					minWidth: 0
				}}>
					{/* Case Description Card */}
					<div className="card" style={{ borderLeft: `5px solid ${threatColor}` }}>
						<div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.5rem" }}>
							<h3 style={{ marginTop: 0, fontSize: "1.25rem", fontWeight: 700 }}>{caseInfo.title}</h3>
							<span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
								<strong>Created:</strong> {new Date(caseInfo.created_at).toLocaleString()}
							</span>
						</div>
						<p style={{ color: "var(--text-secondary)", lineHeight: 1.6, margin: 0, fontSize: "0.95rem" }}>
							{caseInfo.description || "No description provided for this investigation."}
						</p>
					</div>

					{/* Forensic Intelligence & Fraud Scorecard */}
					<div className="card" style={{ padding: "1.5rem" }}>
						<h3 style={{ margin: "0 0 1rem 0", display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "1.25rem", fontWeight: 700 }}>
							<TrendingUp size={22} style={{ color: "var(--primary-color)" }} /> Forensic Risk & Fraud Intelligence
						</h3>
						<p style={{ fontSize: "0.9rem", color: "var(--text-secondary)", marginBottom: "1.5rem", lineHeight: 1.5 }}>
							Real-time analysis of decrypted flow behaviors, statistical outliers, and signature threat rules. This dashboard evaluates network forensic signals to identify anomalous active indicators, compromise risks, and fraudulent network behavior.
						</p>

						<div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "1.25rem", marginBottom: "1.5rem" }}>
							{/* Vector 1: Command & Control */}
							<div style={{ padding: "1rem", borderRadius: "0.5rem", border: "1px solid var(--border-color)", backgroundColor: hasC2Channel ? "#fee2e2" : "#f0fdf4" }}>
								<div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
									<strong style={{ fontSize: "0.85rem", color: hasC2Channel ? "#991b1b" : "#166534" }}>Command & Control (C2)</strong>
									{hasC2Channel ? <ShieldAlert size={16} style={{ color: "#ef4444" }} /> : <CheckCircle size={16} style={{ color: "#22c55e" }} />}
								</div>
								<span style={{
									display: "inline-block",
									padding: "0.15rem 0.4rem",
									borderRadius: "0.25rem",
									fontSize: "0.65rem",
									fontWeight: 700,
									color: hasC2Channel ? "white" : "#166534",
									backgroundColor: hasC2Channel ? "#ef4444" : "#bbf7d0",
									marginBottom: "0.5rem"
								}}>
									{hasC2Channel ? "ACTIVE CHANNEL DETECTED" : "NO THREAT DETECTED"}
								</span>
								<p style={{ fontSize: "0.75rem", margin: 0, color: hasC2Channel ? "#7f1d1d" : "#14532d", lineHeight: 1.4 }}>
									{hasC2Channel 
										? "Beaconing behavior patterns or active TCP/UDP channels identified connecting to suspicious external networks." 
										: "No suspicious persistent connections or command beacon patterns detected in flows."}
								</p>
							</div>

							{/* Vector 2: Data Exfiltration */}
							<div style={{ padding: "1rem", borderRadius: "0.5rem", border: "1px solid var(--border-color)", backgroundColor: hasExfil ? "#fee2e2" : "#f0fdf4" }}>
								<div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
									<strong style={{ fontSize: "0.85rem", color: hasExfil ? "#991b1b" : "#166534" }}>Data Exfiltration Fraud</strong>
									{hasExfil ? <ShieldAlert size={16} style={{ color: "#ef4444" }} /> : <CheckCircle size={16} style={{ color: "#22c55e" }} />}
								</div>
								<span style={{
									display: "inline-block",
									padding: "0.15rem 0.4rem",
									borderRadius: "0.25rem",
									fontSize: "0.65rem",
									fontWeight: 700,
									color: hasExfil ? "white" : "#166534",
									backgroundColor: hasExfil ? "#ef4444" : "#bbf7d0",
									marginBottom: "0.5rem"
								}}>
									{hasExfil ? "SUSPICIOUS TRANSFER DETECTED" : "NO THREAT DETECTED"}
								</span>
								<p style={{ fontSize: "0.75rem", margin: 0, color: hasExfil ? "#7f1d1d" : "#14532d", lineHeight: 1.4 }}>
									{hasExfil 
										? "High-volume data streams or outbound traffic spikes exceeding standard data thresholds indicate potential exfiltration." 
										: "Data transfer volumes remain within standard operational thresholds."}
								</p>
							</div>

							{/* Vector 3: Scanning & Recon */}
							<div style={{ padding: "1rem", borderRadius: "0.5rem", border: "1px solid var(--border-color)", backgroundColor: hasPortScanning ? "#fef9c3" : "#f0fdf4" }}>
								<div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
									<strong style={{ fontSize: "0.85rem", color: hasPortScanning ? "#854d0e" : "#166534" }}>Network Reconnaissance</strong>
									{hasPortScanning ? <AlertTriangle size={16} style={{ color: "#eab308" }} /> : <CheckCircle size={16} style={{ color: "#22c55e" }} />}
								</div>
								<span style={{
									display: "inline-block",
									padding: "0.15rem 0.4rem",
									borderRadius: "0.25rem",
									fontSize: "0.65rem",
									fontWeight: 700,
									color: hasPortScanning ? "white" : "#166534",
									backgroundColor: hasPortScanning ? "#eab308" : "#bbf7d0",
									marginBottom: "0.5rem"
								}}>
									{hasPortScanning ? "SCAN SWEEP MONITORING" : "NO THREAT DETECTED"}
								</span>
								<p style={{ fontSize: "0.75rem", margin: 0, color: hasPortScanning ? "#713f12" : "#14532d", lineHeight: 1.4 }}>
									{hasPortScanning 
										? "Rapid sequential connection attempts across multiple ports indicate active discovery sweeps or reconnaissance mapping." 
										: "Port scan sweeps or horizontal host scanning profiles not detected."}
								</p>
							</div>

							{/* Vector 4: Access Abuse */}
							<div style={{ padding: "1rem", borderRadius: "0.5rem", border: "1px solid var(--border-color)", backgroundColor: hasAccessCrack ? "#fee2e2" : "#f0fdf4" }}>
								<div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
									<strong style={{ fontSize: "0.85rem", color: hasAccessCrack ? "#991b1b" : "#166534" }}>Credential & Access Abuse</strong>
									{hasAccessCrack ? <ShieldAlert size={16} style={{ color: "#ef4444" }} /> : <CheckCircle size={16} style={{ color: "#22c55e" }} />}
								</div>
								<span style={{
									display: "inline-block",
									padding: "0.15rem 0.4rem",
									borderRadius: "0.25rem",
									fontSize: "0.65rem",
									fontWeight: 700,
									color: hasAccessCrack ? "white" : "#166534",
									backgroundColor: hasAccessCrack ? "#ef4444" : "#bbf7d0",
									marginBottom: "0.5rem"
								}}>
									{hasAccessCrack ? "CRACKING / ABUSE DETECTED" : "NO THREAT DETECTED"}
								</span>
								<p style={{ fontSize: "0.75rem", margin: 0, color: hasAccessCrack ? "#7f1d1d" : "#14532d", lineHeight: 1.4 }}>
									{hasAccessCrack 
										? "Multiple authentication failures, brute-force logs, or credential harvesting hashes flagged in traffic." 
										: "No standard password-spraying or brute-force behavior profiles detected."}
								</p>
							</div>
						</div>

						{/* Suspected Actors & Threat Connections */}
						{alerts.length > 0 && (
							<div style={{
								padding: "1rem",
								borderRadius: "0.5rem",
								backgroundColor: "var(--background-card)",
								border: "1px solid var(--border-color)",
								fontSize: "0.85rem",
								lineHeight: 1.5
							}}>
								<h4 style={{ margin: "0 0 0.75rem 0", fontSize: "0.95rem", fontWeight: 700, display: "flex", alignItems: "center", gap: "0.5rem" }}>
									<Network size={16} style={{ color: "var(--primary-color)" }} /> Network Forensic Indicators (IOCs)
								</h4>
								<div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "1rem" }}>
									<div>
										<strong>Suspected Source Hosts:</strong>
										{suspectHosts.length === 0 ? (
											<div style={{ color: "var(--text-secondary)", fontSize: "0.8rem", marginTop: "0.25rem" }}>None flagged</div>
										) : (
											<div style={{ display: "flex", flexWrap: "wrap", gap: "0.25rem", marginTop: "0.25rem" }}>
												{suspectHosts.map((ip, idx) => (
													<span key={idx} style={{ fontFamily: "monospace", fontSize: "0.75rem", padding: "0.15rem 0.4rem", borderRadius: "0.25rem", backgroundColor: "#fee2e2", color: "#b91c1c" }}>{ip}</span>
												))}
											</div>
										)}
									</div>
									<div>
										<strong>Flagged Target Destinations:</strong>
										{externalThreatIPs.length === 0 ? (
											<div style={{ color: "var(--text-secondary)", fontSize: "0.8rem", marginTop: "0.25rem" }}>None flagged</div>
										) : (
											<div style={{ display: "flex", flexWrap: "wrap", gap: "0.25rem", marginTop: "0.25rem" }}>
												{externalThreatIPs.map((ip, idx) => (
													<span key={idx} style={{ fontFamily: "monospace", fontSize: "0.75rem", padding: "0.15rem 0.4rem", borderRadius: "0.25rem", backgroundColor: "#ffedd5", color: "#c2410c" }}>{ip}</span>
												))}
											</div>
										)}
									</div>
								</div>
							</div>
						)}
					</div>

					{/* Security Threat & Fraud Analysis Section */}
					<div>
						<div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
							<h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "1.25rem", fontWeight: 700 }}>
								<ShieldAlert size={22} style={{ color: threatColor }} /> Security Risks & Forensic Alerts ({alerts.length})
							</h3>
							<span style={{ fontSize: "0.8rem", color: "var(--text-secondary)", fontWeight: 500 }}>
								Showing latest security events
							</span>
						</div>

						{alerts.length === 0 ? (
							<div className="card" style={{ padding: "3rem 1.5rem", textAlign: "center", color: "var(--text-secondary)" }}>
								<Shield size={36} style={{ margin: "0 auto 1rem", opacity: 0.5 }} />
								<p style={{ margin: 0, fontWeight: 500 }}>No security threats or anomalies have been flagged for this case.</p>
								<p style={{ margin: "0.25rem 0 0", fontSize: "0.8rem" }}>Upload network evidence and execute detection run to find anomalies.</p>
							</div>
						) : (
							<div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
								{alerts.map((alert) => {
									const isExpanded = !!expandedAlerts[alert.id];
									const isRawVisible = !!showRawAlert[alert.id];
									const isUpdating = updatingAlertId === alert.id;
									
									// Determine color by severity
									const sev = alert.severity.toLowerCase();
									let sevColor = "#3b82f6"; // blue
									if (sev === "critical") sevColor = "#ef4444"; // red
									else if (sev === "high") sevColor = "#f97316"; // orange
									else if (sev === "medium") sevColor = "#eab308"; // yellow
									
									return (
										<div 
											key={alert.id}
											className="card"
											style={{
												padding: 0,
												borderLeft: `6px solid ${sevColor}`,
												boxShadow: isExpanded ? "0 4px 12px rgba(0,0,0,0.08)" : "0 2px 4px rgba(0,0,0,0.04)",
												transition: "all 0.2s ease"
											}}
										>
											{/* Card Header (Clickable) */}
											<div 
												onClick={() => toggleAlertExpand(alert.id)}
												style={{
													padding: "1.25rem 1.5rem",
													cursor: "pointer",
													display: "flex",
													justifyContent: "space-between",
													alignItems: "center",
													backgroundColor: isExpanded ? "#f8fafc" : "transparent"
												}}
											>
												<div style={{ display: "flex", alignItems: "center", gap: "1rem", flex: 1, minWidth: 0 }}>
													{isExpanded ? <ChevronUp size={18} style={{ color: "var(--text-secondary)", flexShrink: 0 }} /> : <ChevronDown size={18} style={{ color: "var(--text-secondary)", flexShrink: 0 }} />}
													<div style={{ minWidth: 0, flex: 1 }}>
														<div style={{ fontWeight: 700, fontSize: "0.95rem", color: "var(--text-color)", display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
															{alert.title}
															{getSeverityBadge(alert.severity)}
														</div>
														<div style={{ fontSize: "0.75rem", color: "var(--text-secondary)", marginTop: "0.25rem", display: "flex", alignItems: "center", gap: "1rem" }}>
															<span><strong>Engine:</strong> {alert.source}</span>
															<span>•</span>
															<span><strong>Model/Rule ID:</strong> {alert.rule_or_model_id}</span>
															<span>•</span>
															<span>{new Date(alert.created_at).toLocaleString()}</span>
														</div>
													</div>
												</div>
												<div style={{ display: "flex", alignItems: "center", gap: "1rem", flexShrink: 0 }} onClick={(e) => e.stopPropagation()}>
													{getAlertStatusBadge(alert.status)}
													
													{/* Toggle Raw button */}
													<button 
														onClick={(e) => toggleRawAlert(alert.id, e)}
														style={{
															background: "none",
															border: "none",
															color: "var(--text-secondary)",
															cursor: "pointer",
															padding: "0.25rem",
															borderRadius: "0.25rem"
														}}
														title="View Raw JSON"
													>
														<Terminal size={16} />
													</button>
												</div>
											</div>

											{/* Expanded Content */}
											{isExpanded && (
												<div style={{
													padding: "1.5rem",
													borderTop: "1px solid var(--border-color)",
													backgroundColor: "#ffffff"
												}}>
													{/* Main Content Layout */}
													<div style={{
														display: "grid",
														gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
														gap: "1.5rem",
														marginBottom: "1.5rem"
													}}>
														{/* Threat Description & Explanation */}
														<div>
															<h4 style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem", fontWeight: 700, color: "var(--text-color)", display: "flex", alignItems: "center", gap: "0.25rem" }}>
																<Activity size={16} style={{ color: sevColor }} /> Analysis Explanation
															</h4>
															<div style={{
																backgroundColor: "#f8fafc",
																border: "1px solid #e2e8f0",
																borderRadius: "0.5rem",
																padding: "1rem",
																fontSize: "0.85rem",
																lineHeight: 1.6
															}}>
																{alert.explanation?.reason ? (
																	<p style={{ margin: 0, color: "#2d3748" }}>
																		{alert.explanation.reason}
																	</p>
																) : (
																	<p style={{ margin: 0, color: "var(--text-secondary)", fontStyle: "italic" }}>
																		{typeof alert.explanation === 'string' ? alert.explanation : "No detailed text description generated."}
																	</p>
																)}
															</div>
														</div>

														{/* Fraud & Anomaly Indicators (Pydantic payload) */}
														<div>
															<h4 style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem", fontWeight: 700, color: "var(--text-color)", display: "flex", alignItems: "center", gap: "0.25rem" }}>
																<TrendingUp size={16} style={{ color: sevColor }} /> Key Risk & Fraud Indicators
															</h4>
															
															<div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
																{/* Basic confidence score if exists */}
																{alert.explanation?.confidence !== undefined && (
																	<div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", padding: "0.4rem 0.75rem", backgroundColor: "#f9fafb", borderRadius: "0.25rem" }}>
																		<span style={{ color: "var(--text-secondary)" }}>Risk Confidence</span>
																		<strong style={{ color: alert.explanation.confidence > 0.8 ? "#ef4444" : "var(--text-color)" }}>
																			{(alert.explanation.confidence * 100).toFixed(1)}%
																		</strong>
																	</div>
																)}
																
																{/* Complex nested features */}
																{alert.explanation?.anomalous_features && typeof alert.explanation.anomalous_features === 'object' ? (
																	Object.entries(alert.explanation.anomalous_features).map(([key, val]) => (
																		<div key={key} style={{ display: "flex", flexDirection: "column", fontSize: "0.8rem", padding: "0.5rem 0.75rem", backgroundColor: "#f9fafb", borderRadius: "0.375rem", border: "1px solid #f3f4f6" }}>
																			<span style={{ color: "var(--text-secondary)", fontSize: "0.7rem", textTransform: "uppercase", fontWeight: 600 }}>
																				{key.replace(/_/g, " ")}
																			</span>
																			<span style={{ fontWeight: 700, marginTop: "0.15rem", color: "#1f2937" }}>
																				{Array.isArray(val) ? val.join(", ") : String(val)}
																			</span>
																		</div>
																	))
																) : (
																	<div style={{ color: "var(--text-secondary)", fontStyle: "italic", fontSize: "0.8rem" }}>
																		No statistical feature breakdown attached.
																	</div>
																)}
															</div>
														</div>
													</div>

													{/* Network Flow Visualization Card */}
													<div style={{ marginBottom: "1.5rem" }}>
														<h4 style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem", fontWeight: 700, color: "var(--text-color)", display: "flex", alignItems: "center", gap: "0.25rem" }}>
															<Network size={16} style={{ color: "var(--primary-color)" }} /> Network Connection Flow Path
														</h4>
														{alert.flow_reference ? (
															<div style={{
																display: "flex",
																flexDirection: "column",
																gap: "0.75rem",
																backgroundColor: "#f8fafc",
																border: "1px solid #e2e8f0",
																borderRadius: "0.5rem",
																padding: "1rem"
															}}>
																{/* Network Flow Diagram */}
																<div style={{
																	display: "flex",
																	alignItems: "center",
																	justifyContent: "space-between",
																	backgroundColor: "white",
																	padding: "0.75rem 1rem",
																	borderRadius: "0.375rem",
																	border: "1px solid #edf2f7",
																	marginBottom: "0.25rem"
																}}>
																	<div style={{ textAlign: "left" }}>
																		<div style={{ fontSize: "0.7rem", color: "var(--text-secondary)", fontWeight: 600 }}>SOURCE HOST</div>
																		<div style={{ fontWeight: 700, color: "#1a202c" }}>{alert.flow_reference.src_ip}</div>
																		<div style={{ fontSize: "0.75rem", color: "#4a5568" }}>Port: {alert.flow_reference.src_port}</div>
																	</div>
																	
																	<div style={{
																		flex: 1,
																		display: "flex",
																		flexDirection: "column",
																		alignItems: "center",
																		justifyContent: "center",
																		padding: "0 1.5rem"
																	}}>
																		<span style={{
																			fontSize: "0.7rem",
																			fontWeight: 700,
																			backgroundColor: "#ebf8ff",
																			color: "#2b6cb0",
																			padding: "0.15rem 0.5rem",
																			borderRadius: "0.25rem",
																			marginBottom: "0.25rem",
																			border: "1px solid #bee3f8"
																		}}>{alert.flow_reference.protocol}</span>
																		<div style={{
																			position: "relative",
																			width: "100%",
																			height: "2px",
																			backgroundColor: "#cbd5e0",
																			display: "flex",
																			alignItems: "center",
																			justifyContent: "center"
																		}}>
																			<div style={{
																				position: "absolute",
																				right: 0,
																				width: "6px",
																				height: "6px",
																				borderTop: "2px solid #a0aec0",
																				borderRight: "2px solid #a0aec0",
																				transform: "rotate(45deg)"
																			}}></div>
																		</div>
																	</div>
																	
																	<div style={{ textAlign: "right" }}>
																		<div style={{ fontSize: "0.7rem", color: "var(--text-secondary)", fontWeight: 600 }}>DESTINATION HOST</div>
																		<div style={{ fontWeight: 700, color: "#1a202c" }}>{alert.flow_reference.dst_ip}</div>
																		<div style={{ fontSize: "0.75rem", color: "#4a5568" }}>Port: {alert.flow_reference.dst_port}</div>
																	</div>
																</div>
																
																{/* Metrics Grid */}
																<div style={{
																	display: "grid",
																	gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
																	gap: "1rem",
																	fontSize: "0.8rem",
																	paddingTop: "0.25rem"
																}}>
																	{alert.flow_reference.bytes_sent !== undefined && (
																		<div>
																			<span style={{ color: "var(--text-secondary)" }}>Bytes Uploaded:</span>{" "}
																			<strong style={{ color: alert.flow_reference.bytes_sent > 10000000 ? "#ef4444" : "var(--text-color)" }}>
																				{formatBytes(alert.flow_reference.bytes_sent)}
																			</strong>
																		</div>
																	)}
																	{alert.flow_reference.bytes_received !== undefined && (
																		<div>
																			<span style={{ color: "var(--text-secondary)" }}>Bytes Downloaded:</span>{" "}
																			<strong>{formatBytes(alert.flow_reference.bytes_received)}</strong>
																		</div>
																	)}
																	{alert.flow_reference.packets !== undefined && (
																		<div>
																			<span style={{ color: "var(--text-secondary)" }}>Packets Transferred:</span>{" "}
																			<strong>{alert.flow_reference.packets}</strong>
																		</div>
																	)}
																	{alert.flow_reference.duration_ms !== undefined && (
																		<div>
																			<span style={{ color: "var(--text-secondary)" }}>Session Duration:</span>{" "}
																			<strong>{(alert.flow_reference.duration_ms / 1000).toFixed(2)}s</strong>
																		</div>
																	)}
																</div>
															</div>
														) : (
															<p style={{ color: "var(--text-secondary)", fontStyle: "italic", fontSize: "0.8rem" }}>
																No network flow telemetry attached.
															</p>
														)}
													</div>

													{/* Interactive Alert Triaging Controls */}
													<div style={{
														display: "flex",
														justifyContent: "space-between",
														alignItems: "center",
														borderTop: "1px solid var(--border-color)",
														paddingTop: "1rem",
														flexWrap: "wrap",
														gap: "1rem"
													}} onClick={(e) => e.stopPropagation()}>
														<span style={{ fontSize: "0.8rem", color: "var(--text-secondary)", fontWeight: 500 }}>
															Update Triage Status:
														</span>
														<div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
															{alert.status === "open" && (
																<button
																	className="btn-primary btn-sm"
																	disabled={isUpdating}
																	style={{ background: "#f59e0b", display: "flex", alignItems: "center", gap: "0.25rem", color: "white", border: "none", cursor: "pointer", borderRadius: "0.25rem", padding: "0.3rem 0.6rem" }}
																	onClick={() => handleUpdateAlertStatus(alert.id, "investigating")}
																>
																	<Eye size={14} /> Investigating
																</button>
															)}
															
															{(alert.status === "open" || alert.status === "investigating") && (
																<>
																	<button
																		className="btn-primary btn-sm"
																		disabled={isUpdating}
																		style={{ background: "#10b981", display: "flex", alignItems: "center", gap: "0.25rem", color: "white", border: "none", cursor: "pointer", borderRadius: "0.25rem", padding: "0.3rem 0.6rem" }}
																		onClick={() => handleUpdateAlertStatus(alert.id, "confirmed")}
																	>
																		<CheckCircle size={14} /> Confirm Vulnerability
																	</button>
																	<button
																		className="btn-primary btn-sm"
																		disabled={isUpdating}
																		style={{ background: "#6b7280", display: "flex", alignItems: "center", gap: "0.25rem", color: "white", border: "none", cursor: "pointer", borderRadius: "0.25rem", padding: "0.3rem 0.6rem" }}
																		onClick={() => handleUpdateAlertStatus(alert.id, "false_positive")}
																	>
																		<XCircle size={14} /> False Positive
																	</button>
																</>
															)}
															
															{alert.status !== "closed" && (
																<button
																	className="btn-primary btn-sm"
																	disabled={isUpdating}
																	style={{ background: "#1f2937", display: "flex", alignItems: "center", gap: "0.25rem", color: "white", border: "none", cursor: "pointer", borderRadius: "0.25rem", padding: "0.3rem 0.6rem" }}
																	onClick={() => handleUpdateAlertStatus(alert.id, "closed")}
																>
																	<Lock size={14} /> Resolve & Close
																</button>
															)}
														</div>
													</div>

													{/* Raw JSON Section (Collapsible) */}
													{isRawVisible && (
														<div style={{ marginTop: "1.5rem" }}>
															<h5 style={{ margin: "0 0 0.5rem 0", color: "var(--text-secondary)", fontSize: "0.8rem", textTransform: "uppercase", fontWeight: 700 }}>Raw Alert Metadata</h5>
															<JsonView data={alert} maxHeight="250px" />
														</div>
													)}
												</div>
											)}
										</div>
									);
								})}
							</div>
						)}
					</div>

					{/* Evidence Files List */}
					<div className="card" style={{ padding: 0 }}>
						<div
							style={{
								padding: "1.25rem 1.5rem",
								borderBottom: "1px solid var(--border-color)",
								display: "flex",
								alignItems: "center",
								justifyContent: "space-between"
							}}
						>
							<h3
								style={{
									margin: 0,
									display: "flex",
									alignItems: "center",
									gap: "0.5rem",
									fontSize: "1.15rem",
									fontWeight: 700
								}}
							>
								<HardDrive size={20} style={{ color: "var(--primary-color)" }} /> Forensic Evidence Files
							</h3>
							<span style={{
								fontSize: "0.75rem",
								backgroundColor: "#f3f4f6",
								padding: "0.2'rem 0.6rem",
								borderRadius: "0.25rem",
								fontWeight: 600
							}}>
								Total Size: {formatBytes(evidence.reduce((sum, item) => sum + item.byte_size, 0))}
							</span>
						</div>
						<div className="table-responsive">
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
											<td colSpan={5} style={{ textAlign: "center", padding: "2rem", color: "var(--text-secondary)" }}>
												No network captures or forensic logs uploaded yet.
											</td>
										</tr>
									) : (
										evidence.map((ev) => (
											<tr key={ev.id}>
												<td style={{ fontWeight: 600, color: "var(--text-color)" }}>{ev.original_filename}</td>
												<td>{formatBytes(ev.byte_size)}</td>
												<td>
													<span className={`status-badge status-${ev.status}`}>
														{ev.status}
													</span>
												</td>
												<td>{new Date(ev.uploaded_at).toLocaleString()}</td>
												<td
													className="text-break"
													style={{
														fontSize: "0.7rem",
														color: "var(--text-secondary)",
														fontFamily: "monospace",
														minWidth: "200px"
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
					</div>
				</div>

				{/* Right Side: Threat Scorecard, KPI Summary & Chain of Custody */}
				<div style={{
					flex: "1 1 300px",
					display: "flex",
					flexDirection: "column",
					gap: "2rem",
					minWidth: 0
				}}>
					{/* Threat Scorecard Card */}
					<div className="card" style={{ padding: "1.5rem" }}>
						<h3 style={{ marginTop: 0, fontSize: "1.15rem", fontWeight: 700, borderBottom: "1px solid var(--border-color)", paddingBottom: "0.75rem", marginBottom: "1rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
							<Activity size={18} style={{ color: threatColor }} /> Threat Assessment
						</h3>
						
						{/* Gauge display */}
						<div style={{ display: "flex", flexDirection: "column", alignItems: "center", margin: "1rem 0" }}>
							<div style={{
								width: "120px",
								height: "120px",
								borderRadius: "50%",
								border: `10px solid ${threatColor}22`,
								borderTop: `10px solid ${threatColor}`,
								display: "flex",
								flexDirection: "column",
								alignItems: "center",
								justifyContent: "center",
								boxShadow: "inset 0 2px 4px rgba(0,0,0,0.05)"
							}}>
								<span style={{ fontSize: "2rem", fontWeight: 800, color: threatColor }}>
									{threatScore}
								</span>
								<span style={{ fontSize: "0.65rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
									RISK SCORE
								</span>
							</div>
							
							<div style={{ marginTop: "1rem", textAlign: "center" }}>
								<strong style={{ fontSize: "1rem", color: threatColor, textTransform: "uppercase" }}>
									{threatLevel} SEVERITY
								</strong>
								<p style={{ margin: "0.25rem 0 0", fontSize: "0.8rem", color: "var(--text-secondary)", lineHeight: 1.4 }}>
									{threatDesc}
								</p>
							</div>
						</div>

						{/* Breakdown counters */}
						<div style={{
							display: "grid",
							gridTemplateColumns: "1fr 1fr",
							gap: "0.75rem",
							marginTop: "1.5rem",
							borderTop: "1px solid var(--border-color)",
							paddingTop: "1rem"
						}}>
							<div style={{ display: "flex", flexDirection: "column", padding: "0.5rem", backgroundColor: "#fee2e2", borderRadius: "0.375rem", textAlign: "center" }}>
								<span style={{ fontSize: "1.25rem", fontWeight: 800, color: "#ef4444" }}>{criticalAlertsCount}</span>
								<span style={{ fontSize: "0.65rem", fontWeight: 700, color: "#991b1b" }}>CRITICAL</span>
							</div>
							<div style={{ display: "flex", flexDirection: "column", padding: "0.5rem", backgroundColor: "#ffedd5", borderRadius: "0.375rem", textAlign: "center" }}>
								<span style={{ fontSize: "1.25rem", fontWeight: 800, color: "#f97316" }}>{highAlertsCount}</span>
								<span style={{ fontSize: "0.65rem", fontWeight: 700, color: "#9a3412" }}>HIGH RISK</span>
							</div>
							<div style={{ display: "flex", flexDirection: "column", padding: "0.5rem", backgroundColor: "#fef9c3", borderRadius: "0.375rem", textAlign: "center" }}>
								<span style={{ fontSize: "1.25rem", fontWeight: 800, color: "#eab308" }}>{mediumAlertsCount}</span>
								<span style={{ fontSize: "0.65rem", fontWeight: 700, color: "#854d0e" }}>MEDIUM RISK</span>
							</div>
							<div style={{ display: "flex", flexDirection: "column", padding: "0.5rem", backgroundColor: "#dbeafe", borderRadius: "0.375rem", textAlign: "center" }}>
								<span style={{ fontSize: "1.25rem", fontWeight: 800, color: "#3b82f6" }}>{lowAlertsCount}</span>
								<span style={{ fontSize: "0.65rem", fontWeight: 700, color: "#1e40af" }}>LOW / INFO</span>
							</div>
						</div>
					</div>

					{/* Chain of Custody Audit Logs */}
					<div className="card" style={{ padding: 0 }}>
						<div
							style={{
								padding: "1.25rem 1.5rem",
								borderBottom: "1px solid var(--border-color)",
							}}
						>
							<h3
								style={{
									margin: 0,
									display: "flex",
									alignItems: "center",
									gap: "0.5rem",
									fontSize: "1.15rem",
									fontWeight: 700
								}}
							>
								<Shield size={20} style={{ color: "var(--primary-color)" }} /> Chain of Custody Audit
							</h3>
						</div>
						<div className="timeline-container" style={{ padding: "1.5rem", maxHeight: "450px", overflowY: "auto" }}>
							{custody_logs.length === 0 ? (
								<p style={{ textAlign: "center", color: "var(--text-secondary)", fontSize: "0.85rem", margin: 0 }}>
									No custody events recorded for this evidence.
								</p>
							) : (
								custody_logs.map((log) => (
									<div
										key={log.id}
										className="timeline-item"
										style={{ 
											marginBottom: "1rem",
											padding: "0.75rem",
											fontSize: "0.8rem",
											borderLeft: "3px solid var(--primary-color)"
										}}
									>
										<div className="timeline-icon" style={{ width: "30px", height: "30px" }}>
											<Clock size={14} />
										</div>
										<div className="timeline-content">
											<div className="timeline-header" style={{ marginBottom: "0.15rem" }}>
												<span
													className="timeline-title"
													style={{ textTransform: "capitalize", fontWeight: 700 }}
												>
													{log.action.replace(/_/g, " ")}
												</span>
												<span className="timeline-time" style={{ fontSize: "0.65rem" }}>
													{new Date(log.occurred_at).toLocaleString()}
												</span>
											</div>
											<div style={{ color: "var(--text-secondary)", fontSize: "0.75rem" }}>
												<div>
													<strong>Actor:</strong> {log.actor_name || "System"}
												</div>
												{log.details && (
													<div className="text-break" style={{ marginTop: "0.25rem", fontSize: "0.7rem", backgroundColor: "#f9fafb", padding: "0.25rem", borderRadius: "0.25rem" }}>
														<strong>Details:</strong> {typeof log.details === 'object' ? JSON.stringify(log.details) : String(log.details)}
													</div>
												)}
											</div>
										</div>
									</div>
								))
							)}
						</div>
					</div>
				</div>
			</div>
		</div>
	);
};

export default CaseDetails;
