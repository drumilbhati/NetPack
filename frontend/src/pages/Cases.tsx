import React, { useEffect, useState } from "react";
import { fetchCases } from "../api/cases";
import { apiFetch } from "../api/client";
import { type Case } from "../types";
import { FileText, Eye } from "lucide-react";
import { Link } from "react-router-dom";
import Loader from "../components/Loader";

const Cases: React.FC = () => {
	const [cases, setCases] = useState<Case[]>([]);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [page, setPage] = useState(1);

	// New State for case creation and upload
	const [showModal, setShowModal] = useState(false);
	const [newCaseTitle, setNewCaseTitle] = useState("");
	const [newCaseDesc, setNewCaseDesc] = useState("");
	const [uploadFile, setUploadFile] = useState<File | null>(null);
	const [uploading, setUploading] = useState(false);

	const handleDownloadReport = async (caseId: string) => {
		try {
			const response = await apiFetch(`/reports/${caseId}`);
			if (!response.ok) {
				throw new Error("Failed to generate report");
			}
			const blob = await response.blob();
			const url = window.URL.createObjectURL(blob);
			const a = document.createElement("a");
			a.href = url;
			a.download = `NetPack_Report_${caseId}.pdf`;
			document.body.appendChild(a);
			a.click();
			window.URL.revokeObjectURL(url);
			document.body.removeChild(a);
		} catch (err) {
			console.error("Download failed:", err);
			alert("Failed to download report. Please try again.");
		}
	};

	const loadCases = (p: number = page) => {
		setLoading(true);
		fetchCases(50, (p - 1) * 50)
			.then((data) => {
				setCases(data);
				setLoading(false);
			})
			.catch(() => {
				setError("Failed to load cases. Please ensure the backend is running.");
				setLoading(false);
			});
	};

	const handleCreateAndUpload = async (e: React.FormEvent) => {
		e.preventDefault();
		if (!newCaseTitle || !uploadFile) return;

		setUploading(true);
		try {
			// 1. Create Case
			const caseRes = await apiFetch(`/cases/`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ title: newCaseTitle, description: newCaseDesc }),
			});
			
			if (!caseRes.ok) {
				throw new Error("Failed to create case");
			}
			const caseData = await caseRes.json();

			// 2. Upload File associated with the new case_id
			const formData = new FormData();
			formData.append("file", uploadFile);

			const uploadRes = await apiFetch(`/upload/${caseData.id}`, {
				method: "POST",
				body: formData,
			});

			if (uploadRes.ok) {
				setShowModal(false);
				setNewCaseTitle("");
				setNewCaseDesc("");
				setUploadFile(null);
				loadCases();
			} else {
				const errData = await uploadRes.json().catch(() => ({}));
				throw new Error(errData.detail || "Case created, but file upload failed");
			}
		} catch (err) {
			console.error("Operation failed:", err);
			alert(err instanceof Error ? err.message : "An unexpected error occurred during upload.");
		} finally {
			setUploading(false);
		}
	};

	useEffect(() => {
		loadCases();
	}, []);

	if (loading)
		return <Loader message="Decrypting packets" />;
	if (error)
		return (
			<div style={{ color: "red", textAlign: "center", padding: "2rem" }}>
				{error}
			</div>
		);

	return (
		<div>
			<div
				style={{
					display: "flex",
					justifyContent: "space-between",
					alignItems: "center",
					marginBottom: "1.5rem",
				}}
			>
				<h2 style={{ margin: 0 }}>Active Investigations</h2>
				<button className="btn-primary" onClick={() => setShowModal(true)}>
					+ New Case
				</button>
			</div>

			{showModal && (
				<div
					style={{
						position: "fixed",
						top: 0,
						left: 0,
						right: 0,
						bottom: 0,
						backgroundColor: "rgba(0,0,0,0.5)",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
						zIndex: 1000,
					}}
				>
					<div className="card" style={{ width: "400px" }}>
						<h3>Create New Investigation</h3>
						<form onSubmit={handleCreateAndUpload}>
							<div style={{ marginBottom: "1rem" }}>
								<label
									style={{
										display: "block",
										marginBottom: "0.25rem",
										fontSize: "0.875rem",
									}}
								>
									Case Title
								</label>
								<input
									type="text"
									className="search-input"
									style={{ width: "100%", boxSizing: "border-box" }}
									value={newCaseTitle}
									onChange={(e) => setNewCaseTitle(e.target.value)}
									required
								/>
							</div>
							<div style={{ marginBottom: "1rem" }}>
								<label
									style={{
										display: "block",
										marginBottom: "0.25rem",
										fontSize: "0.875rem",
									}}
								>
									Description
								</label>
								<textarea
									className="search-input"
									style={{
										width: "100%",
										boxSizing: "border-box",
										height: "80px",
									}}
									value={newCaseDesc}
									onChange={(e) => setNewCaseDesc(e.target.value)}
								/>
							</div>
							<div style={{ marginBottom: "1.5rem" }}>
								<label
									style={{
										display: "block",
										marginBottom: "0.25rem",
										fontSize: "0.875rem",
									}}
								>
									Evidence (PCAP)
								</label>
								<input
									type="file"
									accept=".pcap,.pcapng"
									onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
									required
								/>
							</div>
							<div
								style={{
									display: "flex",
									gap: "1rem",
									justifyContent: "flex-end",
								}}
							>
								<button
									type="button"
									onClick={() => setShowModal(false)}
									style={{
										background: "none",
										border: "none",
										cursor: "pointer",
									}}
								>
									Cancel
								</button>
								<button
									type="submit"
									className="btn-primary"
									disabled={uploading}
									style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
								>
									{uploading ? <Loader inline message="Decrypting evidence" /> : "Start Investigation"}
								</button>
							</div>
						</form>
					</div>
				</div>
			)}

			<div className="card" style={{ padding: 0 }}>
				<div className="table-responsive">
					<table>
						<thead>
							<tr>
								<th>ID</th>
								<th>Title</th>
								<th>Description</th>
								<th>Created At</th>
								<th>Actions</th>
							</tr>
						</thead>
						<tbody>
							{cases.length === 0 ? (
								<tr>
									<td
										colSpan={5}
										style={{
											textAlign: "center",
											color: "var(--text-secondary)",
										}}
									>
										No cases found.
									</td>
								</tr>
							) : (
								cases.map((caseItem) => (
									<tr key={caseItem.id}>
										<td title={caseItem.id}>{caseItem.id.substring(0, 8)}...</td>
										<td className="text-truncate" style={{ fontWeight: 500, maxWidth: "200px" }}>{caseItem.title}</td>
										<td className="text-truncate" style={{ maxWidth: "300px" }}>{caseItem.description}</td>
										<td style={{ color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
											{new Date(caseItem.created_at).toLocaleString()}
										</td>
										<td>
											<div style={{ display: "flex", gap: "0.5rem" }}>
												<Link
													to={`/cases/${caseItem.id}`}
													className="btn-primary"
													style={{
														padding: "0.25rem 0.75rem",
														fontSize: "0.75rem",
														display: "flex",
														alignItems: "center",
														gap: "0.5rem",
														textDecoration: "none",
													}}
												>
													<Eye size={14} />
													Details
												</Link>
												<button
													className="btn-primary"
													style={{
														padding: "0.25rem 0.75rem",
														fontSize: "0.75rem",
														display: "flex",
														alignItems: "center",
														gap: "0.5rem",
														background: "var(--text-secondary)",
													}}
													onClick={() => handleDownloadReport(caseItem.id)}
												>
													<FileText size={14} />
													Report
												</button>
											</div>
										</td>
									</tr>
								))
							)}
						</tbody>
					</table>
				</div>
				<div
					style={{
						display: "flex",
						justifyContent: "space-between",
						alignItems: "center",
						padding: "1rem 1.5rem",
						borderTop: "1px solid var(--border-color)",
						background: "var(--background-card)"
					}}
				>
					<button
						className="btn-primary"
						disabled={page === 1}
						onClick={() => {
							const newPage = page - 1;
							setPage(newPage);
							loadCases(newPage);
						}}
						style={{
							padding: "0.4rem 0.8rem",
							fontSize: "0.875rem",
							backgroundColor: page === 1 ? "var(--border-color)" : "var(--primary-color)",
							cursor: page === 1 ? "not-allowed" : "pointer"
						}}
					>
						Previous
					</button>
					<span style={{ fontSize: "0.875rem", color: "var(--text-secondary)", fontWeight: 500 }}>
						Page {page}
					</span>
					<button
						className="btn-primary"
						disabled={cases.length < 50}
						onClick={() => {
							const newPage = page + 1;
							setPage(newPage);
							loadCases(newPage);
						}}
						style={{
							padding: "0.4rem 0.8rem",
							fontSize: "0.875rem",
							backgroundColor: cases.length < 50 ? "var(--border-color)" : "var(--primary-color)",
							cursor: cases.length < 50 ? "not-allowed" : "pointer"
						}}
					>
						Next
					</button>
				</div>
			</div>
		</div>
	);
};

export default Cases;
