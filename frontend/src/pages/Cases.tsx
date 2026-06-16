import React, { useEffect, useState } from "react";
import { fetchCases } from "../api/cases";
import { type Case } from "../types";
import { FileText } from "lucide-react";

const Cases: React.FC = () => {
	const [cases, setCases] = useState<Case[]>([]);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);

	// New State for case creation and upload
	const [showModal, setShowModal] = useState(false);
	const [newCaseTitle, setNewCaseTitle] = useState("");
	const [newCaseDesc, setNewCaseDesc] = useState("");
	const [uploadFile, setUploadFile] = useState<File | null>(null);
	const [uploading, setUploading] = useState(false);

	const baseUrl = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

	const handleDownloadReport = (caseId: string) => {
		window.open(
			`${baseUrl.replace(/\/$/, "")}/reports/${caseId}`,
			"_blank",
			"noopener,noreferrer",
		);
	};

	const loadCases = () => {
		setLoading(true);
		fetchCases()
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
			await fetch(`${baseUrl}/cases/`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ title: newCaseTitle, description: newCaseDesc }),
			});

			// 2. Upload File (In a real app, this would associate with case_id)
			const formData = new FormData();
			formData.append("file", uploadFile);

			const uploadRes = await fetch(`${baseUrl}/upload/`, {
				method: "POST",
				body: formData,
			});

			if (uploadRes.ok) {
				setShowModal(false);
				setNewCaseTitle("");
				setNewCaseDesc("");
				setUploadFile(null);
				loadCases();
			}
		} catch (err) {
			console.error("Operation failed:", err);
		} finally {
			setUploading(false);
		}
	};

	useEffect(() => {
		loadCases();
	}, []);

	if (loading)
		return (
			<div style={{ textAlign: "center", padding: "2rem" }}>
				Loading cases...
			</div>
		);
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
								>
									{uploading ? "Processing..." : "Start Investigation"}
								</button>
							</div>
						</form>
					</div>
				</div>
			)}

			<div className="card" style={{ padding: 0 }}>
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
									<td style={{ fontWeight: 500 }}>{caseItem.title}</td>
									<td>{caseItem.description}</td>
									<td style={{ color: "var(--text-secondary)" }}>
										{new Date(caseItem.created_at).toLocaleString()}
									</td>
									<td>
										<button
											className="btn-primary"
											style={{
												padding: "0.25rem 0.75rem",
												fontSize: "0.75rem",
												display: "flex",
												alignItems: "center",
												gap: "0.5rem",
											}}
											onClick={() => handleDownloadReport(caseItem.id)}
										>
											<FileText size={14} />
											Report
										</button>
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

export default Cases;
