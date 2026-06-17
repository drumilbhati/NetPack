import React, { useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";

const Login: React.FC = () => {
	const { login, isAuthenticated, loading } = useAuth();
	const navigate = useNavigate();
	const location = useLocation();
	const [email, setEmail] = useState("admin@netpack.local");
	const [password, setPassword] = useState("admin123");
	const [error, setError] = useState<string | null>(null);

	const from =
		(location.state as { from?: { pathname?: string } })?.from?.pathname || "/";

	if (isAuthenticated) {
		return <Navigate to={from} replace />;
	}

	const handleSubmit = async (event: React.FormEvent) => {
		event.preventDefault();
		setError(null);
		try {
			await login(email, password);
			navigate(from, { replace: true });
		} catch (loginError) {
			setError(
				loginError instanceof Error ? loginError.message : "Login failed",
			);
		}
	};

	return (
		<div className="card" style={{ maxWidth: 480, margin: "4rem auto" }}>
			<h2 style={{ marginTop: 0 }}>Sign in to NetPack</h2>
			<p style={{ color: "var(--text-secondary)" }}>
				Authenticate to access case-scoped evidence, search, and audit data.
			</p>
			<form onSubmit={handleSubmit} style={{ display: "grid", gap: "1rem" }}>
				<label>
					<div
						style={{ fontSize: "0.75rem", fontWeight: 700, marginBottom: 6 }}
					>
						Email
					</div>
					<input
						type="email"
						className="search-input"
						style={{ width: "100%" }}
						value={email}
						onChange={(event) => setEmail(event.target.value)}
					/>
				</label>
				<label>
					<div
						style={{ fontSize: "0.75rem", fontWeight: 700, marginBottom: 6 }}
					>
						Password
					</div>
					<input
						type="password"
						className="search-input"
						style={{ width: "100%" }}
						value={password}
						onChange={(event) => setPassword(event.target.value)}
					/>
				</label>
				{error && <div className="text-red-500">{error}</div>}
				<button className="btn-primary" type="submit" disabled={loading}>
					{loading ? "Signing in..." : "Sign In"}
				</button>
			</form>
			<div
				style={{
					marginTop: "1rem",
					fontSize: "0.8rem",
					color: "var(--text-secondary)",
				}}
			>
				Default dev users: <br />
				admin@netpack.local / admin123
				<br />
				investigator@netpack.local / investigator123
				<br />
				auditor@netpack.local / auditor123
			</div>
		</div>
	);
};

export default Login;
