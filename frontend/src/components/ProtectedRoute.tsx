import React from "react";
import { Navigate, useLocation } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";

const ProtectedRoute: React.FC<{ children: React.ReactElement }> = ({ children }) => {
	const { isAuthenticated, loading } = useAuth();
	const location = useLocation();

	if (loading) {
		return (
			<div style={{ 
				display: "flex", 
				height: "100vh", 
				alignItems: "center", 
				justifyContent: "center",
				flexDirection: "column",
				gap: "1rem",
				color: "var(--text-secondary)"
			}}>
				<div className="spinner"></div>
				<span>Verifying session...</span>
			</div>
		);
	}

	if (!isAuthenticated) {
		return <Navigate to="/login" replace state={{ from: location }} />;
	}

	return children;
};

export default ProtectedRoute;
