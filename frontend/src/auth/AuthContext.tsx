import React, {
	createContext,
	useCallback,
	useContext,
	useEffect,
	useMemo,
	useState,
} from "react";

import {
	apiFetch,
	clearAuthState,
	getAccessToken,
	getStoredUser,
	setAuthState,
	type StoredUser,
} from "../api/client";

interface AuthContextValue {
	user: StoredUser | null;
	isAuthenticated: boolean;
	loading: boolean;
	login: (email: string, password: string) => Promise<void>;
	logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
	const [user, setUser] = useState<StoredUser | null>(getStoredUser());
	const [loading, setLoading] = useState(false);

	const logout = useCallback(() => {
		clearAuthState();
		setUser(null);
	}, []);

	useEffect(() => {
		const token = getAccessToken();
		if (token) {
			setLoading(true);
			apiFetch("/auth/me")
				.then((res) => {
					if (!res.ok) throw new Error("Token invalid");
					return res.json();
				})
				.then((userData) => {
					setUser(userData);
				})
				.catch(() => {
					logout();
				})
				.finally(() => {
					setLoading(false);
				});
		}
	}, [logout]);

	const login = useCallback(async (email: string, password: string) => {
		setLoading(true);
		try {
			const response = await apiFetch("/auth/login", {
				method: "POST",
				body: JSON.stringify({ email, password }),
			});
			if (!response.ok) {
				const errorData = await response.json().catch(() => ({}));
				throw new Error(errorData.detail || "Login failed");
			}
			const data = await response.json();
			setAuthState(data.access_token, data.user);
			setUser(data.user);
		} finally {
			setLoading(false);
		}
	}, []);

	const value = useMemo<AuthContextValue>(
		() => ({
			user,
			isAuthenticated: Boolean(user),
			loading,
			login,
			logout,
		}),
		[user, loading, login, logout],
	);

	return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
	const context = useContext(AuthContext);
	if (!context) {
		throw new Error("useAuth must be used within an AuthProvider");
	}
	return context;
}
