import React, { useEffect, useState } from "react";
import Loader from "../components/Loader";

import { apiFetch } from "../api/client";
import {
	LineChart,
	Line,
	XAxis,
	YAxis,
	CartesianGrid,
	Tooltip,
	Legend,
	ResponsiveContainer,
	BarChart,
	Bar,
	PieChart,
	Pie,
	Cell,
} from "recharts";

const COLORS = [
	"#2563eb",
	"#10b981",
	"#f59e0b",
	"#ef4444",
	"#8b5cf6",
	"#06b6d4",
];

const Dashboard: React.FC = () => {
	const [throughput, setThroughput] = useState([]);
	const [protocols, setProtocols] = useState([]);
	const [talkers, setTalkers] = useState([]);
	const [loading, setLoading] = useState(true);

	const fetchData = async () => {
		try {
			const [tRes, pRes, sRes] = await Promise.all([
				apiFetch(`/stats/throughput`),
				apiFetch(`/stats/protocols`),
				apiFetch(`/stats/top-talkers`),
			]);

			setThroughput(await tRes.json());
			setProtocols(await pRes.json());
			setTalkers(await sRes.json());
		} catch (err) {
			console.error("Dashboard data fetch failed:", err);
		} finally {
			setLoading(false);
		}
	};

	useEffect(() => {
		fetchData();
		const interval = setInterval(fetchData, 10000); // Refresh every 10s
		return () => clearInterval(interval);
	}, []);

	if (loading) return <Loader message="Analyzing network traffic" />;

	const formatTraffic = (val: number) => {
		if (val === 0) return "0 B";
		const k = 1024;
		const sizes = ["B", "KB", "MB", "GB", "TB"];
		const i = Math.floor(Math.log(val) / Math.log(k));
		return `${parseFloat((val / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
	};

	return (
		<div style={{ display: "flex", flexDirection: "column", gap: "2rem" }}>
			{/* Throughput Chart */}
			<div className="card">
				<h3 style={{ marginTop: 0 }}>Traffic Throughput</h3>
				<div style={{ height: 300, width: "100%" }}>
					<ResponsiveContainer>
						<LineChart data={throughput} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
							<CartesianGrid strokeDasharray="3 3" />
							<XAxis
								dataKey="timestamp"
								tick={{ fontSize: 12 }}
								tickFormatter={(ts) =>
									new Date(ts).toLocaleDateString(undefined, {
										month: "short",
										day: "numeric",
									})
								}
							/>
							<YAxis 
								width={85} 
								tick={{ fontSize: 12 }} 
								tickFormatter={formatTraffic} 
							/>
							<Tooltip 
								labelFormatter={(ts) => new Date(ts).toLocaleString()} 
								formatter={(val: any, name: any) => [formatTraffic(Number(val)), String(name)]}
							/>
							<Legend />
							<Line
								type="monotone"
								dataKey="bytes_sent"
								stroke="#2563eb"
								name="Sent"
								strokeWidth={2}
								dot={false}
							/>
							<Line
								type="monotone"
								dataKey="bytes_received"
								stroke="#10b981"
								name="Received"
								strokeWidth={2}
								dot={false}
							/>
						</LineChart>
					</ResponsiveContainer>
				</div>
			</div>

			<div
				style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2rem" }}
			>
				{/* Protocol Distribution */}
				<div className="card">
					<h3 style={{ marginTop: 0 }}>Protocol Distribution</h3>
					<div style={{ height: 300, width: "100%" }}>
						<ResponsiveContainer>
							<PieChart>
								<Pie
									data={protocols}
									dataKey="count"
									nameKey="protocol"
									cx="50%"
									cy="50%"
									outerRadius={80}
									label
								>
									{protocols.map((_, index) => (
										<Cell
											key={`cell-${index}`}
											fill={COLORS[index % COLORS.length]}
										/>
									))}
								</Pie>
								<Tooltip />
								<Legend />
							</PieChart>
						</ResponsiveContainer>
					</div>
				</div>

				{/* Top Talkers */}
				<div className="card">
					<h3 style={{ marginTop: 0 }}>Top Talkers (MB)</h3>
					<div style={{ height: 300, width: "100%" }}>
						<ResponsiveContainer>
							<BarChart data={talkers} layout="vertical">
								<CartesianGrid strokeDasharray="3 3" />
								<XAxis
									type="number"
									tickFormatter={(val) => (val / (1024 * 1024)).toFixed(1)}
								/>
								<YAxis dataKey="ip" type="category" width={100} />
								<Tooltip
									formatter={(val: any) =>
										`${(Number(val) / (1024 * 1024)).toFixed(2)} MB`
									}
								/>
								<Legend />
								<Bar
									dataKey="bytes"
									fill="#2563eb"
									name="Total Bytes"
									radius={[0, 4, 4, 0]}
								/>
							</BarChart>
						</ResponsiveContainer>
					</div>
				</div>
			</div>
		</div>
	);
};

export default Dashboard;
