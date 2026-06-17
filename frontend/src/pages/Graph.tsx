import React, { useEffect, useState, useRef } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { fetchGraphData } from "../api/graph";

interface GraphNode {
	id: string;
	label: string;
	color?: string;
	val?: number;
	x?: number;
	y?: number;
}

interface GraphLink {
	source: string | GraphNode;
	target: string | GraphNode;
}

interface GraphData {
	nodes: GraphNode[];
	links: GraphLink[];
}

const GraphPage: React.FC = () => {
	const [data, setData] = useState<GraphData | null>(null);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const containerRef = useRef<HTMLDivElement>(null);
	const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

	useEffect(() => {
		fetchGraphData()
			.then((res) => {
				setData(res);
				setLoading(false);
			})
			.catch((err) => {
				console.error(err);
				setError("Failed to load graph data");
				setLoading(false);
			});
	}, []);

	useEffect(() => {
		if (containerRef.current) {
			setDimensions({
				width: containerRef.current.clientWidth,
				height: containerRef.current.clientHeight,
			});
		}
	}, [loading]);

	if (loading) return <div className="card">Loading network graph...</div>;
	if (error)
		return (
			<div className="card" style={{ color: "red" }}>
				{error}
			</div>
		);
	if (!data || data.nodes.length === 0 || data.links.length === 0) {
		return <div className="card">No indexed flow data available yet.</div>;
	}

	return (
		<div
			className="card"
			style={{ height: "750px", display: "flex", flexDirection: "column" }}
		>
			<h3 style={{ marginTop: 0 }}>Network Topology</h3>
			<p style={{ color: "var(--text-secondary)", marginBottom: "1rem" }}>
				Node size indicates traffic volume. Red nodes indicate potential
				anomalies.
			</p>
			<div
				ref={containerRef}
				style={{
					flex: 1,
					border: "1px solid var(--border-color)",
					borderRadius: "0.5rem",
					overflow: "hidden",
					position: "relative",
					background: "#f8fafc",
				}}
			>
				{data && (
					<ForceGraph2D
						graphData={data}
						width={dimensions.width}
						height={dimensions.height}
						nodeLabel="label"
						nodeVal={(node) => (node as GraphNode).val || 1}
						nodeColor={(node) => (node as GraphNode).color || "#2563eb"}
						linkDirectionalParticles={4}
						linkDirectionalParticleSpeed={(d) => 0.01}
						linkDirectionalParticleWidth={2}
						backgroundColor="#f8fafc"
						nodeRelSize={4}
						nodeCanvasObject={(node: any, ctx, globalScale) => {
							const label = node.label;
							const fontSize = 12 / globalScale;
							ctx.font = `${fontSize}px Sans-Serif`;
							const textWidth = ctx.measureText(label).width;
							const bckgDimensions = [textWidth, fontSize].map(
								(n) => n + fontSize * 0.2,
							);

							// Draw Node Circle
							ctx.beginPath();
							ctx.arc(
								node.x,
								node.y,
								Math.sqrt(node.val || 1) * 4,
								0,
								2 * Math.PI,
								false,
							);
							ctx.fillStyle = node.color || "#2563eb";
							ctx.fill();

							// Draw Label
							ctx.textAlign = "center";
							ctx.textBaseline = "middle";
							ctx.fillStyle = "rgba(0, 0, 0, 0.8)";
							ctx.fillText(label, node.x, node.y + (Math.sqrt(node.val || 1) * 4) + (fontSize * 1.5));
						}}
						nodeCanvasObjectMode={() => "replace"}
					/>
				)}
			</div>
		</div>
	);
};

export default GraphPage;
