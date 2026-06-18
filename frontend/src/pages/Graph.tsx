import React, { useEffect, useState, useRef } from "react";
import ForceGraph2D from "react-force-graph-2d";
import Loader from "../components/Loader";
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
	const graphRef = useRef<any>(null);
	const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
	const [hoverNode, setHoverNode] = useState<any>(null);

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

	useEffect(() => {
		if (graphRef.current) {
			// Fine-tune the physics engine to reduce clutter
			graphRef.current.d3Force("charge").strength(-150);
			graphRef.current.d3Force("link").distance(100);
		}
	}, [data]);

	if (loading) return <Loader message="Mapping IP connections" />;
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
				anomalies. <strong>Hover over a node to see the IP address.</strong>
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
						ref={graphRef}
						graphData={data}
						width={dimensions.width}
						height={dimensions.height}
						onNodeHover={setHoverNode}
						nodeVal={(node) => Math.min((node as GraphNode).val || 1, 15)}
						nodeColor={(node) => (node as GraphNode).color || "#2563eb"}
						linkDirectionalParticles={data.nodes.length > 150 ? 0 : 2}
						linkDirectionalParticleSpeed={() => 0.005}
						linkDirectionalParticleWidth={1.5}
						linkColor={() => "rgba(156, 163, 175, 0.4)"}
						backgroundColor="#f8fafc"
						nodeRelSize={3}
						warmupTicks={data.nodes.length > 50 ? 150 : 0}
						cooldownTicks={100}
						d3VelocityDecay={0.2}
						nodeCanvasObject={(node: any, ctx, globalScale) => {
							const radius = Math.sqrt(Math.min(node.val || 1, 10)) * 3;

							// 1. Draw Node Circle
							ctx.beginPath();
							ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
							ctx.fillStyle = node.color || "#2563eb";
							ctx.fill();

							ctx.strokeStyle = "rgba(255, 255, 255, 0.8)";
							ctx.lineWidth = 1;
							ctx.stroke();

							// 2. Draw Label if hovered OR if we are zoomed in enough
							const isHovered = hoverNode && hoverNode.id === node.id;
							const shouldShowLabel = isHovered || globalScale > 2.5;

							if (shouldShowLabel) {
								const label = node.label;
								const fontSize = 14 / globalScale;
								ctx.font = `${fontSize}px Inter, Sans-Serif`;
								const textWidth = ctx.measureText(label).width;
								const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.4);

								// Draw label background (pill shape)
								ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
								ctx.beginPath();
								const bgX = node.x - bckgDimensions[0] / 2;
								const bgY = node.y + radius + (fontSize * 0.5);
								
								// Drawing a rounded rect manually for better browser support
								const r = 4 / globalScale;
								const w = bckgDimensions[0];
								const h = bckgDimensions[1];
								ctx.moveTo(bgX + r, bgY);
								ctx.arcTo(bgX + w, bgY, bgX + w, bgY + h, r);
								ctx.arcTo(bgX + w, bgY + h, bgX, bgY + h, r);
								ctx.arcTo(bgX, bgY + h, bgX, bgY, r);
								ctx.arcTo(bgX, bgY, bgX + w, bgY, r);
								ctx.closePath();
								ctx.fill();
								
								ctx.strokeStyle = node.color || "#2563eb";
								ctx.lineWidth = 0.5 / globalScale;
								ctx.stroke();

								// Draw label text
								ctx.textAlign = 'center';
								ctx.textBaseline = 'top';
								ctx.fillStyle = '#1e293b';
								ctx.fillText(label, node.x, bgY + (fontSize * 0.2));
							}
						}}
						nodeCanvasObjectMode={() => "replace"}
					/>
				)}
			</div>
		</div>
	);
};

export default GraphPage;
