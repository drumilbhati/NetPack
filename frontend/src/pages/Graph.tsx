import React, { useEffect, useState, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { fetchGraphData } from '../api/graph';

interface GraphNode {
  id: string;
  label: string;
  color?: string;
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
        setError('Failed to load graph data');
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
  if (error) return <div className="card" style={{ color: 'red' }}>{error}</div>;

  return (
    <div className="card" style={{ height: '700px', display: 'flex', flexDirection: 'column' }}>
      <h3 style={{ marginTop: 0 }}>Network Topology</h3>
      <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>
        Red nodes indicate potential anomalies. Drag nodes to explore.
      </p>
      <div 
        ref={containerRef}
        style={{ flex: 1, border: '1px solid var(--border-color)', borderRadius: '0.5rem', overflow: 'hidden', position: 'relative' }}
      >
        {data && (
          <ForceGraph2D
            graphData={data}
            width={dimensions.width}
            height={dimensions.height}
            nodeLabel="label"
            nodeColor={(node) => (node as GraphNode).color || '#2563eb'}
            linkDirectionalParticles={2}
            linkDirectionalParticleSpeed={0.005}
            backgroundColor="#ffffff"
            nodeRelSize={6}
          />
        )}
      </div>
    </div>
  );
};

export default GraphPage;
