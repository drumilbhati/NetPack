import React, { useEffect, useState } from 'react';
import { Graph as D3Graph } from 'react-d3-graph';
import { fetchGraphData } from '../api/graph';

interface GraphNode {
  id: string;
  label: string;
  color?: string;
}

interface GraphLink {
  source: string;
  target: string;
}

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

const GraphPage: React.FC = () => {
  const [data, setData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  const config = {
    nodeHighlightBehavior: true,
    node: {
      color: '#2563eb',
      size: 400,
      highlightStrokeColor: 'blue',
      labelProperty: 'label',
      fontSize: 12,
    },
    link: {
      highlightColor: 'lightblue',
      renderLabel: false,
    },
    width: 800,
    height: 600,
    d3: {
      gravity: -300,
    },
  };

  if (loading) return <div className="card">Loading network graph...</div>;
  if (error) return <div className="card" style={{ color: 'red' }}>{error}</div>;

  return (
    <div className="card" style={{ height: '700px', display: 'flex', flexDirection: 'column' }}>
      <h3 style={{ marginTop: 0 }}>Network Topology</h3>
      <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>
        Red nodes indicate potential anomalies.
      </p>
      <div style={{ flex: 1, border: '1px solid var(--border-color)', borderRadius: '0.5rem', overflow: 'hidden' }}>
        {data && <D3Graph id="network-graph" data={data} config={config} />}
      </div>
    </div>
  );
};

export default GraphPage;
