import React, { useEffect, useState } from 'react';
import { fetchCases } from '../api/cases';
import { type Case } from '../types';

const Cases: React.FC = () => {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCases()
      .then((data) => {
        setCases(data);
        setLoading(false);
      })
      .catch(() => {
        setError('Failed to load cases. Please ensure the backend is running.');
        setLoading(false);
      });
  }, []);

  if (loading) return <div style={{ textAlign: 'center', padding: '2rem' }}>Loading cases...</div>;
  if (error) return <div style={{ color: 'red', textAlign: 'center', padding: '2rem' }}>{error}</div>;

  return (
    <div className="card" style={{ padding: 0 }}>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Description</th>
            <th>Created At</th>
          </tr>
        </thead>
        <tbody>
          {cases.length === 0 ? (
            <tr>
              <td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>
                No cases found.
              </td>
            </tr>
          ) : (
            cases.map((caseItem) => (
              <tr key={caseItem.id}>
                <td>{caseItem.id}</td>
                <td style={{ fontWeight: 500 }}>{caseItem.title}</td>
                <td>{caseItem.description}</td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  {new Date(caseItem.created_at).toLocaleString()}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
};

export default Cases;
