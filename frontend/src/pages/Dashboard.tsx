import React from 'react';

const Dashboard: React.FC = () => {
  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Welcome to NetPack</h3>
      <p style={{ color: 'var(--text-secondary)' }}>
        Start by creating a new case or searching through existing network captures.
      </p>
    </div>
  );
};

export default Dashboard;
