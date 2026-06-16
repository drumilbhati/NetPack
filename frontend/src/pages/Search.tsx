import React from 'react';

const Search: React.FC = () => {
  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Network Search</h3>
      <div className="search-container">
        <input
          type="text"
          placeholder="Search by IP, Protocol, or Keyword..."
          className="search-input"
          aria-label="Search by IP, Protocol, or Keyword"
        />
        <button className="btn-primary">
          Search
        </button>
      </div>
      <div style={{ marginTop: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
        Results will appear here.
      </div>
    </div>
  );
};

export default Search;
