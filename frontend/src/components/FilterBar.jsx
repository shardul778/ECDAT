import React from 'react';

export default function FilterBar({ activeFilter, onFilterChange, counts }) {
  const filters = [
    { key: 'ALL', label: 'All Risks', count: counts.all },
    { key: 'HIGH', label: 'High', count: counts.high },
    { key: 'MEDIUM', label: 'Medium', count: counts.medium },
    { key: 'LOW', label: 'Low', count: counts.low },
  ];

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1rem',
      flexWrap: 'wrap',
      gap: '0.75rem'
    }}>
      <div className="filter-group">
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginRight: '0.25rem' }}>
          Filter by Risk:
        </span>
        {filters.map((f) => (
          <button
            key={f.key}
            className={`filter-btn ${activeFilter === f.key ? 'active' : ''}`}
            onClick={() => onFilterChange(f.key)}
          >
            {f.label} ({f.count})
          </button>
        ))}
      </div>
    </div>
  );
}
