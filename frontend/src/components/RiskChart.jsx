import React from 'react';

export default function RiskChart({ findings }) {
  const highCount = findings.filter(f => f.risk_score === 'High').length;
  const mediumCount = findings.filter(f => f.risk_score === 'Medium').length;
  const lowCount = findings.filter(f => f.risk_score === 'Low').length;
  const total = findings.length;

  const highPct = total > 0 ? (highCount / total) * 100 : 0;
  const mediumPct = total > 0 ? (mediumCount / total) * 100 : 0;
  const lowPct = total > 0 ? (lowCount / total) * 100 : 0;

  return (
    <div className="card">
      <div className="card-title">
        <span>Risk Distribution</span>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 400 }}>{total} Total</span>
      </div>

      {total === 0 ? (
        <div style={{ textAlign: 'center', padding: '2rem 0', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
          No scan data available
        </div>
      ) : (
        <div>
          {/* Stacked Progress Bar */}
          <div style={{
            display: 'flex',
            height: '10px',
            borderRadius: '9999px',
            overflow: 'hidden',
            backgroundColor: 'var(--bg-surface-subtle)',
            border: '1px solid var(--border-color)',
            marginBottom: '1.25rem'
          }}>
            {highPct > 0 && (
              <div
                style={{ width: `${highPct}%`, backgroundColor: 'var(--risk-high)' }}
                title={`High Risk: ${highCount}`}
              />
            )}
            {mediumPct > 0 && (
              <div
                style={{ width: `${mediumPct}%`, backgroundColor: 'var(--risk-medium)' }}
                title={`Medium Risk: ${mediumCount}`}
              />
            )}
            {lowPct > 0 && (
              <div
                style={{ width: `${lowPct}%`, backgroundColor: 'var(--risk-low)' }}
                title={`Low Risk: ${lowCount}`}
              />
            )}
          </div>

          {/* Breakdown List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', fontSize: '0.85rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--risk-high)' }}></span>
                <span style={{ color: 'var(--text-main)' }}>High Risk</span>
              </div>
              <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-main)' }}>
                {highCount} <span style={{ color: 'var(--text-muted)', fontWeight: 400, fontSize: '0.75rem' }}>({Math.round(highPct)}%)</span>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', fontSize: '0.85rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--risk-medium)' }}></span>
                <span style={{ color: 'var(--text-main)' }}>Medium Risk</span>
              </div>
              <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-main)' }}>
                {mediumCount} <span style={{ color: 'var(--text-muted)', fontWeight: 400, fontSize: '0.75rem' }}>({Math.round(mediumPct)}%)</span>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', fontSize: '0.85rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--risk-low)' }}></span>
                <span style={{ color: 'var(--text-main)' }}>Low Risk</span>
              </div>
              <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-main)' }}>
                {lowCount} <span style={{ color: 'var(--text-muted)', fontWeight: 400, fontSize: '0.75rem' }}>({Math.round(lowPct)}%)</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
