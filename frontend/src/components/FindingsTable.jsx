import React from 'react';
import { CheckCircle, AlertCircle } from 'lucide-react';

export default function FindingsTable({ findings, activeFilter, onSelectFinding, scanning, hasScanned }) {
  const filtered = activeFilter === 'ALL'
    ? findings
    : findings.filter(f => f.risk_score?.toUpperCase() === activeFilter);

  const getRiskBadgeClass = (risk) => {
    switch (risk?.toLowerCase()) {
      case 'high': return 'badge badge-risk-high';
      case 'medium': return 'badge badge-risk-medium';
      case 'low': return 'badge badge-risk-low';
      default: return 'badge';
    }
  };

  const getExposureBadgeClass = (exposure) => {
    switch (exposure) {
      case 'Critical': return 'badge badge-exposure-critical';
      case 'Externally Exposed': return 'badge badge-exposure-exposed';
      case 'Test-only': return 'badge badge-exposure-internal';
      default: return 'badge badge-exposure-internal';
    }
  };

  // 1. Skeleton Loading State during scan
  if (scanning) {
    return (
      <div className="card">
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>File Location</th>
                <th>Algorithm</th>
                <th>Confidence</th>
                <th>Exposure</th>
                <th>Risk Assessment</th>
              </tr>
            </thead>
            <tbody>
              {[...Array(6)].map((_, i) => (
                <tr key={`skeleton-${i}`} className="skeleton-row">
                  <td>
                    <div className="skeleton-bar" style={{ width: `${55 + (i % 3) * 15}%`, height: '14px' }}></div>
                  </td>
                  <td>
                    <div className="skeleton-bar" style={{ width: '80px', height: '14px' }}></div>
                  </td>
                  <td>
                    <div className="skeleton-bar" style={{ width: '115px', height: '14px' }}></div>
                  </td>
                  <td>
                    <div className="skeleton-bar" style={{ width: '85px', height: '14px' }}></div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                      <div className="skeleton-bar" style={{ width: '55px', height: '18px', borderRadius: '9999px' }}></div>
                      <div className="skeleton-bar" style={{ width: '48px', height: '14px' }}></div>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  // 2. Initial Empty State before any scan is executed
  if (!hasScanned) {
    return (
      <div className="card">
        <div className="empty-state">
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', lineHeight: '1.6' }}>
            No scan run yet — click 'Run Discovery Scan' or scan a GitHub repo to see results
          </p>
        </div>
      </div>
    );
  }

  // 3. Scan completed but filter or target returned 0 findings
  if (filtered.length === 0) {
    return (
      <div className="card">
        <div className="empty-state">
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
            {activeFilter === 'ALL'
              ? 'No cryptographic assets or vulnerabilities found.'
              : `No findings match the selected filter (${activeFilter}).`}
          </p>
        </div>
      </div>
    );
  }

  // 4. Populated Findings Table
  return (
    <div className="card">
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>File Location</th>
              <th>Algorithm</th>
              <th>Confidence</th>
              <th>Exposure</th>
              <th>Risk Assessment</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((item, idx) => (
              <tr
                key={item.id || idx}
                onClick={() => onSelectFinding && onSelectFinding(item)}
                className="clickable-row"
                title="Click to view full cryptographic details"
              >
                <td>
                  <span className="file-link">{item.file}</span>
                </td>
                <td>
                  <span style={{ fontWeight: 600, color: 'var(--text-main)', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.825rem' }}>
                    {item.algorithm}
                  </span>
                </td>
                <td>
                  <span style={{
                    fontSize: '0.75rem',
                    fontWeight: 500,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.3rem',
                    color: item.confidence?.includes('High') ? 'var(--accent)' : 'var(--text-muted)'
                  }}>
                    {item.confidence?.includes('High') ? (
                      <CheckCircle size={13} color="var(--accent)" />
                    ) : (
                      <AlertCircle size={13} color="var(--text-muted)" />
                    )}
                    <span>{item.confidence}</span>
                  </span>
                </td>
                <td>
                  <span className={getExposureBadgeClass(item.exposure)}>
                    {item.exposure}
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', flexWrap: 'wrap' }}>
                      <span className={getRiskBadgeClass(item.risk_score)}>
                        {item.risk_score}
                      </span>
                      <span style={{
                        fontSize: '0.725rem',
                        fontWeight: 600,
                        color: item.risk_score === 'High' ? 'var(--risk-high)' : item.risk_score === 'Medium' ? 'var(--risk-medium)' : 'var(--risk-low)',
                        background: 'var(--bg-surface)',
                        padding: '0.1rem 0.35rem',
                        borderRadius: '0.25rem',
                        border: '1px solid var(--border-color)',
                        fontFamily: 'JetBrains Mono, monospace'
                      }}>
                        {item.numeric_risk_score !== undefined ? `${item.numeric_risk_score}/100` : item.risk_score === 'High' ? '75.0/100' : item.risk_score === 'Medium' ? '30.0/100' : '5.0/100'}
                      </span>
                    </div>
                    {item.time_horizon && (
                      <span style={{
                        fontSize: '0.7rem',
                        color: 'var(--text-muted)',
                        fontWeight: 400
                      }}>
                        {item.time_horizon.includes('Immediate') ? 'Immediate (0–3m)' : item.time_horizon.includes('Medium-term') ? 'PQC Migration' : 'Monitor'}
                      </span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
