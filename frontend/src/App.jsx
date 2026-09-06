import React, { useState, useEffect } from 'react';
import { ShieldAlert, Play, Download, CheckCircle2, AlertTriangle, ShieldCheck, RefreshCw, GitBranch, Globe } from 'lucide-react';
import FindingsTable from './components/FindingsTable';
import RiskChart from './components/RiskChart';
import FilterBar from './components/FilterBar';
import FindingDetailModal from './components/FindingDetailModal';

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function App() {
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [hasScanned, setHasScanned] = useState(false);
  const [repoUrl, setRepoUrl] = useState('');
  const [scanTarget, setScanTarget] = useState(null);
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [error, setError] = useState(null);
  const [lastScanTime, setLastScanTime] = useState(null);

  const fetchFindings = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`${API_BASE}/findings`);
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();
      setFindings(data.findings || []);
      setHasScanned(true);
    } catch (err) {
      console.error('Failed to fetch findings:', err);
    } finally {
      setLoading(false);
    }
  };

  const triggerScan = async () => {
    try {
      setScanning(true);
      setError(null);
      const res = await fetch(`${API_BASE}/scan`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Scan failed with status ${res.status}`);
      setFindings(data.findings || []);
      setHasScanned(true);
      setScanTarget('Sample Repository');
      setLastScanTime(new Date().toLocaleTimeString());
    } catch (err) {
      console.error('Scan error:', err);
      setError(err.message || 'Failed to complete scan. Please ensure the backend server is running.');
    } finally {
      setScanning(false);
    }
  };

  const triggerUrlScan = async (e) => {
    if (e) e.preventDefault();
    if (!repoUrl.trim()) {
      setError('Please enter a GitHub repository URL (e.g., https://github.com/owner/repo).');
      return;
    }
    try {
      setScanning(true);
      setError(null);
      const res = await fetch(`${API_BASE}/scan-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: repoUrl.trim() })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || `Scan failed with status ${res.status}`);
      }
      setFindings(data.findings || []);
      setHasScanned(true);
      setScanTarget(data.target_directory || repoUrl.trim());
      setLastScanTime(new Date().toLocaleTimeString());
    } catch (err) {
      console.error('Scan URL error:', err);
      setError(err.message || 'Failed to scan repository.');
    } finally {
      setScanning(false);
    }
  };

  const exportCBOM = async () => {
    try {
      const res = await fetch(`${API_BASE}/export/cbom`);
      if (!res.ok) throw new Error(`CBOM export failed: ${res.status}`);
      const data = await res.json();
      
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ecdat-cbom-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export error:', err);
      setError('Failed to export CBOM JSON.');
    }
  };

  const counts = {
    all: findings.length,
    high: findings.filter(f => f.risk_score === 'High').length,
    medium: findings.filter(f => f.risk_score === 'Medium').length,
    low: findings.filter(f => f.risk_score === 'Low').length,
  };

  return (
    <div className="container">
      {/* Header */}
      <header className="header">
        <div className="title-group">
          <h1>
            <ShieldAlert color="var(--accent)" size={24} />
            <span>ECDAT Dashboard</span>
          </h1>
          <p className="subtitle">
            Enterprise Cryptographic Discovery & Analysis Tool — Dual Engine (Semgrep + AST)
          </p>
        </div>

        <div className="btn-group">
          <button
            className="btn btn-secondary"
            onClick={exportCBOM}
            disabled={findings.length === 0 || scanning}
          >
            <Download size={15} />
            <span>Export CBOM JSON</span>
          </button>
          <button
            className="btn btn-primary"
            onClick={triggerScan}
            disabled={scanning}
          >
            {scanning ? (
              <>
                <RefreshCw size={15} className="spin" style={{ animation: 'spin 1s linear infinite' }} />
                <span>Scanning Repository...</span>
              </>
            ) : (
              <>
                <Play size={15} />
                <span>Run Discovery Scan</span>
              </>
            )}
          </button>
        </div>
      </header>

      {/* GitHub Repository Scan Bar (Prominent visual weight) */}
      <div className="scan-bar-card">
        <div className="scan-bar-header">
          <div className="scan-bar-title">
            <Globe size={18} color="var(--accent)" />
            <span>Scan Public GitHub Repository</span>
          </div>
          {scanTarget && (
            <div className="scan-target-tag">
              Target: <code>{scanTarget}</code>
            </div>
          )}
        </div>
        <form onSubmit={triggerUrlScan} className="scan-bar-form">
          <input
            type="url"
            className="scan-input"
            placeholder="https://github.com/owner/repository"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            disabled={scanning}
          />
          <button
            type="submit"
            className="btn btn-primary"
            disabled={scanning || !repoUrl.trim()}
          >
            {scanning ? (
              <>
                <RefreshCw size={15} className="spin" style={{ animation: 'spin 1s linear infinite' }} />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <GitBranch size={15} />
                <span>Scan GitHub Repo</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="alert-error">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Metric Cards (Quieter summary cards) */}
      <div className="metrics-row">
        <div className="metric-card">
          <div className="metric-label">Total Assets Scanned</div>
          <div className="metric-value">{findings.length}</div>
        </div>
        <div className="metric-card" style={{ borderColor: 'var(--risk-high-border)' }}>
          <div className="metric-label" style={{ color: 'var(--risk-high)' }}>High Risk</div>
          <div className="metric-value" style={{ color: 'var(--risk-high)' }}>{counts.high}</div>
        </div>
        <div className="metric-card" style={{ borderColor: 'var(--risk-medium-border)' }}>
          <div className="metric-label" style={{ color: 'var(--risk-medium)' }}>Medium Risk</div>
          <div className="metric-value" style={{ color: 'var(--risk-medium)' }}>{counts.medium}</div>
        </div>
        <div className="metric-card" style={{ borderColor: 'var(--risk-low-border)' }}>
          <div className="metric-label" style={{ color: 'var(--risk-low)' }}>Low Risk / Test</div>
          <div className="metric-value" style={{ color: 'var(--risk-low)' }}>{counts.low}</div>
        </div>
      </div>

      {/* Main Grid: Findings Table + Risk Distribution */}
      <div className="dashboard-grid">
        <div>
          <FilterBar
            activeFilter={activeFilter}
            onFilterChange={setActiveFilter}
            counts={counts}
          />
          <FindingsTable
            findings={findings}
            activeFilter={activeFilter}
            onSelectFinding={setSelectedFinding}
            scanning={scanning}
            hasScanned={hasScanned}
          />
        </div>

        <div>
          <RiskChart findings={findings} />
          {lastScanTime && (
            <div style={{ marginTop: '0.75rem', color: 'var(--text-muted)', fontSize: '0.75rem', textAlign: 'center' }}>
              Last scanned: {lastScanTime}
            </div>
          )}
        </div>
      </div>

      {/* Detail View Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}
