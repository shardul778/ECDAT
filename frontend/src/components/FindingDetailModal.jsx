import React, { useState, useEffect } from 'react';
import { X, ArrowLeft, CheckCircle, AlertCircle, AlertTriangle, FileCode, Lightbulb, Info } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export function getRecommendation(algorithm) {
  const algoUpper = (algorithm || '').toUpperCase();
  if (algoUpper.includes('MD5')) {
    return 'Migrate to SHA-256 or SHA-3 for hashing; use Argon2id/bcrypt for password hashing.';
  }
  if (algoUpper.includes('SHA1') || algoUpper.includes('SHA-1')) {
    return 'Migrate to SHA-256, SHA-384, or SHA-512.';
  }
  if (algoUpper.includes('DES')) {
    return 'Replace DES with AES-256-GCM or ChaCha20-Poly1305.';
  }
  if (algoUpper.includes('RC4') || algoUpper.includes('ARC4')) {
    return 'Replace RC4 stream cipher with AES-256-GCM or ChaCha20-Poly1305.';
  }
  if (algoUpper.includes('HARDCODED')) {
    return 'Remove hardcoded secret; load securely from environment variables or a Secret Vault (e.g. AWS Secrets Manager, HashiCorp Vault).';
  }
  if (algoUpper.includes('WEAK RSA')) {
    return 'Upgrade RSA key length to at least 2048 (preferably 3072/4096) or transition to Post-Quantum Cryptography (ML-KEM/Kyber, ML-DSA/Dilithium).';
  }
  if (algoUpper.includes('RSA')) {
    return 'Classically secure, but prepare Post-Quantum Cryptography (PQC) migration strategy (NIST FIPS 203 / ML-KEM).';
  }
  return 'Adopt NIST-recommended post-quantum and modern cryptographic standards.';
}

export function getExplainability(finding) {
  const algoUpper = (finding.algorithm || '').toUpperCase();
  const exposure = finding.exposure || 'Internal-only';
  const confidence = finding.confidence || 'High (Dual-Engine)';
  const isTest = exposure === 'Test-only';

  let base = 10.0;
  let baseDesc = 'Standard cryptographic primitive (Base severity: 10/50)';
  if (['HARDCODED', 'DES', 'RC4', 'ARC4'].some(k => algoUpper.includes(k))) {
    base = 50.0;
    baseDesc = 'Broken symmetric cipher / hardcoded secret (Base severity: 50/50)';
  } else if (algoUpper.includes('WEAK RSA')) {
    base = 45.0;
    baseDesc = 'Inadequate RSA key length <2048 bits (Base severity: 45/50)';
  } else if (['MD5', 'SHA1', 'SHA-1', 'VULNERABLE DEPENDENCY'].some(k => algoUpper.includes(k))) {
    base = 40.0;
    baseDesc = 'Deprecated/broken hash or vulnerable dependency (Base severity: 40/50)';
  } else if (['RSA', 'ECC', 'ECDSA', 'ECDH', 'DSA', 'DH'].some(k => algoUpper.includes(k))) {
    base = 25.0;
    baseDesc = 'Classically secure, quantum-vulnerable public key crypto (Base severity: 25/50)';
  } else if (['AES', 'SHA-256', 'SHA256', 'SHA-512', 'SHA512', 'CHACHA'].some(k => algoUpper.includes(k))) {
    base = 5.0;
    baseDesc = 'Modern NIST-approved cryptographic primitive (Base severity: 5/50)';
  }

  let expWeight = 0.0;
  let expDesc = '+0 pts (Unclassified exposure)';
  if (exposure === 'Critical') {
    expWeight = 25.0;
    expDesc = '+25 pts (Critical security path / authentication context)';
  } else if (exposure === 'Externally Exposed') {
    expWeight = 20.0;
    expDesc = '+20 pts (Direct network / route exposure)';
  } else if (exposure === 'Internal-only') {
    expWeight = 5.0;
    expDesc = '+5 pts (Internal non-exposed module)';
  } else if (isTest) {
    expWeight = -25.0;
    expDesc = '-25 pts (Test-only file context downweighting)';
  }

  let confMult = 1.0;
  let confDesc = '1.0x multiplier (Dual-engine consensus: Semgrep + AST)';
  if (confidence.toLowerCase().includes('single') || confidence.toLowerCase().includes('medium')) {
    confMult = 0.7;
    confDesc = '0.7x multiplier (Single-engine detection)';
  }

  let raw = (base + Math.max(0.0, expWeight)) * confMult;
  if (isTest) {
    raw = Math.max(2.0, raw - 25.0);
  }
  const score = Math.round(Math.max(0.0, Math.min(100.0, raw)) * 10) / 10;

  let horizon = 'Monitor - no action required';
  if (['MD5', 'SHA1', 'SHA-1', 'DES', 'RC4', 'ARC4', 'HARDCODED', 'WEAK RSA', 'VULNERABLE DEPENDENCY'].some(k => algoUpper.includes(k))) {
    horizon = 'Immediate (0-3 months) - exploitable today';
  } else if (['RSA', 'ECC', 'ECDSA', 'ECDH', 'DSA', 'DH', 'DIFFIE-HELLMAN', 'ED25519', 'SECP'].some(k => algoUpper.includes(k))) {
    horizon = 'Medium-term (1-5 years) - plan PQC migration now';
  }

  const formula = isTest
    ? `(Base ${Math.round(base)} pts) × ${confMult}x - 25 pts (Test context) = ${score}/100`
    : `(Base ${Math.round(base)} pts + Exposure ${Math.round(expWeight)} pts) × ${confMult}x = ${score}/100`;

  return {
    score: finding.numeric_risk_score !== undefined ? finding.numeric_risk_score : score,
    horizon: finding.time_horizon || horizon,
    base,
    baseDesc,
    expWeight,
    expDesc,
    confMult,
    confDesc,
    formula
  };
}

export default function FindingDetailModal({ finding, onClose }) {
  const [snippetData, setSnippetData] = useState(null);
  const [loadingSnippet, setLoadingSnippet] = useState(true);

  useEffect(() => {
    if (!finding) return;

    let isMounted = true;
    setLoadingSnippet(true);
    setSnippetData(null);

    const fetchSnippet = async () => {
      try {
        const url = `${API_BASE}/snippet?file=${encodeURIComponent(finding.file)}&line=${finding.line}`;
        const res = await fetch(url);
        if (!res.ok) {
          if (isMounted) {
            setSnippetData({ status: 'unavailable', message: 'Source snippet unavailable' });
          }
          return;
        }
        const data = await res.json();
        if (isMounted) {
          setSnippetData(data);
        }
      } catch (err) {
        if (isMounted) {
          setSnippetData({ status: 'unavailable', message: 'Source snippet unavailable' });
        }
      } finally {
        if (isMounted) {
          setLoadingSnippet(false);
        }
      }
    };

    fetchSnippet();

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);

    return () => {
      isMounted = false;
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [finding, onClose]);

  if (!finding) return null;

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

  const recommendation = getRecommendation(finding.algorithm);
  const breakdown = getExplainability(finding);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div className="modal-header">
          <div className="modal-title-group">
            <button className="btn-back" onClick={onClose} title="Back to findings table">
              <ArrowLeft size={15} />
              <span>Back</span>
            </button>
            <div className="modal-title">
              <h2>{finding.algorithm}</h2>
              <span className={getRiskBadgeClass(finding.risk_score)}>
                {finding.risk_score} Risk ({breakdown.score}/100)
              </span>
              <span className={getExposureBadgeClass(finding.exposure)}>
                {finding.exposure}
              </span>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose} title="Close detail view">
            <X size={18} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="modal-body">
          {/* Metadata Grid */}
          <div className="detail-meta-grid">
            <div className="detail-meta-item">
              <div className="detail-meta-label">File Location</div>
              <div className="detail-meta-value code-font">{finding.file}</div>
            </div>
            <div className="detail-meta-item">
              <div className="detail-meta-label">Line Number</div>
              <div className="detail-meta-value code-font">Line {finding.line}</div>
            </div>
            <div className="detail-meta-item">
              <div className="detail-meta-label">Confidence</div>
              <div className="detail-meta-value" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                {finding.confidence?.includes('High') ? (
                  <CheckCircle size={14} color="var(--accent)" />
                ) : (
                  <AlertCircle size={14} color="var(--text-muted)" />
                )}
                <span>{finding.confidence}</span>
              </div>
            </div>
            <div className="detail-meta-item">
              <div className="detail-meta-label">Exposure Tier</div>
              <div className="detail-meta-value">
                <span className={getExposureBadgeClass(finding.exposure)}>
                  {finding.exposure}
                </span>
              </div>
            </div>
            <div className="detail-meta-item">
              <div className="detail-meta-label">Risk Score</div>
              <div className="detail-meta-value" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <span style={{
                  fontSize: '1rem',
                  fontWeight: 600,
                  color: finding.risk_score === 'High' ? 'var(--risk-high)' : finding.risk_score === 'Medium' ? 'var(--risk-medium)' : 'var(--risk-low)',
                  fontFamily: 'JetBrains Mono, monospace'
                }}>
                  {breakdown.score}
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>/ 100</span>
              </div>
            </div>
            <div className="detail-meta-item">
              <div className="detail-meta-label">Time Horizon</div>
              <div className="detail-meta-value" style={{
                fontSize: '0.825rem',
                color: 'var(--text-main)',
                fontWeight: 500
              }}>
                {breakdown.horizon}
              </div>
            </div>
          </div>

          {/* Risk Score Calculation Breakdown */}
          <div className="detail-section">
            <div className="detail-section-title">
              <Info size={15} color="var(--accent)" />
              <span>Risk Score Mathematical Breakdown</span>
            </div>
            <div className="detail-box" style={{ background: 'var(--bg-surface-subtle)', border: '1px solid var(--border-color)', padding: '1rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.65rem', marginBottom: '0.75rem' }}>
                <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', padding: '0.6rem 0.75rem', borderRadius: '0.35rem' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 500 }}>Base Severity</div>
                  <div style={{ fontSize: '0.825rem', color: 'var(--text-main)', fontWeight: 500, marginTop: '0.2rem' }}>{breakdown.baseDesc}</div>
                </div>
                <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', padding: '0.6rem 0.75rem', borderRadius: '0.35rem' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 500 }}>Exposure Context</div>
                  <div style={{ fontSize: '0.825rem', color: 'var(--text-main)', fontWeight: 500, marginTop: '0.2rem' }}>{breakdown.expDesc}</div>
                </div>
                <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', padding: '0.6rem 0.75rem', borderRadius: '0.35rem' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 500 }}>Confidence Weight</div>
                  <div style={{ fontSize: '0.825rem', color: 'var(--text-main)', fontWeight: 500, marginTop: '0.2rem' }}>{breakdown.confDesc}</div>
                </div>
              </div>
              <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '0.35rem', padding: '0.55rem 0.75rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 500 }}>Formula Calculation:</span>
                <code style={{ fontSize: '0.825rem', color: 'var(--accent)', background: 'var(--bg-surface-subtle)', padding: '0.15rem 0.5rem', borderRadius: '0.25rem', border: '1px solid var(--border-color)' }}>{breakdown.formula}</code>
              </div>
            </div>
          </div>

          {/* Exposure Why Section */}
          <div className="detail-section">
            <div className="detail-section-title">
              <Info size={15} color="var(--text-muted)" />
              <span>Exposure Context</span>
            </div>
            <div className="detail-box explain-box">
              {finding.exposure_reason || 'Standard internal module context.'}
            </div>
          </div>

          {/* Recommendation Section */}
          <div className="detail-section">
            <div className="detail-section-title">
              <Lightbulb size={15} color="var(--risk-medium)" />
              <span>Remediation Recommendation</span>
            </div>
            <div className="detail-box recommendation-box">
              {recommendation}
            </div>
          </div>

          {/* Code Snippet Section */}
          <div className="detail-section">
            <div className="detail-section-title">
              <FileCode size={15} color="var(--accent)" />
              <span>Source Code Context</span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 'normal' }}>
                (Line {finding.line} highlighted)
              </span>
            </div>

            {loadingSnippet ? (
              <div className="snippet-loading">
                <span>Loading source snippet...</span>
              </div>
            ) : snippetData && snippetData.status === 'success' && snippetData.lines?.length > 0 ? (
              <div className="snippet-container">
                <div className="snippet-file-bar">
                  <span>{finding.file}</span>
                  <span>Lines {snippetData.start_line}–{snippetData.end_line}</span>
                </div>
                <div className="snippet-code-block">
                  {snippetData.lines.map((l) => (
                    <div
                      key={l.line_number}
                      className={`snippet-line ${l.is_target ? 'snippet-line-target' : ''}`}
                    >
                      <span className="snippet-lineno">{l.line_number}</span>
                      <span className="snippet-code">{l.content}</span>
                      {l.is_target && (
                        <span className="snippet-target-badge">Vulnerable Line</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="snippet-unavailable">
                <AlertTriangle size={16} color="var(--risk-medium)" />
                <span>Source snippet unavailable</span>
              </div>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>
            Back to Findings Table
          </button>
        </div>
      </div>
    </div>
  );
}
