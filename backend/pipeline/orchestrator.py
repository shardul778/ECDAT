import os
from typing import List, Dict, Any, Optional
from backend.scanners.semgrep_scanner import run_semgrep_scan
from backend.scanners.ast_scanner import run_ast_scan
from backend.scanners.sca_scanner import run_sca_scan
from backend.pipeline.matcher import match_confidence
from backend.pipeline.exposure import tag_exposure
from backend.pipeline.scoring import calculate_risk, calculate_numeric_risk_score, get_time_horizon, explain_risk_score

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "crypto_rules.yaml")

def run_ecdat_pipeline(
    target_dir: str,
    rules_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Executes the full ECDAT scanning and analysis pipeline:
    1. Discovery: Semgrep + Python AST scanner + SCA Dependency scanner
    2. Confidence matching: Dual-engine comparison (High = 2 engines, Medium = 1 engine)
    3. Exposure tagging & Reason: Path keywords, Route decorators, Indirect call graphs
    4. Risk scoring: Rule-based score calculation + continuous 0-100 score + Mosca time horizon
    """
    rule_file = rules_path or DEFAULT_RULES_PATH
    
    # 1. Multi-engine discovery
    semgrep_findings = run_semgrep_scan(target_dir, rule_file)
    ast_findings = run_ast_scan(target_dir)
    sca_findings = run_sca_scan(target_dir, rule_file)

    # 2. Confidence matching
    matched = match_confidence(semgrep_findings, ast_findings)

    for sca_item in sca_findings:
        matched.append({
            "file": sca_item["file"],
            "line": sca_item["line"],
            "algorithm": sca_item["algorithm"],
            "confidence": "Medium (Single-Engine)",
            "engines": ["sca"],
            "is_test_context": False,
            "message": sca_item.get("message", "")
        })

    # 3. Exposure tagging & Risk scoring
    final_findings = []
    for item in matched:
        exposure, reason = tag_exposure(
            item["file"],
            item["line"],
            base_dir=target_dir,
            confidence=item.get("confidence")
        )
        risk = calculate_risk(item["algorithm"], exposure, is_test_context=item.get("is_test_context", False))
        numeric_score = calculate_numeric_risk_score(
            item["algorithm"],
            exposure,
            confidence=item.get("confidence", "High (Dual-Engine)"),
            is_test_context=item.get("is_test_context", False)
        )
        time_horizon = get_time_horizon(item["algorithm"])
        score_info = explain_risk_score(
            item["algorithm"],
            exposure,
            confidence=item.get("confidence", "High (Dual-Engine)"),
            is_test_context=item.get("is_test_context", False)
        )
        
        final_findings.append({
            "file": item["file"],
            "line": item["line"],
            "algorithm": item["algorithm"],
            "confidence": item["confidence"],
            "exposure": exposure,
            "exposure_reason": reason,
            "risk_score": risk,
            "numeric_risk_score": numeric_score,
            "time_horizon": time_horizon,
            "score_explanation": score_info["summary"],
            "score_breakdown": score_info,
            "engines": item.get("engines", [])
        })

    # Sort deterministically by file, then line
    final_findings.sort(key=lambda x: (x["file"], x["line"]))
    return final_findings
