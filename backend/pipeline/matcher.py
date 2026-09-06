import os
import re
from typing import List, Dict, Any

TEST_PATH_PATTERN = re.compile(r"(^|[/\\])(tests?|mock|mocks|conftest|fixtures?)([/\\]|$)|test_|_test\.py$", re.IGNORECASE)

def is_test_context(file_path: str) -> bool:
    normalized = file_path.replace("\\", "/").lower()
    return bool(TEST_PATH_PATTERN.search(normalized))

def match_confidence(
    semgrep_findings: List[Dict[str, Any]],
    ast_findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Combines Semgrep and AST findings and calculates confidence level:
    - Both agree on file/line/algorithm -> 'High (Dual-Engine)'
    - Only one flags -> 'Medium (Single-Engine)'
    Test-file context does NOT affect Confidence.
    """
    matched_results = []
    ast_used = set()
    
    for s_item in semgrep_findings:
        s_file = s_item["file"].replace("\\", "/")
        s_line = s_item["line"]
        s_algo = s_item["algorithm"]
        
        # Check if matched by any AST finding on same file & algorithm (within +/- 1 line)
        ast_match_idx = None
        for i, a_item in enumerate(ast_findings):
            if i in ast_used:
                continue
            a_file = a_item["file"].replace("\\", "/")
            a_line = a_item["line"]
            a_algo = a_item["algorithm"]
            
            if s_file.lower() == a_file.lower() and s_algo == a_algo and abs(s_line - a_line) <= 1:
                ast_match_idx = i
                break
                
        if ast_match_idx is not None:
            ast_used.add(ast_match_idx)
            confidence = "High (Dual-Engine)"
            engines = ["semgrep", "ast"]
        else:
            confidence = "Medium (Single-Engine)"
            engines = ["semgrep"]

        matched_results.append({
            "file": s_file,
            "line": s_line,
            "algorithm": s_algo,
            "confidence": confidence,
            "engines": engines,
            "is_test_context": is_test_context(s_file)
        })

    # Add remaining AST findings that weren't matched in Semgrep
    for i, a_item in enumerate(ast_findings):
        if i in ast_used:
            continue
        a_file = a_item["file"].replace("\\", "/")
        a_line = a_item["line"]
        a_algo = a_item["algorithm"]
        
        matched_results.append({
            "file": a_file,
            "line": a_line,
            "algorithm": a_algo,
            "confidence": "Medium (Single-Engine)",
            "engines": ["ast"],
            "is_test_context": is_test_context(a_file)
        })

    return matched_results
