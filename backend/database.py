import sqlite3
import os
from typing import List, Dict, Any, Optional

def get_db_path(db_path: Optional[str] = None) -> str:
    if db_path:
        return db_path
    return os.environ.get("ECDAT_DB_PATH", os.path.join(os.path.dirname(__file__), "ecdat.db"))

def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: Optional[str] = None) -> None:
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT NOT NULL,
            line INTEGER NOT NULL,
            algorithm TEXT NOT NULL,
            confidence TEXT NOT NULL,
            exposure TEXT NOT NULL,
            exposure_reason TEXT DEFAULT '',
            risk_score TEXT NOT NULL,
            numeric_risk_score REAL DEFAULT 0.0,
            time_horizon TEXT DEFAULT '',
            score_explanation TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    for alter_stmt in [
        "ALTER TABLE findings ADD COLUMN exposure_reason TEXT DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN numeric_risk_score REAL DEFAULT 0.0",
        "ALTER TABLE findings ADD COLUMN time_horizon TEXT DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN score_explanation TEXT DEFAULT ''"
    ]:
        try:
            cursor.execute(alter_stmt)
        except sqlite3.OperationalError:
            pass
    conn.commit()
    conn.close()

def clear_findings(db_path: Optional[str] = None) -> None:
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM findings")
    conn.commit()
    conn.close()

def insert_finding(
    file: str,
    line: int,
    algorithm: str,
    confidence: str,
    exposure: str,
    risk_score: str,
    exposure_reason: str = "",
    db_path: Optional[str] = None,
    numeric_risk_score: float = 0.0,
    time_horizon: str = "",
    score_explanation: str = ""
) -> int:
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO findings (file, line, algorithm, confidence, exposure, exposure_reason, risk_score, numeric_risk_score, time_horizon, score_explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (file, line, algorithm, confidence, exposure, exposure_reason, risk_score, numeric_risk_score, time_horizon, score_explanation))
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id

def insert_findings_batch(findings: List[Dict[str, Any]], db_path: Optional[str] = None) -> None:
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    for f in findings:
        cursor.execute("""
            INSERT INTO findings (file, line, algorithm, confidence, exposure, exposure_reason, risk_score, numeric_risk_score, time_horizon, score_explanation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f["file"],
            f["line"],
            f["algorithm"],
            f["confidence"],
            f["exposure"],
            f.get("exposure_reason", ""),
            f["risk_score"],
            f.get("numeric_risk_score", 0.0),
            f.get("time_horizon", ""),
            f.get("score_explanation", "")
        ))
    conn.commit()
    conn.close()

def get_all_findings(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, file, line, algorithm, confidence, exposure, exposure_reason, risk_score, numeric_risk_score, time_horizon, score_explanation, created_at FROM findings ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

