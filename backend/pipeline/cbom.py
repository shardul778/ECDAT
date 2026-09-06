import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from backend.pipeline.scoring import get_recommendation

def _map_algorithm_crypto_properties(algorithm: str) -> Dict[str, Any]:
    """
    Maps our algorithm names to CycloneDX 1.6 cryptoProperties schema:
    assetType, primitive, parameterSetIdentifier, executionEnvironment, cryptoFunctions.
    """
    algo_upper = algorithm.upper()

    if "MD5" in algo_upper or "SHA1" in algo_upper or "SHA-1" in algo_upper:
        asset_type = "algorithm"
        primitive = "hash"
        crypto_functions = ["digest"]
    elif "DES" in algo_upper:
        asset_type = "algorithm"
        primitive = "block-cipher"
        crypto_functions = ["encrypt", "decrypt"]
    elif "RC4" in algo_upper or "ARC4" in algo_upper:
        asset_type = "algorithm"
        primitive = "stream-cipher"
        crypto_functions = ["encrypt", "decrypt"]
    elif "HARDCODED" in algo_upper:
        asset_type = "related-crypto-material"
        primitive = "unknown"
        crypto_functions = ["generate"]
    elif "RSA" in algo_upper:
        asset_type = "algorithm"
        primitive = "signature"
        crypto_functions = ["encrypt", "decrypt", "sign", "verify"]
    else:
        asset_type = "algorithm"
        primitive = "unknown"
        crypto_functions = ["unknown"]

    return {
        "assetType": asset_type,
        "algorithmProperties": {
            "primitive": primitive,
            "parameterSetIdentifier": algorithm,
            "executionEnvironment": "software-plain-ram",
            "cryptoFunctions": crypto_functions,
        },
        "oid": None,
    }

def _create_crypto_component(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Constructs a CycloneDX 1.6 cryptographic-asset component for an ECDAT finding.
    """
    file_path = finding.get("file", "unknown")
    line = finding.get("line", 1)
    algo = finding.get("algorithm", "Unknown")
    confidence = finding.get("confidence", "Medium")
    exposure = finding.get("exposure", "Internal-only")
    reason = finding.get("exposure_reason", "")
    risk = finding.get("risk_score", finding.get("risk", "Medium"))
    engines = finding.get("engines", [])
    engines_str = ",".join(engines) if isinstance(engines, list) else str(engines)
    rec = get_recommendation(algo)

    clean_algo = (
        algo.lower()
        .replace(" ", "-")
        .replace("(", "")
        .replace(")", "")
        .replace("<", "lt-")
        .replace(">", "gt-")
        .replace("=", "eq-")
    )
    bom_ref = f"crypto/{clean_algo}/{uuid.uuid4().hex[:8]}"
    crypto_properties = _map_algorithm_crypto_properties(algo)

    return {
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": algo,
        "description": reason or f"Cryptographic asset {algo} at {file_path}:{line}",
        "cryptoProperties": crypto_properties,
        "properties": [
            {"name": "ecdat:file", "value": file_path},
            {"name": "ecdat:line", "value": str(line)},
            {"name": "ecdat:confidence", "value": confidence},
            {"name": "ecdat:exposure", "value": exposure},
            {"name": "ecdat:exposureReason", "value": reason},
            {"name": "ecdat:riskScore", "value": str(risk)},
            {"name": "ecdat:recommendation", "value": rec},
            {"name": "ecdat:sourceEngines", "value": engines_str or "semgrep,ast"},
        ],
    }

def generate_cbom(findings: List[Dict[str, Any]], project_name: str = "sample_repo") -> Dict[str, Any]:
    """
    Generates a standards-compliant CycloneDX v1.6 CBOM (Cryptography Bill of Materials) JSON.
    Uses official 'cryptographic-asset' component type with 'cryptoProperties'.
    """
    components = [_create_crypto_component(f) for f in findings]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "ECDAT",
                        "version": "1.0.0",
                        "description": "Enterprise Cryptographic Discovery & Analysis Tool",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": project_name,
                "bom-ref": f"app/{project_name}",
            },
        },
        "components": components,
    }
