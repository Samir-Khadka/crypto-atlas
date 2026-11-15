"""CBOM output: a CycloneDX 1.7 cryptographic bill of materials.

Every finding becomes a component of type ``cryptographic-asset``
with a ``cryptoProperties`` object. The document is validated
against the bundled CycloneDX 1.7 JSON schema before it is written
— a CBOM that fails schema validation is a bug, not an output.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .findings import Finding

_SCHEMA = Path(__file__).parent / "schema" / "bom-1.7.schema.json"


def _bom_ref(finding: Finding) -> str:
    digest = hashlib.sha256(
        f"{finding.file}:{finding.line}:{finding.rule_id}"
        .encode("utf-8")).hexdigest()[:12]
    return f"crypto-atlas:{digest}"


def _crypto_properties(finding: Finding) -> dict:
    props: dict = {"assetType": finding.asset_type}
    if finding.asset_type == "algorithm":
        algo: dict = {}
        if finding.primitive:
            algo["primitive"] = finding.primitive
        if finding.parameter_set:
            algo["parameterSetIdentifier"] = finding.parameter_set
        if finding.curve:
            algo["curve"] = finding.curve
        # classical strength in bits, when known
        if finding.key_size:
            algo["classicalSecurityLevel"] = \
                112 if finding.key_size <= 2048 else \
                128 if finding.key_size <= 3072 else 192
        # 0 = no security against a quantum attacker; 1+ = a NIST
        # post-quantum category (ML-KEM-768 is category 3)
        algo["nistQuantumSecurityLevel"] = \
            3 if finding.algorithm == "ML-KEM" else \
            2 if finding.algorithm in ("ML-DSA", "SLH-DSA") else 0
        props["algorithmProperties"] = algo
    elif finding.asset_type == "certificate":
        cert: dict = {}
        if finding.parameter_set:
            cert["signatureAlgorithmRef"] = finding.parameter_set
        props["certificateProperties"] = cert
    elif finding.asset_type == "protocol":
        proto: dict = {"type": "tls"}
        if finding.parameter_set:
            proto["version"] = finding.parameter_set
        props["protocolProperties"] = proto
    elif finding.asset_type == "related-crypto-material":
        material: dict = {"type": "secret-key"}
        if finding.parameter_set:
            material["algorithmRef"] = finding.parameter_set
        if finding.key_size:
            material["size"] = finding.key_size
        props["relatedCryptoMaterialProperties"] = material
    return props


def build_cbom(findings: list[Finding], target: str) -> dict:
    """The CycloneDX 1.7 document for a scan."""
    components = []
    for finding in findings:
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": _bom_ref(finding),
            "name": finding.parameter_set or finding.algorithm,
            "cryptoProperties": _crypto_properties(finding),
            "properties": [
                {"name": "crypto-atlas:rule",
                 "value": finding.rule_id},
                {"name": "crypto-atlas:file",
                 "value": finding.file},
                {"name": "crypto-atlas:line",
                 "value": str(finding.line)},
                {"name": "crypto-atlas:weakness",
                 "value": str(finding.weakness)},
                {"name": "crypto-atlas:evidence",
                 "value": finding.evidence},
            ],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "Crypto Atlas", "name": "crypto-atlas",
                       "version": __version__}],
            "component": {
                "type": "application",
                "bom-ref": "crypto-atlas:scan-target",
                "name": target,
            },
        },
        "components": components,
    }


def validate_cbom(document: dict) -> list[str]:
    """Schema errors, empty when the document is valid."""
    import jsonschema
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    return [f"{'.'.join(str(p) for p in e.path)}: {e.message}"
            for e in validator.iter_errors(document)]


def write_cbom(findings: list[Finding], target: str, path: Path) -> Path:
    """Write the CBOM, validated first. Raises ValueError when the
    document does not validate — that is a bug, not an output."""
    document = build_cbom(findings, target)
    errors = validate_cbom(document)
    if errors:
        raise ValueError(
            "CBOM failed CycloneDX 1.7 schema validation: "
            + "; ".join(errors))
    path.write_text(json.dumps(document, indent=2),
                    encoding="utf-8")
    return path
