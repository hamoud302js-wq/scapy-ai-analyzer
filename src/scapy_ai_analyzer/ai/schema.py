"""AI response schema and validation.

The AI layer is treated as an untrusted component. Whatever the provider
returns is validated before it becomes a ``Finding``:

* the payload must be a JSON object with the expected keys and types,
* ``severity`` must be one of the known values,
* ``confidence`` must lie within 0..1,
* every ``evidence_refs`` entry must resolve to real evidence in the store.

A response that fails validation is either repaired (for recoverable problems)
or rejected. Rejection never removes the deterministic results: the packet
statistics, flows, and rule alerts are already computed and are reported
regardless.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..evidence.evidence_store import EvidenceStore
from ..models.finding import SEVERITIES, Finding

REQUIRED_FIELDS = ("analysis_summary", "finding_type", "severity")
OPTIONAL_LIST_FIELDS = (
    "observations",
    "evidence_refs",
    "alternative_explanations",
    "limitations",
    "recommended_next_steps",
)

# Confidence is a self-reported model estimate, not a calibrated probability.
CONFIDENCE_DISCLAIMER = (
    "Confidence is a self-reported model estimate and is not a calibrated probability."
)

# Text that looks like an attempt to override the system prompt.
INJECTION_MARKERS = (
    "ignore previous instructions",
    "ignore all previous",
    "disregard previous",
    "system prompt",
    "you are now",
    "new instructions:",
    "override your",
    "reveal your prompt",
)

MAX_FIELD_LENGTH = 2000
MAX_LIST_ITEMS = 30


@dataclass
class ValidationResult:
    """Outcome of validating a raw AI payload."""

    finding: Optional[Finding] = None
    valid: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def extract_json_payload(raw: str) -> tuple[Optional[dict], list[str]]:
    """Pull a JSON object out of a provider response.

    Handles the common cases where a model wraps JSON in prose or a fenced code
    block. Returns ``(payload, warnings)``; ``payload`` is ``None`` when no
    usable JSON object is present.
    """
    warnings: list[str] = []
    if raw is None:
        return None, ["empty_response"]
    text = raw.strip()
    if not text:
        return None, ["empty_response"]

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed, warnings
        warnings.append("json_root_not_object")
        return None, warnings
    except json.JSONDecodeError:
        pass

    # Try fenced code blocks first, then the outermost braces.
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidates = []
    if fenced:
        candidates.append(fenced.group(1))
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        candidates.append(text[first_brace : last_brace + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                warnings.append("json_extracted_from_wrapped_text")
                return parsed, warnings
        except json.JSONDecodeError:
            continue

    return None, ["no_valid_json_object"]


def _coerce_string_list(value: Any, field_name: str, warnings: list[str]) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value[:MAX_FIELD_LENGTH]]
    if not isinstance(value, list):
        warnings.append(f"{field_name}_not_a_list")
        return []
    result: list[str] = []
    for item in value[:MAX_LIST_ITEMS]:
        if isinstance(item, str):
            result.append(item[:MAX_FIELD_LENGTH])
        elif isinstance(item, (int, float, bool)):
            result.append(str(item))
        else:
            warnings.append(f"{field_name}_item_dropped")
    return result


def validate_response(
    payload: dict[str, Any],
    store: EvidenceStore,
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> ValidationResult:
    """Validate a parsed AI payload against the schema and the evidence store."""
    result = ValidationResult()

    if not isinstance(payload, dict):
        result.errors.append("response_not_an_object")
        return result

    missing = [name for name in REQUIRED_FIELDS if name not in payload]
    if missing:
        result.errors.append(f"missing_required_fields: {', '.join(missing)}")
        return result

    summary = payload.get("analysis_summary")
    if not isinstance(summary, str) or not summary.strip():
        result.errors.append("analysis_summary_must_be_a_non_empty_string")
        return result
    summary = summary.strip()[:MAX_FIELD_LENGTH]

    finding_type = payload.get("finding_type")
    if not isinstance(finding_type, str) or not finding_type.strip():
        result.errors.append("finding_type_must_be_a_non_empty_string")
        return result
    finding_type = finding_type.strip()[:200]

    severity = payload.get("severity")
    if not isinstance(severity, str) or severity.strip().lower() not in SEVERITIES:
        result.errors.append(
            f"severity_must_be_one_of: {', '.join(SEVERITIES)}"
        )
        return result
    severity = severity.strip().lower()

    confidence: Optional[float] = None
    raw_confidence = payload.get("confidence")
    if raw_confidence is not None:
        if isinstance(raw_confidence, bool) or not isinstance(raw_confidence, (int, float)):
            result.warnings.append("confidence_not_numeric_ignored")
        else:
            value = float(raw_confidence)
            if 0.0 <= value <= 1.0:
                confidence = round(value, 4)
            else:
                result.warnings.append("confidence_out_of_range_ignored")

    observations = _coerce_string_list(payload.get("observations"), "observations", result.warnings)
    alternatives = _coerce_string_list(
        payload.get("alternative_explanations"), "alternative_explanations", result.warnings
    )
    limitations = _coerce_string_list(payload.get("limitations"), "limitations", result.warnings)
    next_steps = _coerce_string_list(
        payload.get("recommended_next_steps"), "recommended_next_steps", result.warnings
    )
    evidence_refs = _coerce_string_list(payload.get("evidence_refs"), "evidence_refs", result.warnings)

    # The critical check: references must resolve to evidence that exists.
    check = store.verify_references(evidence_refs)
    if check.invalid:
        result.warnings.append(
            "invalid_evidence_refs_removed: " + ", ".join(check.invalid[:10])
        )

    result.warnings.extend(
        _detect_injection_markers([summary], observations, alternatives)
    )

    if not check.valid:
        result.warnings.append("no_valid_evidence_refs")

    result.finding = Finding(
        analysis_summary=summary,
        finding_type=finding_type,
        severity=severity,
        confidence=confidence,
        observations=observations,
        evidence_refs=check.valid,
        alternative_explanations=alternatives,
        limitations=limitations,
        recommended_next_steps=next_steps,
        provider=provider,
        model=model,
        validation_status="valid" if not result.warnings else "valid_with_warnings",
        validation_warnings=list(result.warnings),
    )
    result.valid = True
    return result


def _detect_injection_markers(*text_groups: list[str]) -> list[str]:
    """Flag prompt-injection-shaped text found in model output.

    Packet content is untrusted input. If it influenced the model into emitting
    instruction-like text, the report should say so rather than present it as a
    finding.
    """
    warnings: list[str] = []
    for group in text_groups:
        for item in group:
            lowered = item.lower()
            for marker in INJECTION_MARKERS:
                if marker in lowered:
                    warnings.append("possible_prompt_injection_in_output")
                    return warnings
    return warnings


def build_rejected_finding(
    reason: str,
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> Finding:
    """Represent a failed AI call without losing the deterministic results."""
    return Finding(
        analysis_summary="AI analysis was not available or its response failed validation.",
        finding_type="ai_unavailable",
        severity="info",
        confidence=None,
        observations=[],
        evidence_refs=[],
        alternative_explanations=[],
        limitations=[
            reason,
            "Packet statistics, flows, and rule alerts in this report were produced "
            "without AI and remain valid.",
        ],
        recommended_next_steps=[
            "Review the rule alerts and referenced flows directly.",
        ],
        provider=provider,
        model=model,
        validation_status="rejected",
        validation_warnings=[reason],
    )
