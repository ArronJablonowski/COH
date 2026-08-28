"""Closed pySigma backend construction and normalized response creation."""

from __future__ import annotations

from typing import Any

from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
from sigma.backends.kusto.kusto import KustoBackend
from sigma.backends.splunk.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation, SetStateTransformation
from sigma.processing.transformations.failure import StrictFieldMappingFailure

from .protocol import ProtocolDenied, make_response
from .yaml_profile import load_and_validate


class CompilationDenied(ValueError):
    """The rule is valid at the boundary but cannot produce a closed result."""


def compile_request(request: dict[str, Any]) -> dict[str, Any]:
    try:
        rule = load_and_validate(request["sigma_yaml"], request)
    except ProtocolDenied as error:
        reason = str(error)
        outcome = "needs_mapping" if reason in {"mapping_missing", "logsource_mismatch"} else "unsupported"
        code = "MAP001" if outcome == "needs_mapping" else "SIG001"
        return make_response(request, outcome, [reason], [_diagnostic(code, reason)], "")
    try:
        native_query = _convert(rule, request)
    except Exception:
        return make_response(request, "unsupported", ["conversion_denied"], [_diagnostic("SIG002", "conversion_denied")], "")
    maximum = request["policy"]["maximum_native_query_bytes"]
    if not native_query or len(native_query.encode()) > maximum or "\x00" in native_query:
        return make_response(request, "denied", ["native_output_denied"], [_diagnostic("OUT001", "native_output_denied")], "")
    return make_response(request, "compiled_untrusted", [], [], native_query)


def _convert(rule: dict[str, Any], request: dict[str, Any]) -> str:
    mapping = {item["source"]: item["target"] for item in request["mapping"]["fields"]}
    items = [
        ProcessingItem(FieldMappingTransformation(mapping), identifier="coh_exact_field_mapping"),
        ProcessingItem(StrictFieldMappingFailure(), identifier="coh_strict_field_mapping"),
    ]
    target = request["target"]["target"]
    resource = request["mapping"]["target_resource"]
    if target == "elastic":
        items.append(ProcessingItem(SetStateTransformation("index", resource), identifier="coh_exact_resource"))
        backend = ESQLBackend(ProcessingPipeline(items=items), collect_errors=False)
    elif target == "splunk":
        backend = SplunkBackend(ProcessingPipeline(items=items), collect_errors=False)
    elif target == "sentinel":
        backend = KustoBackend(ProcessingPipeline(items=items), collect_errors=False)
    else:
        raise CompilationDenied("backend_denied")
    collection = SigmaCollection.from_dicts([rule], collect_errors=False, collect_filters=False, resolve_references=False)
    results = backend.convert(collection, output_format="default", callback=None)
    if not isinstance(results, list) or len(results) != 1 or not isinstance(results[0], str):
        raise CompilationDenied("result_cardinality")
    query = results[0].strip()
    if target == "splunk":
        query = f"index={resource} {query}"
    elif target == "sentinel":
        query = f"{resource} | where {query}"
    return query


def _diagnostic(code: str, reason: str) -> dict[str, str]:
    return {"code": code, "severity": "error", "class": reason, "location": "detection.condition"}
