"""Strict wire protocol and Go-compatible domain-separated digests."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

REQUEST_VERSION = "coh.pysigma-helper-request/v1"
RESPONSE_VERSION = "coh.pysigma-helper-response/v1"
CONTRACT_VERSION = "1.0.0"
SIGMA_PROFILE = "sigma-basic-2.1.0-coh-v1"
COMPILER_VERSION = "pysigma-1.5.0-coh-1.0.0"
MAXIMUM_DOCUMENT_BYTES = 1 << 20

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UUID7 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
_FIELD = re.compile(r"[A-Za-z_@][A-Za-z0-9_.@-]{0,127}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z\Z")

TARGETS: dict[str, tuple[str, str, str, str, str, str]] = {
    "elastic": ("esql", "pysigma-backend-elasticsearch", "2.1.0", "5bf3529d1450e46b6a937ad29ecf0e122fbadf9d", "ESQLBackend", "default"),
    "sentinel": ("kql", "pysigma-backend-kusto", "1.0.1", "c83f737a39f1084f30022150482f8dbbc035034b", "KustoBackend", "default"),
    "splunk": ("spl", "pysigma-backend-splunk", "2.1.0", "68a5e382f1d57a14337c6e66022af34da1e3bfe6", "SplunkBackend", "default"),
}


class ProtocolDenied(ValueError):
    """A request cannot cross the helper boundary."""


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ProtocolDenied("duplicate_json")
        result[key] = value
    return result


def decode_request(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAXIMUM_DOCUMENT_BYTES or b"\x00" in raw:
        raise ProtocolDenied("document_bound")
    try:
        request = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ProtocolDenied) as error:
        raise ProtocolDenied("document_ambiguous") from error
    if not isinstance(request, dict):
        raise ProtocolDenied("document_type")
    normalized = _normalize_request(request)
    if request != normalized or request["request_digest"] != request_digest(normalized):
        raise ProtocolDenied("request_binding")
    return normalized


def _exact(value: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ProtocolDenied("object_shape")
    return value


def _string(value: Any, maximum: int, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum or "\x00" in value:
        raise ProtocolDenied("string_bound")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ProtocolDenied("string_shape")
    return value


def _digest(value: Any) -> str:
    value = _string(value, 71)
    if _DIGEST.fullmatch(value) is None:
        raise ProtocolDenied("digest_shape")
    return value


def _timestamp(value: Any) -> str:
    value = _string(value, 64)
    if _TIMESTAMP.fullmatch(value) is None or "." in value and value[:-1].endswith("0"):
        raise ProtocolDenied("timestamp_shape")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProtocolDenied("timestamp_shape") from error
    return value


def _normalize_target(value: Any) -> dict[str, str]:
    keys = ("target", "native_language", "backend_package", "backend_version", "backend_commit", "backend_class", "output_format")
    source = _exact(value, keys)
    result = {key: _string(source[key], 128) for key in keys}
    expected = TARGETS.get(result["target"])
    if expected is None or tuple(result[key] for key in keys[1:]) != expected:
        raise ProtocolDenied("backend_binding")
    return result


def _normalize_policy(value: Any) -> dict[str, Any]:
    keys = ("profile", "maximum_sigma_bytes", "maximum_yaml_nodes", "maximum_yaml_depth", "maximum_mapping_entries", "maximum_sequence_entries", "maximum_scalar_bytes", "maximum_scalars", "maximum_selections", "maximum_detection_items", "maximum_detection_values", "maximum_condition_tokens", "maximum_condition_depth", "maximum_expanded_terms", "maximum_native_query_bytes")
    source = _exact(value, keys)
    ceilings = (131072, 4096, 32, 2048, 2048, 16384, 4096, 64, 512, 2048, 512, 32, 2048, 262144)
    result: dict[str, Any] = {"profile": _string(source["profile"], 64)}
    if result["profile"] != SIGMA_PROFILE:
        raise ProtocolDenied("profile_binding")
    for key, ceiling in zip(keys[1:], ceilings, strict=True):
        item = source[key]
        if isinstance(item, bool) or not isinstance(item, int) or item < 1 or item > ceiling:
            raise ProtocolDenied("policy_bound")
        result[key] = item
    return result


def _normalize_identity(value: Any) -> dict[str, str]:
    keys = ("name", "version", "rid", "artifact_digest", "package_closure_digest", "runtime_digest", "backend_matrix_digest", "profile_digest")
    source = _exact(value, keys)
    result = {key: _string(source[key], 128) for key in keys[:3]}
    result.update({key: _digest(source[key]) for key in keys[3:]})
    if result["name"] != "coh-pysigma-helper" or result["version"] != COMPILER_VERSION or result["rid"] not in {"osx-arm64", "linux-x64", "linux-arm64"}:
        raise ProtocolDenied("helper_identity")
    return result


def _normalize_mapping(value: Any) -> dict[str, Any]:
    keys = ("mapping_id", "revision", "target_resource", "logsource", "fields", "source_schema_digest", "target_schema_digest", "mapping_digest")
    source = _exact(value, keys)
    logsource_keys = ("category", "product", "service", "definition")
    source_logsource = _exact(source["logsource"], logsource_keys)
    logsource = {key: source_logsource[key] for key in logsource_keys}
    for key in ("category", "product"):
        _string(logsource[key], 128, _TOKEN)
    if logsource["service"] != "":
        _string(logsource["service"], 128, _TOKEN)
    if not isinstance(logsource["definition"], str) or len(logsource["definition"].encode()) > 256 or any(character in logsource["definition"] for character in "\x00\r\n"):
        raise ProtocolDenied("logsource_shape")
    fields = source["fields"]
    if not isinstance(fields, list) or not 1 <= len(fields) <= 256:
        raise ProtocolDenied("mapping_bound")
    normalized_fields: list[dict[str, str]] = []
    for item in fields:
        entry = _exact(item, ("source", "target", "data_type"))
        normalized_fields.append({"source": _string(entry["source"], 128, _FIELD), "target": _string(entry["target"], 128, _FIELD), "data_type": _string(entry["data_type"], 16)})
    if normalized_fields != sorted(normalized_fields, key=lambda item: item["source"]) or len({item["source"] for item in normalized_fields}) != len(fields) or len({item["target"] for item in normalized_fields}) != len(fields):
        raise ProtocolDenied("mapping_ambiguous")
    if any(item["data_type"] not in {"bool", "datetime", "float", "integer", "ip", "keyword", "string"} for item in normalized_fields):
        raise ProtocolDenied("mapping_type")
    revision = source["revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ProtocolDenied("mapping_revision")
    result = {"mapping_id": _string(source["mapping_id"], 36, _UUID7), "revision": revision, "target_resource": _string(source["target_resource"], 128, _TOKEN), "logsource": logsource, "fields": normalized_fields, "source_schema_digest": _digest(source["source_schema_digest"]), "target_schema_digest": _digest(source["target_schema_digest"]), "mapping_digest": _digest(source["mapping_digest"])}
    if result["mapping_digest"] != mapping_digest(result):
        raise ProtocolDenied("mapping_binding")
    return result


def _normalize_request(value: dict[str, Any]) -> dict[str, Any]:
    keys = ("schema_version", "contract_version", "request_id", "operation", "sigma_yaml", "sigma_digest", "sigma_profile", "target", "mapping", "capability_digest", "qualification_digest", "policy", "helper_identity_expectation", "deadline", "request_digest")
    source = _exact(value, keys)
    result = {
        "schema_version": _string(source["schema_version"], 64), "contract_version": _string(source["contract_version"], 16),
        "request_id": _string(source["request_id"], 36, _UUID7), "operation": _string(source["operation"], 32),
        "sigma_yaml": _string(source["sigma_yaml"], 131072), "sigma_digest": _digest(source["sigma_digest"]),
        "sigma_profile": _string(source["sigma_profile"], 64), "target": _normalize_target(source["target"]),
        "mapping": _normalize_mapping(source["mapping"]), "capability_digest": _digest(source["capability_digest"]),
        "qualification_digest": _digest(source["qualification_digest"]), "policy": _normalize_policy(source["policy"]),
        "helper_identity_expectation": _normalize_identity(source["helper_identity_expectation"]),
        "deadline": _timestamp(source["deadline"]), "request_digest": _digest(source["request_digest"]),
    }
    if result["schema_version"] != REQUEST_VERSION or result["contract_version"] != CONTRACT_VERSION or result["operation"] != "sigma.compile" or result["sigma_profile"] != SIGMA_PROFILE:
        raise ProtocolDenied("protocol_binding")
    if result["sigma_digest"] != domain_digest("COH-SIGMA-SOURCE-V1\0", result["sigma_yaml"]):
        raise ProtocolDenied("sigma_binding")
    return result


def domain_digest(domain: str, value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    encoded = encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return "sha256:" + hashlib.sha256(domain.encode() + encoded.encode()).hexdigest()


def mapping_digest(value: dict[str, Any]) -> str:
    candidate = dict(value)
    candidate["mapping_digest"] = ""
    return domain_digest("COH-SIGMA-MAPPING-V1\0", candidate)


def request_digest(value: dict[str, Any]) -> str:
    candidate = dict(value)
    candidate["request_digest"] = ""
    return domain_digest("COH-SIGMA-COMPILE-REQUEST-V1\0", candidate)


def make_response(request: dict[str, Any], outcome: str, reasons: list[str], diagnostics: list[dict[str, str]], native_query: str) -> dict[str, Any]:
    native_digest = domain_digest("COH-SIGMA-NATIVE-QUERY-V1\0", native_query) if native_query else ""
    provenance = {"request_digest": request["request_digest"], "sigma_digest": request["sigma_digest"], "mapping_digest": request["mapping"]["mapping_digest"], "target_schema_digest": request["mapping"]["target_schema_digest"], "native_query_digest": native_digest, "outcome": outcome}
    response = {
        "schema_version": RESPONSE_VERSION, "contract_version": CONTRACT_VERSION,
        "request_id": request["request_id"], "request_digest": request["request_digest"], "outcome": outcome,
        "reason_codes": sorted(reasons), "diagnostics": sorted(diagnostics, key=lambda item: (item["code"], item["class"], item["location"])),
        "target": request["target"], "sigma_digest": request["sigma_digest"], "mapping_digest": request["mapping"]["mapping_digest"],
        "target_schema_digest": request["mapping"]["target_schema_digest"], "native_query": native_query,
        "native_query_digest": native_digest, "helper_identity": request["helper_identity_expectation"],
        "provenance_digest": domain_digest("COH-SIGMA-HELPER-PROVENANCE-V1\0", provenance), "response_digest": "",
    }
    response["response_digest"] = domain_digest("COH-SIGMA-COMPILE-RESPONSE-V1\0", response)
    return response


def generic_denial() -> bytes:
    return b'{"schema_version":"coh.pysigma-helper-response/v1","contract_version":"1.0.0","outcome":"denied","reason_codes":["request_denied"]}'


def encode(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
