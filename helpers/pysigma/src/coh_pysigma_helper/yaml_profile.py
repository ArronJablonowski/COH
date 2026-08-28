"""Alias-free YAML loader and closed Sigma 2.1 basic-rule profile."""

from __future__ import annotations

import math
import re
from typing import Any

import yaml
from yaml.composer import ComposerError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, ScalarNode

from .protocol import ProtocolDenied

_ALLOWED_TAGS = {
    "tag:yaml.org,2002:map", "tag:yaml.org,2002:seq", "tag:yaml.org,2002:str",
    "tag:yaml.org,2002:int", "tag:yaml.org,2002:float", "tag:yaml.org,2002:bool", "tag:yaml.org,2002:null",
}
_TOP_LEVEL = {"title", "id", "status", "description", "author", "date", "modified", "references", "tags", "falsepositives", "level", "license", "fields", "logsource", "detection"}
_LOGSOURCE = {"category", "product", "service", "definition"}
_MODIFIERS = {"contains", "startswith", "endswith", "all", "exists", "cidr", "lt", "lte", "gt", "gte", "neq"}
_SELECTION = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_FIELD = re.compile(r"[A-Za-z_@][A-Za-z0-9_.@-]{0,127}\Z")
_CONDITION_TOKEN = re.compile(r"\s*(?:(1|all)\s+of\s+([A-Za-z][A-Za-z0-9_]*)\*|(and|or|not)|([()])|([A-Za-z][A-Za-z0-9_]*))")


class BoundedLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects graph construction and bounds composition."""

    def __init__(self, stream: str, limits: dict[str, int]):
        super().__init__(stream)
        self._limits = limits
        self._node_count = 0
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(AliasEvent):
            raise ComposerError(None, None, "aliases are denied", self.peek_event().start_mark)
        event = self.peek_event()
        if event.anchor is not None or event.tag is not None and event.tag not in _ALLOWED_TAGS:
            raise ComposerError(None, None, "anchors or tags are denied", event.start_mark)
        self._node_count += 1
        self._depth += 1
        if self._node_count > self._limits["maximum_yaml_nodes"] or self._depth > self._limits["maximum_yaml_depth"]:
            raise ComposerError(None, None, "YAML complexity exceeded", event.start_mark)
        try:
            node = super().compose_node(parent, index)
        finally:
            self._depth -= 1
        if node.tag not in _ALLOWED_TAGS:
            raise ComposerError(None, None, "resolved YAML tag is denied", node.start_mark)
        return node

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[str, Any]:
        if not isinstance(node, MappingNode):
            raise ProtocolDenied("mapping_type")
        result: dict[str, Any] = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, ScalarNode) or key_node.tag != "tag:yaml.org,2002:str":
                raise ProtocolDenied("mapping_key")
            key = self.construct_object(key_node, deep=False)
            if not isinstance(key, str) or key == "<<" or key in result:
                raise ProtocolDenied("mapping_duplicate")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


BoundedLoader.add_constructor("tag:yaml.org,2002:map", BoundedLoader.construct_mapping)


def load_and_validate(source: str, request: dict[str, Any]) -> dict[str, Any]:
    policy = request["policy"]
    if len(source.encode()) > policy["maximum_sigma_bytes"]:
        raise ProtocolDenied("sigma_oversize")
    loader = BoundedLoader(source, policy)
    try:
        rule = loader.get_single_data()
    except (yaml.YAMLError, ProtocolDenied) as error:
        raise ProtocolDenied("yaml_denied") from error
    finally:
        loader.dispose()
    counts = {"mapping": 0, "sequence": 0, "scalars": 0}
    _validate_primitive_tree(rule, policy, counts)
    _validate_rule(rule, request)
    return rule


def _validate_primitive_tree(value: Any, policy: dict[str, int], counts: dict[str, int]) -> None:
    if isinstance(value, dict):
        counts["mapping"] += len(value)
        if counts["mapping"] > policy["maximum_mapping_entries"]:
            raise ProtocolDenied("mapping_bound")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolDenied("mapping_key")
            _validate_scalar(key, policy, counts)
            _validate_primitive_tree(item, policy, counts)
    elif isinstance(value, list):
        counts["sequence"] += len(value)
        if counts["sequence"] > policy["maximum_sequence_entries"]:
            raise ProtocolDenied("sequence_bound")
        for item in value:
            _validate_primitive_tree(item, policy, counts)
    else:
        _validate_scalar(value, policy, counts)


def _validate_scalar(value: Any, policy: dict[str, int], counts: dict[str, int]) -> None:
    counts["scalars"] += 1
    if counts["scalars"] > policy["maximum_scalars"] or not isinstance(value, (str, int, float, bool, type(None))):
        raise ProtocolDenied("scalar_type")
    if isinstance(value, str) and (len(value.encode()) > policy["maximum_scalar_bytes"] or "\x00" in value):
        raise ProtocolDenied("scalar_bound")
    if isinstance(value, float) and not math.isfinite(value):
        raise ProtocolDenied("scalar_nonfinite")


def _validate_rule(rule: Any, request: dict[str, Any]) -> None:
    if not isinstance(rule, dict) or not {"title", "logsource", "detection"}.issubset(rule) or not set(rule).issubset(_TOP_LEVEL):
        raise ProtocolDenied("rule_shape")
    if "id" in rule and not isinstance(rule["id"], str):
        raise ProtocolDenied("rule_id")
    logsource = rule["logsource"]
    if not isinstance(logsource, dict) or not {"category", "product"}.issubset(logsource) or not set(logsource).issubset(_LOGSOURCE):
        raise ProtocolDenied("logsource_shape")
    expected = request["mapping"]["logsource"]
    for key in _LOGSOURCE:
        if str(logsource.get(key, "")) != expected[key]:
            raise ProtocolDenied("logsource_mismatch")
    _validate_metadata(rule)
    _validate_detection(rule["detection"], request)


def _validate_metadata(rule: dict[str, Any]) -> None:
    scalar_fields = {"title", "id", "status", "description", "author", "date", "modified", "level", "license"}
    for key in scalar_fields & set(rule):
        if not isinstance(rule[key], str):
            raise ProtocolDenied("metadata_type")
    list_limits = {"references": 32, "tags": 64, "falsepositives": 32, "fields": 256}
    for key, maximum in list_limits.items():
        if key not in rule:
            continue
        if not isinstance(rule[key], list) or len(rule[key]) > maximum or any(not isinstance(item, str) for item in rule[key]):
            raise ProtocolDenied("metadata_bound")


def _validate_detection(detection: Any, request: dict[str, Any]) -> None:
    policy = request["policy"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise ProtocolDenied("detection_shape")
    names = sorted(key for key in detection if key != "condition")
    if not names or len(names) > policy["maximum_selections"] or any(_SELECTION.fullmatch(name) is None for name in names):
        raise ProtocolDenied("selection_shape")
    mapped = {item["source"] for item in request["mapping"]["fields"]}
    counts = {"items": 0, "values": 0}
    for name in names:
        _validate_selection(detection[name], mapped, policy, counts)
    _validate_condition(detection["condition"], names, policy)


def _validate_selection(value: Any, mapped: set[str], policy: dict[str, int], counts: dict[str, int]) -> None:
    if isinstance(value, list):
        if not value:
            raise ProtocolDenied("selection_empty")
        for item in value:
            _validate_selection(item, mapped, policy, counts)
        return
    if not isinstance(value, dict) or not value:
        raise ProtocolDenied("selection_type")
    for expression, item in value.items():
        counts["items"] += 1
        if counts["items"] > policy["maximum_detection_items"] or not isinstance(expression, str):
            raise ProtocolDenied("detection_item_bound")
        parts = expression.split("|")
        if _FIELD.fullmatch(parts[0]) is None or parts[0] not in mapped:
            raise ProtocolDenied("mapping_missing")
        if any(modifier not in _MODIFIERS for modifier in parts[1:]) or len(parts[1:]) != len(set(parts[1:])):
            raise ProtocolDenied("modifier_unsupported")
        values = item if isinstance(item, list) else [item]
        if not values:
            raise ProtocolDenied("detection_value_empty")
        counts["values"] += len(values)
        if counts["values"] > policy["maximum_detection_values"] or any(isinstance(candidate, (dict, list)) for candidate in values):
            raise ProtocolDenied("detection_value_bound")
        if "exists" in parts[1:] and (len(values) != 1 or not isinstance(values[0], bool)):
            raise ProtocolDenied("exists_type")
        if set(parts[1:]) & {"lt", "lte", "gt", "gte"} and any(isinstance(candidate, bool) or not isinstance(candidate, (int, float)) for candidate in values):
            raise ProtocolDenied("comparison_type")


def _validate_condition(value: Any, names: list[str], policy: dict[str, int]) -> None:
    if not isinstance(value, str) or not value:
        raise ProtocolDenied("condition_type")
    position = 0
    tokens = 0
    depth = 0
    expanded = 0
    while position < len(value):
        match = _CONDITION_TOKEN.match(value, position)
        if match is None:
            raise ProtocolDenied("condition_token")
        position = match.end()
        tokens += 1
        if match.group(2) is not None:
            matches = [name for name in names if name.startswith(match.group(2))]
            if not matches:
                raise ProtocolDenied("condition_selection")
            expanded += len(matches)
        elif match.group(5) is not None:
            if match.group(5) not in names:
                raise ProtocolDenied("condition_selection")
            expanded += 1
        elif match.group(4) == "(":
            depth += 1
        elif match.group(4) == ")":
            depth -= 1
            if depth < 0:
                raise ProtocolDenied("condition_parenthesis")
        if tokens > policy["maximum_condition_tokens"] or depth > policy["maximum_condition_depth"] or expanded > policy["maximum_expanded_terms"]:
            raise ProtocolDenied("condition_bound")
    if depth != 0:
        raise ProtocolDenied("condition_parenthesis")
