"""Source-level conformance tests for the closed helper process."""

from __future__ import annotations

import copy
import concurrent.futures
import json
import os
import pathlib
import unittest

from coh_pysigma_helper.compiler import compile_request
from coh_pysigma_helper.protocol import ProtocolDenied, TARGETS, decode_request, mapping_digest, request_digest

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "contracts" / "pysigma-helper" / "v1" / "fixtures" / "compile-request.json"


class HelperTests(unittest.TestCase):
    def request(self) -> dict:
        return decode_request(FIXTURE.read_bytes())

    def rebound(self, request: dict) -> dict:
        request["sigma_digest"] = self._domain("COH-SIGMA-SOURCE-V1\0", request["sigma_yaml"])
        request["mapping"]["mapping_digest"] = mapping_digest(request["mapping"])
        request["request_digest"] = request_digest(request)
        return decode_request(json.dumps(request, separators=(",", ":")).encode())

    def _domain(self, domain: str, value: object) -> str:
        from coh_pysigma_helper.protocol import domain_digest

        return domain_digest(domain, value)

    def test_fixture_compiles_as_untrusted(self) -> None:
        response = compile_request(self.request())
        self.assertEqual(response["outcome"], "compiled_untrusted")
        self.assertEqual(response["reason_codes"], [])
        self.assertIn(self.request()["mapping"]["target_resource"], response["native_query"])

    def test_all_candidate_backends_are_explicit_and_resource_bound(self) -> None:
        for target in ("elastic", "sentinel", "splunk"):
            with self.subTest(target=target):
                request = copy.deepcopy(self.request())
                keys = ("native_language", "backend_package", "backend_version", "backend_commit", "backend_class", "output_format")
                request["target"] = {"target": target, **dict(zip(keys, TARGETS[target], strict=True))}
                response = compile_request(self.rebound(request))
                self.assertEqual(response["outcome"], "compiled_untrusted")
                self.assertIn(request["mapping"]["target_resource"], response["native_query"])

    def test_candidate_backends_are_deterministic_under_replay_and_concurrency(self) -> None:
        requests = []
        for target in ("elastic", "sentinel", "splunk"):
            request = copy.deepcopy(self.request())
            keys = ("native_language", "backend_package", "backend_version", "backend_commit", "backend_class", "output_format")
            request["target"] = {"target": target, **dict(zip(keys, TARGETS[target], strict=True))}
            requests.append(self.rebound(request))
        expected = [compile_request(request) for request in requests]
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            actual = list(pool.map(compile_request, requests * 4))
        for index, response in enumerate(actual):
            self.assertEqual(response, expected[index % len(requests)])

    def test_alias_duplicate_and_regex_are_closed_denials(self) -> None:
        mutations = {
            "anchor": lambda source: source.replace("title: Suspicious", "title: &ambient Suspicious", 1),
            "duplicate": lambda source: "title: duplicate\n" + source,
            "regex": lambda source: source.replace("CommandLine|contains", "CommandLine|re", 1),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                request = copy.deepcopy(self.request())
                request["sigma_yaml"] = mutate(request["sigma_yaml"])
                response = compile_request(self.rebound(request))
                self.assertNotEqual(response["outcome"], "compiled_untrusted")
                self.assertEqual(response["native_query"], "")

    def test_malformed_alias_bomb_and_condition_expansion_are_bounded(self) -> None:
        mutations = {
            "malformed": lambda source: source + "\ndetection: [",
            "alias_bomb": lambda source: source.replace(
                "selection:\n", "selection: &seed\n", 1
            ).replace("condition: selection", "copy: *seed\n  condition: selection", 1),
            "condition_expansion": lambda source: source.replace(
                "condition: selection", "condition: all of selection*", 1
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                request = copy.deepcopy(self.request())
                request["sigma_yaml"] = mutate(request["sigma_yaml"])
                if name == "condition_expansion":
                    request["policy"]["maximum_expanded_terms"] = 1
                    request["sigma_yaml"] = request["sigma_yaml"].replace(
                        "selection:\n", "selection_one:\n", 1
                    ).replace("  condition: all of selection*", "  selection_two:\n    Image|endswith: cmd.exe\n  condition: all of selection*", 1)
                response = compile_request(self.rebound(request))
                self.assertNotEqual(response["outcome"], "compiled_untrusted")
                self.assertEqual(response["native_query"], "")

    def test_oversize_and_unsupported_features_release_no_query(self) -> None:
        cases = []
        oversize = copy.deepcopy(self.request())
        oversize["policy"]["maximum_sigma_bytes"] = 64
        cases.append(("oversize", oversize))
        correlation = copy.deepcopy(self.request())
        correlation["sigma_yaml"] += "\ncorrelation:\n  type: event_count\n"
        cases.append(("correlation", correlation))
        regex = copy.deepcopy(self.request())
        regex["sigma_yaml"] = regex["sigma_yaml"].replace("CommandLine|contains", "CommandLine|re", 1)
        cases.append(("regex", regex))
        for name, request in cases:
            with self.subTest(name=name):
                response = compile_request(self.rebound(request))
                self.assertNotEqual(response["outcome"], "compiled_untrusted")
                self.assertEqual(response["native_query"], "")

    def test_denial_diagnostics_are_normalized_and_redacted(self) -> None:
        marker = "COH_PRIVATE_RULE_MARKER_7f3c"
        request = copy.deepcopy(self.request())
        request["sigma_yaml"] = request["sigma_yaml"].replace("Suspicious", marker, 1).replace(
            "CommandLine|contains", "CommandLine|re", 1
        )
        response = compile_request(self.rebound(request))
        encoded = json.dumps(response, sort_keys=True)
        self.assertNotIn(marker, encoded)
        self.assertEqual(response["native_query"], "")
        self.assertEqual(response["diagnostics"], sorted(response["diagnostics"], key=lambda item: (item["code"], item["class"], item["location"])))

    def test_missing_mapping_is_typed_without_query(self) -> None:
        request = copy.deepcopy(self.request())
        request["mapping"]["fields"] = request["mapping"]["fields"][1:]
        response = compile_request(self.rebound(request))
        self.assertEqual(response["outcome"], "needs_mapping")
        self.assertEqual(response["reason_codes"], ["mapping_missing"])
        self.assertEqual(response["native_query"], "")

    def test_duplicate_transport_key_is_denied(self) -> None:
        raw = FIXTURE.read_text().replace('"operation": "sigma.compile",', '"operation": "other",\n  "operation": "sigma.compile",', 1).encode()
        with self.assertRaises(ProtocolDenied):
            decode_request(raw)

    def test_source_contains_no_ambient_configuration_reads(self) -> None:
        source = "\n".join(path.read_text() for path in sorted((ROOT / "helpers" / "pysigma" / "src").rglob("*.py")))
        for forbidden in ("autodiscover", "ProcessingPipelineResolver", "from_yaml", "load_ruleset", "collect_errors=True", "os.getenv", "requests."):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    os.environ.clear()
    unittest.main()
