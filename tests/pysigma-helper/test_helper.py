"""Source-level conformance tests for the closed helper process."""

from __future__ import annotations

import copy
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
