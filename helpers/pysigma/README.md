# COH signed pySigma helper

This directory contains the only approved Python Sigma compiler process. It is
credentialless, network-denied, T0, and launched only through COH's signed
native executor. The process accepts one closed JSON request on standard input
and emits one closed JSON response on standard output. It has no arguments,
paths, endpoints, credentials, environment configuration, plugin discovery,
pipeline files, templates, callbacks, or skip-unsupported mode.

The helper imports only the exact Elastic ES|QL, Splunk SPL, and Kusto KQL
backend classes. Before pySigma receives a rule, a custom YAML loader rejects
duplicate keys, aliases, anchors, unsafe/implicit object tags, multiple
documents, and policy-limit violations. A second closed-profile pass verifies
metadata, logsource, selections, modifiers, conditions, mappings, and expanded
complexity. Every backend uses `collect_errors=False`, a fresh code-owned
pipeline, exact field mappings, and `StrictFieldMappingFailure`.

`uv.lock` is the complete cross-platform dependency lock. Build inputs are
fetched separately, then `scripts/build_pysigma_helper.sh` restores from a
hash-verified offline wheelhouse with resolution and network disabled. Build
products, virtual environments, wheel caches, and temporary files remain under
the external COH toolchain root. The build refuses a runtime other than CPython
3.13.15 or PyInstaller other than 6.22.2.

The generated query is always `compiled_untrusted`. It cannot become runnable
until COH-E15-02 rebinds it to current discovered schema and passes the matching
native-language validator. See `docs/design/signed-pysigma-helper.md` and
`contracts/pysigma-helper/v1/README.md`.
