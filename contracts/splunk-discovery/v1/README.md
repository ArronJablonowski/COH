# Splunk discovery contract v1

This contract binds a COH source to one self-managed Splunk Enterprise search
head. It permits only bounded, read-only identity, current-context, index
inventory, and registered-field discovery. Splunk Cloud, generic REST
passthrough, authentication endpoints, redirects, ambient proxies, wildcard or
internal indexes, and privileged capabilities are outside v1.

Operators provision an authentication token out of band and register only its
credential-broker reference. COH releases a scoped, single-use lease after the
TLS peer and configured server GUID match. Public configuration, qualification,
capability, schema, denial, and error evidence never contains the token, a
Splunk session key, native response text, result rows, or vendor bodies.

Registered Splunk fields do not provide reliable per-index logical types.
Operators therefore declare the logical type and resource membership; live
discovery may only intersect that declaration with the bounded registered-field
inventory. Deployment identity, credential authority, capability set, config,
or qualified minor-version changes require requalification.

