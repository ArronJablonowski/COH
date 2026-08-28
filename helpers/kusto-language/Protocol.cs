using System.Text.Json.Serialization;

namespace COH.KustoValidator;

internal static class Protocol
{
    internal const string ContractVersion = "1.0.0";
    internal const string RequestVersion = "coh.kusto-helper-request/v1";
    internal const string ResponseVersion = "coh.kusto-helper-response/v1";
    internal const string ValidatorVersion = "kusto-language-12.4.1-coh-1.0.0";
    internal const string RegistryDigest = "sha256:4b01ac2f77f54138c0a9b5fdab1a5a9195f147804aac44884e03860a83ee6f52";
    internal const int MaximumInputBytes = 1 << 20;
    internal const int MaximumChunkCount = 8;
    internal const int MaximumChunkCharacters = 61_440;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record TransportEnvelope
{
    [JsonPropertyName("request_chunk_00")]
    public string? RequestChunk00 { get; init; }
    [JsonPropertyName("request_chunk_01")]
    public string? RequestChunk01 { get; init; }
    [JsonPropertyName("request_chunk_02")]
    public string? RequestChunk02 { get; init; }
    [JsonPropertyName("request_chunk_03")]
    public string? RequestChunk03 { get; init; }
    [JsonPropertyName("request_chunk_04")]
    public string? RequestChunk04 { get; init; }
    [JsonPropertyName("request_chunk_05")]
    public string? RequestChunk05 { get; init; }
    [JsonPropertyName("request_chunk_06")]
    public string? RequestChunk06 { get; init; }
    [JsonPropertyName("request_chunk_07")]
    public string? RequestChunk07 { get; init; }

    internal string?[] Chunks() =>
    [
        RequestChunk00, RequestChunk01, RequestChunk02, RequestChunk03,
        RequestChunk04, RequestChunk05, RequestChunk06, RequestChunk07,
    ];
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record HelperRequest
{
    public required string SchemaVersion { get; init; }
    public required string ContractVersion { get; init; }
    public required string RequestId { get; init; }
    public required string Operation { get; init; }
    public required string Query { get; init; }
    public required string QueryDigest { get; init; }
    public required string SourceId { get; init; }
    public required string[] ResourceIds { get; init; }
    public required string WorkspaceIdentityDigest { get; init; }
    public required string QualificationDigest { get; init; }
    public required string CapabilityDigest { get; init; }
    public required SchemaBinding Schema { get; init; }
    public required string SchemaDigest { get; init; }
    public required Policy Policy { get; init; }
    public required HelperIdentity HelperIdentityExpectation { get; init; }
    public ulong RequestedRows { get; init; }
    public required string Deadline { get; init; }
    public required string RequestDigest { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record SchemaBinding
{
    public required string Database { get; init; }
    public required string ObservedAt { get; init; }
    public required string ValidUntil { get; init; }
    public required SchemaTable[] Tables { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record SchemaTable
{
    public required string Name { get; init; }
    public required SchemaColumn[] Columns { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record SchemaColumn
{
    public required string Name { get; init; }
    public required string Type { get; init; }
    public bool Nullable { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record Policy
{
    public required string Profile { get; init; }
    public required string RegistryDigest { get; init; }
    public ulong MaximumRows { get; init; }
    public uint MaximumQueryBytes { get; init; }
    public uint MaximumSyntaxNodes { get; init; }
    public uint MaximumSyntaxDepth { get; init; }
    public uint MaximumOperators { get; init; }
    public uint MaximumOutputColumns { get; init; }
    public uint MaximumAggregates { get; init; }
    public uint MaximumUnionOperands { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record HelperIdentity
{
    public required string Name { get; init; }
    public required string Version { get; init; }
    public required string Rid { get; init; }
    public required string ArtifactDigest { get; init; }
    public required string PackageClosureDigest { get; init; }
    public required string RuntimeDigest { get; init; }
    public required string RegistryDigest { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record HelperResponse
{
    public required string SchemaVersion { get; init; }
    public required string ContractVersion { get; init; }
    public required string RequestId { get; init; }
    public required string RequestDigest { get; init; }
    public required string Outcome { get; init; }
    public required string[] ReasonCodes { get; init; }
    public required Diagnostic[] Diagnostics { get; init; }
    public required string CanonicalKql { get; init; }
    public required string CanonicalKqlDigest { get; init; }
    public required string OriginalTreeDigest { get; init; }
    public required string BoundedTreeDigest { get; init; }
    public required SemanticInventory Semantic { get; init; }
    public required OutputColumn[] OutputColumns { get; init; }
    public ulong TerminalTake { get; init; }
    public required string SchemaDigest { get; init; }
    public required string RegistryDigest { get; init; }
    public required HelperIdentity HelperIdentity { get; init; }
    public required string ProvenanceDigest { get; init; }
    public required string ResponseDigest { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record Diagnostic
{
    public required string Code { get; init; }
    public required string Severity { get; init; }
    public required string Class { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record SemanticInventory
{
    public required string[] Tables { get; init; }
    public required string[] Columns { get; init; }
    public required string[] Operators { get; init; }
    public required string[] Functions { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record OutputColumn
{
    public required string Name { get; init; }
    public required string Type { get; init; }
    public bool Nullable { get; init; }
}
