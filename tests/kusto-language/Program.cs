using System.Text.Json;
using COH.KustoValidator;

if (args.Length != 4)
{
    throw new InvalidOperationException("request, accepted, metadata, and denial corpus paths required");
}

var requestJson = await File.ReadAllTextAsync(args[0]).ConfigureAwait(false);
var transportJson = JsonSerializer.Serialize(new TransportEnvelope { RequestChunk00 = requestJson }, Transport.JsonOptions);
var request = Transport.DecodeRequest(System.Text.Encoding.UTF8.GetBytes(transportJson));

try
{
    RequestContract.Validate(request);
    var globals = SchemaSymbols.Build(request.Schema);
    var original = SemanticAnalyzer.Analyze(request.Query, globals, request.Schema, request.Policy);
    var bounded = AstBounder.Apply(original, globals, request.Schema, request.Policy, request.RequestedRows);
    var response = ValidationEngine.Validate(request);
    Require(response.Outcome == "accepted", "canonical fixture was denied");
    Require(response.CanonicalKql == "SecurityEvent | where EventID == 4624 | project TimeGenerated, Computer, EventID | take 500",
        "canonical AST output drifted");
    Require(response.CanonicalKql == bounded.CanonicalKql, "public response differs from AST proof");

    var acceptedCorpus = JsonSerializer.Deserialize<AcceptedCorpus>(await File.ReadAllTextAsync(args[1]).ConfigureAwait(false),
        Transport.JsonOptions) ?? throw new InvalidDataException("accepted_corpus");
    Require(acceptedCorpus.SchemaVersion == "coh.kusto-validator-accepted/v1" &&
        acceptedCorpus.ContractVersion == Protocol.ContractVersion && acceptedCorpus.Cases.Length >= 8, "accepted corpus contract");
    foreach (var item in acceptedCorpus.Cases)
    {
        var acceptedRequest = RequestForQuery(request, item.Query);
        var accepted = ValidationEngine.Validate(acceptedRequest);
        Require(accepted.Outcome == "accepted", "safe query denied: " + item.Name);
        Require(accepted.CanonicalKql.EndsWith(item.CanonicalSuffix, StringComparison.Ordinal),
            "terminal AST bound missing: " + item.Name);
    }

    foreach (var query in new[]
    {
        ".show tables",
        "set querytrace=true; SecurityEvent",
        "let X = SecurityEvent; X",
        "declare query_parameters(x:string); SecurityEvent",
        "SecurityEvent; SecurityEvent",
        "externaldata(x:string)[\"https://example.invalid/data\"]",
        "cluster(\"other\").database(\"db\").SecurityEvent",
        "database(\"other\").SecurityEvent",
        "union *",
        "union isfuzzy=true SecurityEvent",
        "SecurityEvent | evaluate autocluster()",
        "SecurityEvent | join SecurityEvent on Computer",
        "materialize(SecurityEvent)",
        "datatable(x:int)[1]",
        "toscalar(SecurityEvent | count)",
        "entity_group [SecurityEvent]",
        "SecurityEvent | where EventID in (dynamic([4624]))",
        "SecurityEvent | extend Bag = pack(\"x\", EventID)",
        "UnknownTable | take 1",
        "SecurityEvent | project UnknownColumn",
    })
    {
        var denied = ValidationEngine.Validate(RequestForQuery(request, query));
        Require(denied.Outcome == "denied" && denied.ReasonCodes.Length != 0, "unsafe query accepted: " + query);
        Require(denied.CanonicalKql.Length == 0 && denied.TerminalTake == 0, "denial leaked executable KQL: " + query);
    }

    var denialCorpus = JsonSerializer.Deserialize<ManagedDenialCorpus>(await File.ReadAllTextAsync(args[3]).ConfigureAwait(false),
        Transport.JsonOptions) ?? throw new InvalidDataException("denial_corpus");
    var semanticDenials = denialCorpus.Cases.Where(item => item.CoveredBy == "TestSemanticDenialCorpus").ToArray();
    Require(denialCorpus.SchemaVersion == "coh.kusto-validator-denials/v1" &&
        denialCorpus.ContractVersion == Protocol.ContractVersion && semanticDenials.Length >= 20, "denial corpus contract");
    foreach (var item in semanticDenials)
    {
        var denied = ValidationEngine.Validate(RequestForQuery(request, item.Input));
        Require(denied.Outcome == "denied" && denied.ReasonCodes.Length != 0,
            "declared denial accepted: " + item.Class + " (" + item.Reason + ")");
        Require(denied.CanonicalKql.Length == 0 && denied.TerminalTake == 0,
            "declared denial leaked executable KQL: " + item.Class);
    }

    var metadataCorpus = JsonSerializer.Deserialize<MetadataCorpus>(await File.ReadAllTextAsync(args[2]).ConfigureAwait(false),
        Transport.JsonOptions) ?? throw new InvalidDataException("metadata_corpus");
    Require(metadataCorpus.SchemaVersion == "coh.kusto-validator-metadata/v1" &&
        metadataCorpus.ContractVersion == Protocol.ContractVersion && metadataCorpus.Cases.Length >= 8, "metadata corpus contract");
    foreach (var item in metadataCorpus.Cases)
    {
        var changed = MutateMetadata(request, item.Mutation);
        var denied = false;
        try
        {
            RequestContract.Validate(changed);
        }
        catch (InvalidDataException)
        {
            denied = true;
        }
        Require(denied, "unsafe metadata accepted: " + item.Name);
    }

    Console.WriteLine("Kusto.Language semantic and AST-bound conformance passed");
    return 0;
}

catch (Exception exception)
{
    Console.Error.WriteLine(exception);
    return 1;
}

static HelperRequest MutateMetadata(HelperRequest source, string mutation)
{
    var table = source.Schema.Tables[0];
    var schema = mutation switch
    {
        "duplicate_table" => source.Schema with { Tables = [table, table] },
        "unsorted_columns" => source.Schema with
        {
            Tables = [table with { Columns = [table.Columns[1], table.Columns[0], table.Columns[2]] }],
        },
        "table_traversal" => source.Schema with { Tables = [table with { Name = "../SecurityEvent" }] },
        "column_injection" => source.Schema with
        {
            Tables = [table with { Columns = [table.Columns[0] with { Name = "Computer);externaldata" }, .. table.Columns[1..]] }],
        },
        "dynamic_type" => source.Schema with
        {
            Tables = [table with { Columns = [table.Columns[0] with { Type = "dynamic" }, .. table.Columns[1..]] }],
        },
        "empty_catalog" => source.Schema with { Tables = [] },
        "validity_excessive" => source.Schema with { ValidUntil = "2026-08-29T02:00:01Z" },
        "schema_digest_substitution" => source.Schema with { Tables = [table with { Name = "DeviceEvents" }] },
        _ => throw new InvalidDataException("unknown_metadata_mutation"),
    };
    var changed = source with { Schema = schema, RequestDigest = string.Empty };
    if (mutation != "schema_digest_substitution")
    {
        changed = changed with { SchemaDigest = ValidationEngine.DigestValue("COH-KUSTO-SCHEMA-BINDING-V1\0", schema) };
    }
    return changed with { RequestDigest = ValidationEngine.RequestDigest(changed) };
}

static HelperRequest RequestForQuery(HelperRequest source, string query)
{
    var changed = source with
    {
        Query = query,
        QueryDigest = ValidationEngine.Digest("COH-KUSTO-QUERY-V1\0", query),
        RequestDigest = string.Empty,
    };
    return changed with { RequestDigest = ValidationEngine.RequestDigest(changed) };
}

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

internal sealed record AcceptedCorpus
{
    public required string SchemaVersion { get; init; }
    public required string ContractVersion { get; init; }
    public required AcceptedCase[] Cases { get; init; }
}

internal sealed record AcceptedCase
{
    public required string Name { get; init; }
    public required string Query { get; init; }
    public required string CanonicalSuffix { get; init; }
}

internal sealed record MetadataCorpus
{
    public required string SchemaVersion { get; init; }
    public required string ContractVersion { get; init; }
    public required MetadataCase[] Cases { get; init; }
}

internal sealed record MetadataCase
{
    public required string Name { get; init; }
    public required string Mutation { get; init; }
}

internal sealed record ManagedDenialCorpus
{
    public required string SchemaVersion { get; init; }
    public required string ContractVersion { get; init; }
    public required ManagedDenialCase[] Cases { get; init; }
}

internal sealed record ManagedDenialCase
{
    public required string Class { get; init; }
    public required string Input { get; init; }
    public required string Reason { get; init; }
    public required string CoveredBy { get; init; }
}
