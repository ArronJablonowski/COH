using System.Text.Json;
using COH.KustoValidator;

if (args.Length != 1)
{
    throw new InvalidOperationException("fixture path required");
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

    foreach (var query in new[]
    {
        "SecurityEvent",
        "SecurityEvent | take 5",
        "SecurityEvent | extend Rendered = tostring(EventID) | project Rendered",
        "SecurityEvent | summarize Count = count()",
        "union SecurityEvent, SecurityEvent | project Computer",
        "SecurityEvent | where Computer == \"München<&>\" | project Computer",
    })
    {
        var acceptedRequest = RequestForQuery(request, query);
        var accepted = ValidationEngine.Validate(acceptedRequest);
        Require(accepted.Outcome == "accepted", "safe query denied: " + query);
        Require(accepted.CanonicalKql.EndsWith("| take 500", StringComparison.Ordinal), "terminal AST bound missing: " + query);
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

    Console.WriteLine("Kusto.Language semantic and AST-bound conformance passed");
    return 0;
}
catch (Exception exception)
{
    Console.Error.WriteLine(exception);
    return 1;
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
