using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace COH.KustoValidator;

// Task 3 deliberately provides a fail-closed process and packaging boundary.
// Task 4 replaces this unavailable response with Kusto.Language semantic
// analysis and AST-derived bounding under the same protocol.
internal static class ValidationEngine
{
    internal static HelperResponse Validate(HelperRequest request)
    {
        ValidateEnvelope(request);
        var response = new HelperResponse
        {
            SchemaVersion = Protocol.ResponseVersion,
            ContractVersion = Protocol.ContractVersion,
            RequestId = request.RequestId,
            RequestDigest = request.RequestDigest,
            Outcome = "denied",
            ReasonCodes = ["helper_semantics_unavailable"],
            Diagnostics = [new Diagnostic { Code = "KS000", Severity = "error", Class = "helper_unavailable" }],
            CanonicalKql = string.Empty,
            CanonicalKqlDigest = string.Empty,
            OriginalTreeDigest = string.Empty,
            BoundedTreeDigest = string.Empty,
            Semantic = new SemanticInventory { Tables = [], Columns = [], Operators = [], Functions = [] },
            OutputColumns = [],
            TerminalTake = 0,
            SchemaDigest = request.SchemaDigest,
            RegistryDigest = request.Policy.RegistryDigest,
            HelperIdentity = request.HelperIdentityExpectation,
            ProvenanceDigest = Digest("COH-KUSTO-HELPER-UNAVAILABLE-V1\0", request.RequestDigest),
            ResponseDigest = string.Empty,
        };
        return response with { ResponseDigest = ResponseDigest(response) };
    }

    private static void ValidateEnvelope(HelperRequest request)
    {
        if (request.SchemaVersion != Protocol.RequestVersion || request.ContractVersion != Protocol.ContractVersion ||
            request.Operation != "kusto.validate" || request.Query.Length == 0 || request.Query.Length > 65_536 ||
            request.RequestedRows == 0 || request.RequestedRows > request.Policy.MaximumRows ||
            request.HelperIdentityExpectation.Version != Protocol.ValidatorVersion ||
            request.HelperIdentityExpectation.RegistryDigest != request.Policy.RegistryDigest)
        {
            throw new InvalidDataException("request_contract");
        }
    }

    private static string ResponseDigest(HelperResponse response)
    {
        var encoded = JsonSerializer.SerializeToUtf8Bytes(response with { ResponseDigest = string.Empty }, Transport.JsonOptions);
        return Digest("COH-KUSTO-HELPER-RESPONSE-V1\0", encoded);
    }

    private static string Digest(string domain, string value) => Digest(domain, Encoding.UTF8.GetBytes(value));

    private static string Digest(string domain, byte[] value)
    {
        var domainBytes = Encoding.UTF8.GetBytes(domain);
        var input = new byte[domainBytes.Length + value.Length];
        Buffer.BlockCopy(domainBytes, 0, input, 0, domainBytes.Length);
        Buffer.BlockCopy(value, 0, input, domainBytes.Length, value.Length);
        var digest = SHA256.HashData(input);
        CryptographicOperations.ZeroMemory(input);
        return "sha256:" + Convert.ToHexStringLower(digest);
    }
}
