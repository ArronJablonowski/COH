using System.Security.Cryptography;
using System.Text;

namespace COH.KustoValidator;

internal static class ValidationEngine
{
    internal static HelperResponse Validate(HelperRequest request)
    {
        RequestContract.Validate(request);
        try
        {
            var globals = SchemaSymbols.Build(request.Schema);
            var original = SemanticAnalyzer.Analyze(request.Query, globals, request.Schema, request.Policy);
            var limit = Math.Min(request.RequestedRows, request.Policy.MaximumRows);
            var bounded = AstBounder.Apply(original, globals, request.Schema, request.Policy, limit);
            var canonicalDigest = Digest("COH-KUSTO-CANONICAL-KQL-V1\0", bounded.CanonicalKql);
            var provenance = Digest("COH-KUSTO-HELPER-PROVENANCE-V1\0", string.Join('\0',
                request.RequestDigest, original.TreeDigest, bounded.Analysis.TreeDigest, canonicalDigest,
                request.SchemaDigest, request.Policy.RegistryDigest, request.HelperIdentityExpectation.ArtifactDigest,
                request.HelperIdentityExpectation.PackageClosureDigest, request.HelperIdentityExpectation.RuntimeDigest));
            return WithDigest(new HelperResponse
            {
                SchemaVersion = Protocol.ResponseVersion,
                ContractVersion = Protocol.ContractVersion,
                RequestId = request.RequestId,
                RequestDigest = request.RequestDigest,
                Outcome = "accepted",
                ReasonCodes = [],
                Diagnostics = [],
                CanonicalKql = bounded.CanonicalKql,
                CanonicalKqlDigest = canonicalDigest,
                OriginalTreeDigest = original.TreeDigest,
                BoundedTreeDigest = bounded.Analysis.TreeDigest,
                Semantic = bounded.Analysis.Inventory,
                OutputColumns = bounded.Analysis.OutputColumns,
                TerminalTake = limit,
                SchemaDigest = request.SchemaDigest,
                RegistryDigest = request.Policy.RegistryDigest,
                HelperIdentity = request.HelperIdentityExpectation,
                ProvenanceDigest = provenance,
                ResponseDigest = string.Empty,
            });
        }
        catch (ValidationDeniedException exception)
        {
            return Denied(request, exception.Reason);
        }
    }

    private static HelperResponse Denied(HelperRequest request, string reason)
    {
        return WithDigest(new HelperResponse
        {
            SchemaVersion = Protocol.ResponseVersion,
            ContractVersion = Protocol.ContractVersion,
            RequestId = request.RequestId,
            RequestDigest = request.RequestDigest,
            Outcome = "denied",
            ReasonCodes = [reason],
            Diagnostics = [],
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
            ProvenanceDigest = Digest("COH-KUSTO-HELPER-DENIAL-V1\0", request.RequestDigest + "\0" + reason),
            ResponseDigest = string.Empty,
        });
    }

    private static HelperResponse WithDigest(HelperResponse response) =>
        response with { ResponseDigest = ResponseDigest(response) };

    internal static string RequestDigest(HelperRequest request)
    {
        var encoded = Transport.CanonicalBytes(request with { RequestDigest = string.Empty });
        return Digest("COH-KUSTO-HELPER-REQUEST-V1\0", encoded);
    }

    private static string ResponseDigest(HelperResponse response)
    {
        var encoded = Transport.CanonicalBytes(response with { ResponseDigest = string.Empty });
        return Digest("COH-KUSTO-HELPER-RESPONSE-V1\0", encoded);
    }

    internal static string DigestValue<T>(string domain, T value) =>
        Digest(domain, Transport.CanonicalBytes(value));

    internal static string Digest(string domain, string value) => Digest(domain, Encoding.UTF8.GetBytes(value));

    internal static string Digest(string domain, byte[] value)
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
