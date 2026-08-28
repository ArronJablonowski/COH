using System.Text;
using System.Text.RegularExpressions;

namespace COH.KustoValidator;

internal static class RequestContract
{
    internal static void Validate(HelperRequest request)
    {
        if (request.SchemaVersion != Protocol.RequestVersion || request.ContractVersion != Protocol.ContractVersion ||
            request.Operation != "kusto.validate" || !Uuid.IsMatch(request.RequestId) || request.Query.Length == 0 ||
            Encoding.UTF8.GetByteCount(request.Query) > request.Policy.MaximumQueryBytes || request.Query.IndexOf('\0') >= 0 ||
            request.QueryDigest != ValidationEngine.Digest("COH-KUSTO-QUERY-V1\0", request.Query) ||
            !Token.IsMatch(request.SourceId) || !SortedTokens(request.ResourceIds, 1, 64) ||
            !Digest.IsMatch(request.WorkspaceIdentityDigest) || !Digest.IsMatch(request.QualificationDigest) ||
            !Digest.IsMatch(request.CapabilityDigest) || !ValidateSchema(request.Schema) ||
            request.SchemaDigest != ValidationEngine.DigestValue("COH-KUSTO-SCHEMA-BINDING-V1\0", request.Schema) ||
            !ValidatePolicy(request.Policy) || !ValidateIdentity(request.HelperIdentityExpectation) ||
            request.HelperIdentityExpectation.RegistryDigest != request.Policy.RegistryDigest ||
            request.RequestedRows == 0 || request.RequestedRows > request.Policy.MaximumRows ||
            !DateTimeOffset.TryParse(request.Deadline, out _) ||
            request.RequestDigest != ValidationEngine.RequestDigest(request))
        {
            throw new InvalidDataException("request_contract");
        }
    }

    private static bool ValidateSchema(SchemaBinding schema)
    {
        if (schema.Database != "coh_workspace" || !DateTimeOffset.TryParse(schema.ObservedAt, out var observed) ||
            !DateTimeOffset.TryParse(schema.ValidUntil, out var validUntil) || observed >= validUntil ||
            validUntil - observed > TimeSpan.FromHours(24) || schema.Tables.Length is < 1 or > 64)
        {
            return false;
        }
        var previousTable = string.Empty;
        var totalColumns = 0;
        foreach (var table in schema.Tables)
        {
            if (!KustoName.IsMatch(table.Name) || string.CompareOrdinal(previousTable, table.Name) >= 0 || table.Columns.Length == 0)
            {
                return false;
            }
            var previousColumn = string.Empty;
            foreach (var column in table.Columns)
            {
                if (!KustoName.IsMatch(column.Name) || string.CompareOrdinal(previousColumn, column.Name) >= 0 ||
                    !SupportedTypes.Contains(column.Type))
                {
                    return false;
                }
                previousColumn = column.Name;
                totalColumns++;
            }
            previousTable = table.Name;
        }
        return totalColumns <= 8192;
    }

    private static bool ValidatePolicy(Policy policy) =>
        policy.Profile == "coh-kql-v1" && policy.RegistryDigest == Protocol.RegistryDigest &&
        policy.MaximumRows is > 0 and <= 10_000 && policy.MaximumQueryBytes is > 0 and <= 65_536 &&
        policy.MaximumSyntaxNodes is > 0 and <= 8192 && policy.MaximumSyntaxDepth is > 0 and <= 64 &&
        policy.MaximumOperators is > 0 and <= 64 && policy.MaximumOutputColumns is > 0 and <= 256 &&
        policy.MaximumAggregates is > 0 and <= 64 && policy.MaximumUnionOperands is > 0 and <= 32;

    private static bool ValidateIdentity(HelperIdentity identity) =>
        identity.Name == "coh-kusto-validator" && identity.Version == Protocol.ValidatorVersion &&
        identity.Rid is "osx-arm64" or "linux-x64" or "linux-arm64" && Digest.IsMatch(identity.ArtifactDigest) &&
        Digest.IsMatch(identity.PackageClosureDigest) && Digest.IsMatch(identity.RuntimeDigest) &&
        Digest.IsMatch(identity.RegistryDigest);

    private static bool SortedTokens(string[] values, int minimum, int maximum)
    {
        if (values.Length < minimum || values.Length > maximum)
        {
            return false;
        }
        for (var index = 0; index < values.Length; index++)
        {
            if (!Token.IsMatch(values[index]) || index > 0 && string.CompareOrdinal(values[index - 1], values[index]) >= 0)
            {
                return false;
            }
        }
        return true;
    }

    private static readonly HashSet<string> SupportedTypes = new(StringComparer.Ordinal)
    {
        "bool", "datetime", "decimal", "guid", "int", "long", "real", "string", "timespan",
    };

    private static readonly Regex Uuid = new(
        "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex Digest = new("^sha256:[0-9a-f]{64}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex Token = new("^[a-z][a-z0-9_.-]{0,127}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex KustoName = new("^[A-Za-z_][A-Za-z0-9_]{0,127}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
}
