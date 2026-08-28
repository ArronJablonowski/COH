using Kusto.Language.Syntax;

namespace COH.KustoValidator;

internal static class SemanticPolicy
{
    internal static readonly HashSet<string> AllowedFunctions = new(StringComparer.Ordinal)
    {
        "abs", "bin", "case", "coalesce", "endofday", "endofmonth", "endofweek", "format_datetime",
        "getmonth", "getyear", "iff", "indexof", "ipv4_compare", "ipv4_is_in_range", "isascii", "isempty",
        "isfinite", "isinf", "isnan", "isnotempty", "isnotnull", "isnull", "log", "max_of", "min_of",
        "round", "startofday", "startofmonth", "startofweek", "strcat", "strcmp", "strlen", "substring",
        "tobool", "todatetime", "todecimal", "todouble", "toint", "tolong", "tolower", "toreal", "tostring",
        "totimespan", "toupper", "trim", "trim_end", "trim_start",
    };

    internal static readonly HashSet<string> AllowedAggregates = new(StringComparer.Ordinal)
    {
        "avg", "avgif", "count", "countif", "dcount", "dcountif", "max", "min", "sum", "sumif",
    };

    internal static bool TryGetOperatorName(QueryOperator operation, out string name)
    {
        name = operation switch
        {
            CountOperator => "count",
            DistinctOperator => "distinct",
            ExtendOperator => "extend",
            FilterOperator filter when filter.GetFirstToken().Kind == SyntaxKind.WhereKeyword => "where",
            FilterOperator => "filter",
            ParseOperator => "parse",
            ParseWhereOperator => "parse-where",
            ProjectOperator => "project",
            ProjectAwayOperator => "project-away",
            ProjectKeepOperator => "project-keep",
            ProjectRenameOperator => "project-rename",
            SortOperator sort when sort.GetFirstToken().Kind == SyntaxKind.OrderKeyword => "order",
            SortOperator => "sort",
            SummarizeOperator => "summarize",
            TakeOperator take when take.Keyword.Kind == SyntaxKind.LimitKeyword => "limit",
            TakeOperator => "take",
            TopOperator => "top",
            UnionOperator => "union",
            _ => string.Empty,
        };
        return name.Length != 0;
    }
}
