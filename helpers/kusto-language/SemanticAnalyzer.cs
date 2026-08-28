using Kusto.Language;
using Kusto.Language.Symbols;
using Kusto.Language.Syntax;

namespace COH.KustoValidator;

internal sealed record AnalysisResult(
    KustoCode Code,
    Expression Expression,
    SemanticInventory Inventory,
    OutputColumn[] OutputColumns,
    string TreeDigest);

internal sealed class ValidationDeniedException(string reason) : Exception(reason)
{
    internal string Reason { get; } = reason;
}

internal static class SemanticAnalyzer
{
    internal static AnalysisResult Analyze(string query, GlobalState globals, SchemaBinding schema, Policy policy)
    {
        var code = KustoCode.ParseAndAnalyze(query, globals);
        var block = code.Syntax as QueryBlock ?? throw new ValidationDeniedException("invalid_kql");
        if (!code.HasSemantics || code.GetDiagnostics().Count != 0 || block.Directives.Count != 0 ||
            block.Statements.Count != 1 || block.SkippedTokens is not null || block.Statements[0].Separator is not null)
        {
            Deny("invalid_kql");
        }
        var statement = block.Statements[0].Element as ExpressionStatement ?? throw new ValidationDeniedException("invalid_kql");

        var nodes = block.GetDescendantsOrSelf<SyntaxNode>();
        if (nodes.Count > policy.MaximumSyntaxNodes || MaximumDepth(block) > policy.MaximumSyntaxDepth ||
            block.GetDescendants<SyntaxToken>().Any(token => token.IsLiteral && token.Width > 4096))
        {
            Deny("query_complexity");
        }
        if (nodes.Any(node => node is DataTableExpression or ContextualDataTableExpression or ExternalDataExpression or
            InlineExternalTableExpression or MaterializeExpression or MaterializedViewCombineExpression or ToScalarExpression or
            ToTableExpression or DynamicExpression or JsonExpression or PathExpression or EntityGroup))
        {
            Deny("construct_denied");
        }

        var operators = statement.Expression.GetDescendantsOrSelf<QueryOperator>();
        if (operators.Count > policy.MaximumOperators)
        {
            Deny("operator_limit");
        }
        var operatorNames = new SortedSet<string>(StringComparer.Ordinal);
        var unionOperands = 0;
        foreach (var operation in operators)
        {
            if (!SemanticPolicy.TryGetOperatorName(operation, out var name))
            {
                Deny("operator_denied");
            }
            operatorNames.Add(name);
            if (operation is UnionOperator union)
            {
                unionOperands += union.Expressions.Count;
                if (union.GetDescendants<StarExpression>().Count != 0 || union.GetDescendants<WildcardedName>().Count != 0)
                {
                    Deny("union_operand_denied");
                }
                foreach (var operand in union.Expressions)
                {
                    if (operand.Element is not NameReference reference || reference.ReferencedSymbol is not TableSymbol table ||
                        globals.GetDatabase(table) != globals.Database)
                    {
                        Deny("union_operand_denied");
                    }
                }
                if (union.Parameters.Count != 0)
                {
                    Deny("union_parameter_denied");
                }
            }
        }
        if (unionOperands > policy.MaximumUnionOperands)
        {
            Deny("union_limit");
        }

        var functionNames = new SortedSet<string>(StringComparer.Ordinal);
        var aggregateCount = 0;
        foreach (var call in statement.Expression.GetDescendantsOrSelf<FunctionCallExpression>())
        {
            var function = call.ReferencedSymbol as FunctionSymbol ?? throw new ValidationDeniedException("function_denied");
            if (!globals.IsBuiltInFunction(function))
            {
                Deny("function_denied");
            }
            var aggregate = globals.IsAggregateFunction(function);
            if (!(aggregate ? SemanticPolicy.AllowedAggregates : SemanticPolicy.AllowedFunctions).Contains(function.Name))
            {
                Deny("function_denied");
            }
            aggregateCount += aggregate ? 1 : 0;
            functionNames.Add(function.Name);
        }
        if (aggregateCount > policy.MaximumAggregates)
        {
            Deny("aggregate_limit");
        }

        var tables = new SortedSet<string>(StringComparer.Ordinal);
        var columns = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var reference in statement.Expression.GetDescendantsOrSelf<NameReference>())
        {
            switch (reference.ReferencedSymbol)
            {
                case TableSymbol table when globals.GetDatabase(table) == globals.Database:
                    tables.Add(table.Name);
                    break;
                case TableSymbol:
                    Deny("table_denied");
                    break;
                case ColumnSymbol column:
                    AddColumns(column, globals, tables, columns);
                    break;
            }
        }
        if (tables.Count == 0)
        {
            Deny("table_required");
        }

        var result = code.ResultType as TableSymbol ?? throw new ValidationDeniedException("output_schema_denied");
        if (result.IsOpen || result.Columns.Count == 0 || result.Columns.Count > policy.MaximumOutputColumns)
        {
            Deny("output_schema_denied");
        }
        var output = new List<OutputColumn>(result.Columns.Count);
        var outputNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var column in result.Columns)
        {
            var type = SchemaSymbols.TypeName(column.Type);
            if (type.Length == 0 || !outputNames.Add(column.Name))
            {
                Deny("output_schema_denied");
            }
            output.Add(new OutputColumn
            {
                Name = column.Name,
                Type = type,
                Nullable = SchemaSymbols.IsNullable(column, globals, schema),
            });
        }

        return new AnalysisResult(code, statement.Expression, new SemanticInventory
        {
            Tables = [.. tables],
            Columns = [.. columns],
            Operators = [.. operatorNames],
            Functions = [.. functionNames],
        }, [.. output], SyntaxFingerprint.Digest(statement.Expression));
    }

    private static void AddColumns(ColumnSymbol column, GlobalState globals, ISet<string> tables, ISet<string> columns)
    {
        var sources = column.OriginalColumns.Count == 0 ? [column] : column.OriginalColumns;
        foreach (var source in sources)
        {
            var table = globals.GetTable(source);
            if (table is not null && globals.GetDatabase(table) == globals.Database)
            {
                tables.Add(table.Name);
                columns.Add(table.Name + "." + source.Name);
            }
        }
    }

    private static int MaximumDepth(SyntaxElement root)
    {
        var maximum = 0;
        var stack = new Stack<(SyntaxElement Element, int Depth)>();
        stack.Push((root, 1));
        while (stack.Count != 0)
        {
            var (element, depth) = stack.Pop();
            maximum = Math.Max(maximum, depth);
            for (var index = 0; index < element.ChildCount; index++)
            {
                if (element.GetChild(index) is SyntaxElement child)
                {
                    stack.Push((child, depth + 1));
                }
            }
        }
        return maximum;
    }

    private static void Deny(string reason) => throw new ValidationDeniedException(reason);
}
