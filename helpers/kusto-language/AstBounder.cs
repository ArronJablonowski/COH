using System.Globalization;
using System.Reflection;
using Kusto.Language;
using Kusto.Language.Editor;
using Kusto.Language.Syntax;

namespace COH.KustoValidator;

internal sealed record BoundedAnalysis(string CanonicalKql, AnalysisResult Analysis);

internal static class AstBounder
{
    internal static BoundedAnalysis Apply(AnalysisResult original, GlobalState globals, SchemaBinding schema, Policy policy, ulong limit)
    {
        var templateText = "_coh_template | take " + limit.ToString(CultureInfo.InvariantCulture);
        var template = KustoCode.Parse(templateText);
        if (template.Syntax is not QueryBlock templateBlock ||
            templateBlock.Statements[0].Element is not ExpressionStatement templateStatement ||
            templateStatement.Expression is not PipeExpression templatePipe || templatePipe.Operator is not TakeOperator templateTake)
        {
            throw new InvalidOperationException("trusted_template");
        }

        var constructor = typeof(PipeExpression).GetConstructor(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            [typeof(Expression), typeof(SyntaxToken), typeof(QueryOperator), typeof(IReadOnlyList<Kusto.Language.Diagnostic>)],
            modifiers: null) ?? throw new InvalidOperationException("ast_constructor");
        var boundedTree = constructor.Invoke([
            original.Expression.Clone(), templatePipe.Bar.Clone(), templateTake.Clone(), null,
        ]) as PipeExpression ?? throw new InvalidOperationException("ast_constructor");
        var unformatted = boundedTree.ToString(IncludeTrivia.Minimal);
        var factory = new KustoCodeServiceFactory(globals);
        if (!factory.TryGetCodeService(unformatted, out var service))
        {
            throw new InvalidOperationException("formatter");
        }
        var options = FormattingOptions.Default
            .WithPipeOperatorStyle(PlacementStyle.None)
            .WithExpressionStyle(PlacementStyle.None)
            .WithStatementStyle(PlacementStyle.None);
        var formatted = service.GetFormattedText(options).Text;
        if (!factory.TryGetCodeService(formatted, out var formattedService))
        {
            throw new InvalidOperationException("formatter");
        }
        var canonical = formattedService.GetMinimalText(MinimalTextKind.SingleLine).Trim();
        var analyzed = SemanticAnalyzer.Analyze(canonical, globals, schema, policy);

        if (analyzed.Expression is not PipeExpression finalPipe || finalPipe.Operator is not TakeOperator finalTake ||
            finalTake.Expression is not LiteralExpression literal || Convert.ToUInt64(literal.LiteralValue, CultureInfo.InvariantCulture) != limit ||
            SyntaxFingerprint.Digest(finalPipe.Expression) != original.TreeDigest ||
            !original.Inventory.Tables.SequenceEqual(analyzed.Inventory.Tables) ||
            !original.Inventory.Columns.SequenceEqual(analyzed.Inventory.Columns) ||
            !original.Inventory.Functions.SequenceEqual(analyzed.Inventory.Functions) ||
            !original.OutputColumns.SequenceEqual(analyzed.OutputColumns))
        {
            throw new InvalidOperationException("bounded_tree_proof");
        }
        var expectedOperators = original.Inventory.Operators.Append("take").Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);
        if (!expectedOperators.SequenceEqual(analyzed.Inventory.Operators))
        {
            throw new InvalidOperationException("bounded_operator_proof");
        }
        return new BoundedAnalysis(canonical, analyzed);
    }
}
