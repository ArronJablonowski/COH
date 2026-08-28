using System.Security.Cryptography;
using System.Text;
using Kusto.Language.Syntax;

namespace COH.KustoValidator;

internal static class SyntaxFingerprint
{
    internal static string Digest(SyntaxElement root)
    {
        var builder = new StringBuilder();
        Append(root, builder);
        return ValidationEngine.Digest("COH-KUSTO-SYNTAX-TREE-V1\0", Encoding.UTF8.GetBytes(builder.ToString()));
    }

    private static void Append(SyntaxElement element, StringBuilder builder)
    {
        if (element is SyntaxToken token)
        {
            var value = token.ValueText;
            builder.Append('T').Append((int)token.Kind).Append(':').Append(value.Length).Append(':').Append(value).Append(';');
            return;
        }
        builder.Append('N').Append((int)element.Kind).Append('[');
        for (var index = 0; index < element.ChildCount; index++)
        {
            if (element.GetChild(index) is SyntaxElement child)
            {
                Append(child, builder);
            }
            else
            {
                builder.Append('-');
            }
        }
        builder.Append(']');
    }
}
