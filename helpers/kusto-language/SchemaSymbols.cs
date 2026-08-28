using Kusto.Language;
using Kusto.Language.Symbols;

namespace COH.KustoValidator;

internal static class SchemaSymbols
{
    internal static GlobalState Build(SchemaBinding schema)
    {
        var tables = schema.Tables.Select(table => new TableSymbol(
            table.Name,
            table.Columns.Select(column => new ColumnSymbol(column.Name, ScalarType(column.Type))).ToArray())).ToArray();
        return GlobalState.Default.WithDatabase(new DatabaseSymbol(schema.Database, tables));
    }

    internal static string TypeName(TypeSymbol type) => type switch
    {
        var value when value == ScalarTypes.Bool => "bool",
        var value when value == ScalarTypes.DateTime => "datetime",
        var value when value == ScalarTypes.Decimal => "decimal",
        var value when value == ScalarTypes.Guid => "guid",
        var value when value == ScalarTypes.Int => "int",
        var value when value == ScalarTypes.Long => "long",
        var value when value == ScalarTypes.Real => "real",
        var value when value == ScalarTypes.String => "string",
        var value when value == ScalarTypes.TimeSpan => "timespan",
        _ => string.Empty,
    };

    internal static bool IsNullable(ColumnSymbol column, GlobalState globals, SchemaBinding schema)
    {
        var sources = column.OriginalColumns.Count == 0 ? [column] : column.OriginalColumns;
        var resolved = false;
        var nullable = false;
        foreach (var source in sources)
        {
            var table = globals.GetTable(source);
            var schemaTable = table is null ? null : schema.Tables.SingleOrDefault(value => value.Name == table.Name);
            var schemaColumn = schemaTable?.Columns.SingleOrDefault(value => value.Name == source.Name);
            if (schemaColumn is not null)
            {
                resolved = true;
                nullable |= schemaColumn.Nullable;
            }
        }
        return !resolved || nullable;
    }

    private static ScalarSymbol ScalarType(string name) => name switch
    {
        "bool" => ScalarTypes.Bool,
        "datetime" => ScalarTypes.DateTime,
        "decimal" => ScalarTypes.Decimal,
        "guid" => ScalarTypes.Guid,
        "int" => ScalarTypes.Int,
        "long" => ScalarTypes.Long,
        "real" => ScalarTypes.Real,
        "string" => ScalarTypes.String,
        "timespan" => ScalarTypes.TimeSpan,
        _ => throw new InvalidDataException("schema_type"),
    };
}
