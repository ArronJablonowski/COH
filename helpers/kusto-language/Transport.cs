using System.Buffers;
using System.Text;
using System.Text.Json;

namespace COH.KustoValidator;

internal static class Transport
{
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 64,
        WriteIndented = false,
    };

    internal static async Task<byte[]> ReadBoundedAsync(Stream input, CancellationToken cancellationToken)
    {
        var writer = new ArrayBufferWriter<byte>();
        var buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
        try
        {
            while (true)
            {
                var read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                if (writer.WrittenCount + read > Protocol.MaximumInputBytes)
                {
                    throw new InvalidDataException("input_size");
                }

                writer.Write(buffer.AsSpan(0, read));
            }

            return writer.WrittenSpan.ToArray();
        }
        finally
        {
            Array.Clear(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    internal static HelperRequest DecodeRequest(byte[] input)
    {
        RejectDuplicateProperties(input);
        var envelope = JsonSerializer.Deserialize<TransportEnvelope>(input, JsonOptions)
            ?? throw new InvalidDataException("transport_envelope");
        var chunks = envelope.Chunks();
        if (string.IsNullOrEmpty(chunks[0]))
        {
            throw new InvalidDataException("transport_chunks");
        }

        var builder = new StringBuilder();
        var missing = false;
        foreach (var chunk in chunks)
        {
            if (chunk is null)
            {
                missing = true;
                continue;
            }

            if (missing || chunk.Length == 0 || chunk.Length > Protocol.MaximumChunkCharacters)
            {
                throw new InvalidDataException("transport_chunks");
            }

            builder.Append(chunk);
        }

        var requestBytes = Encoding.UTF8.GetBytes(builder.ToString());
        if (requestBytes.Length == 0 || requestBytes.Length > Protocol.MaximumInputBytes)
        {
            throw new InvalidDataException("request_size");
        }

        RejectDuplicateProperties(requestBytes);
        return JsonSerializer.Deserialize<HelperRequest>(requestBytes, JsonOptions)
            ?? throw new InvalidDataException("helper_request");
    }

    internal static void RejectDuplicateProperties(ReadOnlySpan<byte> json)
    {
        using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 64,
        });
        Visit(document.RootElement);
    }

    private static void Visit(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException("duplicate_property");
                }

                Visit(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                Visit(item);
            }
        }
    }
}
