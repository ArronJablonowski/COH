using System.Buffers;
using System.Text;
using System.Text.Encodings.Web;
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
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
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

    internal static byte[] CanonicalBytes<T>(T value)
    {
        var encoded = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        var writer = new ArrayBufferWriter<byte>(encoded.Length);
        var inString = false;
        var escaped = false;
        for (var index = 0; index < encoded.Length; index++)
        {
            var current = encoded[index];
            if (inString && !escaped && current is (byte)'<' or (byte)'>' or (byte)'&')
            {
                writer.Write(current switch
                {
                    (byte)'<' => "\\u003c"u8,
                    (byte)'>' => "\\u003e"u8,
                    _ => "\\u0026"u8,
                });
                continue;
            }
            if (inString && !escaped && index + 2 < encoded.Length && current == 0xe2 && encoded[index + 1] == 0x80 &&
                encoded[index + 2] is 0xa8 or 0xa9)
            {
                writer.Write(encoded[index + 2] == 0xa8 ? "\\u2028"u8 : "\\u2029"u8);
                index += 2;
                continue;
            }
            writer.Write(encoded.AsSpan(index, 1));
            if (!inString && current == (byte)'"')
            {
                inString = true;
            }
            else if (inString && escaped)
            {
                escaped = false;
            }
            else if (inString && current == (byte)'\\')
            {
                escaped = true;
            }
            else if (inString && current == (byte)'"')
            {
                inString = false;
            }
        }
        var canonical = writer.WrittenSpan.ToArray();
        for (var index = 0; index + 5 < canonical.Length; index++)
        {
            if (canonical[index] != (byte)'\\' || canonical[index + 1] != (byte)'u')
            {
                continue;
            }
            var slashCount = 1;
            for (var prior = index - 1; prior >= 0 && canonical[prior] == (byte)'\\'; prior--)
            {
                slashCount++;
            }
            if (slashCount % 2 == 0)
            {
                continue;
            }
            for (var digit = index + 2; digit < index + 6; digit++)
            {
                if (canonical[digit] is >= (byte)'A' and <= (byte)'F')
                {
                    canonical[digit] += (byte)('a' - 'A');
                }
            }
        }
        return canonical;
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
