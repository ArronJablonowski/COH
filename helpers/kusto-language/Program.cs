using System.Text;
using System.Text.Json;
using COH.KustoValidator;

try
{
    var input = await Transport.ReadBoundedAsync(Console.OpenStandardInput(), CancellationToken.None).ConfigureAwait(false);
    var request = Transport.DecodeRequest(input);
    Array.Clear(input);
    var response = ValidationEngine.Validate(request);
    await JsonSerializer.SerializeAsync(Console.OpenStandardOutput(), response, Transport.JsonOptions).ConfigureAwait(false);
    return 0;
}
catch (Exception exception) when (exception is JsonException or InvalidDataException or DecoderFallbackException)
{
    await Console.Error.WriteAsync("request_denied\n").ConfigureAwait(false);
    return 64;
}
catch (OperationCanceledException)
{
    await Console.Error.WriteAsync("request_cancelled\n").ConfigureAwait(false);
    return 65;
}
catch
{
    await Console.Error.WriteAsync("helper_unavailable\n").ConfigureAwait(false);
    return 70;
}
