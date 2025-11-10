using OpenIddict.Abstractions;

namespace IdentityServer.Application.Helpers;

public static class OpenIddictRequestExtensions
{
    public static IReadOnlyList<string> GetPromptModes(this OpenIddictRequest request)
    {
        return request.Prompt?
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            ?? Array.Empty<string>();
    }

    public static bool HasPrompt(this OpenIddictRequest request, string promptMode)
    {
        return request.GetPromptModes()
            .Contains(promptMode, StringComparer.OrdinalIgnoreCase);
    }
}