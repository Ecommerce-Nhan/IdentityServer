using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Shared.Commons;

public class OptionsPattern
{
    public class OpenIddict
    {
        [Required(AllowEmptyStrings = false)]
        public string Issuer { get; set; } = string.Empty;

        [Required(AllowEmptyStrings = false)]
        public string KeySignature { get; set; } = string.Empty;

        [Required(AllowEmptyStrings = false)]
        public string RedirectUriCadastral { get; set; } = string.Empty;
    }

    public class MailSettings
    {
        public int Port { get; set; }

        [Required(AllowEmptyStrings = false)]
        public string Mail { get; set; } = string.Empty;

        [Required(AllowEmptyStrings = false)]
        public string DisplayName { get; set; } = string.Empty;

        [Required(AllowEmptyStrings = false)]
        public string Password { get; set; } = string.Empty;

        [Required(AllowEmptyStrings = false)]
        public string Host { get; set; } = string.Empty;
    }

    public class AuthOptions
    {
        [Required(AllowEmptyStrings = false)]
        public string UserServiceEndpoint { get; set; } = string.Empty;

        [Required(AllowEmptyStrings = false)]
        public string ServerIssuer { get; set; } = string.Empty;
    }
}