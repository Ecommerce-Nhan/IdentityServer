namespace IdentityServer.Shared.Commons;

public class Constants
{
    public static class ErrorConstants
    {
        public const string OpenIDRequest = "The OpenID Connect request cannot be retrieved.";
        public const string GrantType = "The specified grant type is not supported.";
        public const string Account = "The mandatory 'username' and/or 'password' parameters are missing.";
    }

    public static class ClientConstants
    {
        public const string Ecommerce = "ecommerce";
        public const string Ecommerce_ClientId = "2ddc26af-9623-4f6d-9abb-9b412bae5ef5";
        public const string Ecommerce_ClientSecret = "388D45FA-B36B-4988-BA59-B187D329C207";
        public const string Ecommerce_DisplayName = "E-Commerce";
    }
}