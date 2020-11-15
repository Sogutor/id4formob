using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace IdentityServer
{
    public class Config
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
            };
        }

        public static IEnumerable<IdentityServer4.EntityFramework.Entities.ApiScope> GetApiScopes()
        {
            return new List<IdentityServer4.EntityFramework.Entities.ApiScope>
            {

            };
        }

        public static IEnumerable<ApiResource> GetApis()
        {
            return new List<ApiResource>
            {

            };
        }

        public static IEnumerable<Client> GetClients()
        {
            return new List<Client> {
              new Client
                {
                    ClientId = "interactive.public",

                    RedirectUris = { "mobileticketing://callback" },

                    RequireClientSecret = false,

                    AllowedGrantTypes = GrantTypes.Code,
                    AllowedScopes = { "openid", "profile" },

                    AllowOfflineAccess = true,
                    RefreshTokenUsage = TokenUsage.OneTimeOnly,
                    RefreshTokenExpiration = TokenExpiration.Sliding
                },
               new Client
                {
                    ClientId = "tf3G4RTCfLrE4iP98RsvRjda8DNdcdZR",
                    ClientName = "ciema_mob_app",
                    AllowedGrantTypes = GrantTypes.Hybrid,
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },
                    RedirectUris = { "mobileticketing" },
                    RequireConsent = false,
                    RequirePkce = true,
                    PostLogoutRedirectUris = { "mobileticketing://callback" },
                    AllowedCorsOrigins = { "http://mobileticketing" },
                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.OfflineAccess
                    },
                    AllowOfflineAccess = true,
                    AllowAccessTokensViaBrowser = true
                }
            };
        }
    }
}
