using Microsoft.Extensions.DependencyInjection;
using IdentityServer.Services.Abstract;
using IdentityServer.Services.Concrete;

namespace IdentityServer.Services
{
    public static class ISServiceBuilderExtensions
    {
        public static void AddISServices(this IServiceCollection services)
        {
            services.AddTransient<IAccountService, AccountService>();
            services.AddTransient<IConsentService, ConsentService>();
        }
    }
}
