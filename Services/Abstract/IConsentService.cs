using IdentityServer4.Models;
using System.Threading.Tasks;
using IdentityServer.Models.Consent;

namespace IdentityServer.Services.Abstract
{
    public interface IConsentService
    {
        Task<ProcessConsentResult> ProcessConsent(ConsentInputModel model);
        Task<ConsentViewModel> BuildViewModelAsync(string returnUrl, ConsentInputModel model = null);
        ScopeViewModel CreateScopeViewModel(IdentityResource identity, bool check);
        ScopeViewModel CreateScopeViewModel(ApiScope scope, bool check);
    }
}
