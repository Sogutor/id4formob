using System.Threading.Tasks;
using IdentityServer.Models.Account;

namespace IdentityServer.Services.Abstract
{
    public interface IAccountService
    {
        Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model);
        Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl);
        Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId);
        Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId);
    }
}
