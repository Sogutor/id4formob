using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Identity;
using System;
using System.Threading.Tasks;
using IdentityServer.Models;

namespace IdentityServer.Services
{
    public class IdentityProfileService : IProfileService
    {
        private readonly UserManager<User> _userManager;

        public IdentityProfileService(UserManager<User> userManager)
        {
            _userManager = userManager;
        }

        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            throw new NotImplementedException();
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            throw new NotImplementedException();
        }
    }
}
