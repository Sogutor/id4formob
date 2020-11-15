using Microsoft.AspNetCore.Identity;
using System;
using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Models
{
    public enum GenderType
    {
        Male = 1,
        Famale
    }

    public class User : IdentityUser
    {
        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        [Required]
        public GenderType Gender { get; set; }

        [Required]
        public DateTimeOffset DateRegistration { get; set; }
    }
}
