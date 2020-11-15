using IdentityServer.Context;
using IdentityServer.Models;
using IdentityServer.Services;
using IdentityServer.Settings;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace IdentityServer
{
    public class Startup
    {
        private readonly string CorsPolicy = "CorsPolicy";

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {

            // Add health check
            services.AddHealthChecks();

            // Bind app settings
            var sectionSettings = Configuration.GetSection("Settings");
            services.Configure<AppSettings>(sectionSettings);
            AppSettings _settings = new AppSettings();
            sectionSettings.Bind(_settings);

            // Add CORS
            services.AddCors(options =>
            {
                options.AddPolicy(CorsPolicy, builder =>
                {
                    builder.AllowAnyOrigin()
                           .AllowAnyMethod()
                           .AllowAnyHeader();
                });
            });

            // Db Context
            string connectionString = Configuration.GetConnectionString("IdentityServerDbConnection");
            services.AddDbContext<ApplicationDbContext>(options => options.UseNpgsql(connectionString));

            // Add Identity
            services.AddIdentity<User, IdentityRole>(options =>
            {
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 6;
                options.Lockout.MaxFailedAccessAttempts = 10;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

            // Add Identity Server
            services.AddIdentityServer()
                    //.AddDeveloperSigningCredential()
                    .AddSigningCredential(CreateSigningCredential())
                    .AddAspNetIdentity<User>()
                    .AddInMemoryIdentityResources(Config.GetIdentityResources())
                    .AddInMemoryApiResources(Config.GetApis())
                    .AddInMemoryClients(Config.GetClients());
            //.AddInMemoryIdentityResources(Configuration.GetSection("IdentityServer:IdentityResource"))
            //.AddInMemoryApiResources(Configuration.GetSection("IdentityServer:ApiResources"))
            //.AddInMemoryClients(Configuration.GetSection("IdentityServer:Clients"));

            // Add internal SSO services
            services.AddISServices();

            // Add Authentication
            services.AddAuthentication();

            services.AddMvc(options =>
            {
                options.RespectBrowserAcceptHeader = true;
               // options.Filters.Add(new SecurityHeadersAttribute());
            });

            services.AddTransient<ICorsPolicyService, DemoCorsPolicy>();

            services.AddRazorPages().AddRazorRuntimeCompilation();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if(env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseBrowserLink();

            app.UseHttpsRedirection();

            app.UseCors(CorsPolicy);

            app.UseStaticFiles();

            app.UseRouting();

            app.UseIdentityServer();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseHealthChecks("/health", new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }

        private SigningCredentials CreateSigningCredential()
        {
            var credentials = new SigningCredentials(GetSecurityKey(), SecurityAlgorithms.RsaSha256);

            return credentials;
        }
        private RSACryptoServiceProvider GetRSACryptoServiceProvider()
        {
            return new RSACryptoServiceProvider(2048);
        }
        private SecurityKey GetSecurityKey()
        {
            return new RsaSecurityKey(GetRSACryptoServiceProvider());
        }
    }
}
