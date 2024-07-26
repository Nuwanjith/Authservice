using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.IO;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        // Configure data protection to use a common key storage location
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(@"D:\ASE\Enterprise-Application-development\cookies"))
            .SetApplicationName("SharedCookieApp");

        // Configure cookie authentication
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.Cookie.Name = ".AspNet.SharedCookie"; // Must match with the other microservice
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(30); // Ensure this is the same as the first microservice
                options.LoginPath = "/Auth/Login"; // Path to redirect for unauthenticated requests
                options.AccessDeniedPath = "/Auth/AccessDenied"; // Path to redirect for access denied
                options.SlidingExpiration = true; // Refresh expiration time on each request

                // Add events for detailed logging
                options.Events = new CookieAuthenticationEvents
                {
                    OnRedirectToLogin = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                        logger.LogInformation("Redirecting to login page: {ReturnUrl}", context.RedirectUri);
                        return Task.CompletedTask;
                    },
                    OnRedirectToAccessDenied = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                        logger.LogInformation("Redirecting to access denied page: {ReturnUrl}", context.RedirectUri);
                        return Task.CompletedTask;
                    },
                    OnValidatePrincipal = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Startup>>();
                        logger.LogInformation("Validating principal: {Principal}", context.Principal?.Identity?.Name);
                        return Task.CompletedTask;
                    }
                };
            });

        services.AddControllersWithViews();
        services.AddLogging(); // Ensure logging services are added
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Auth/Login"); // Redirect to login on exceptions
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllerRoute(
                name: "default",
                pattern: "{controller=Auth}/{action=Login}/{id?}");
        });
    }
}
