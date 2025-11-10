using IdentityServer.Application.Services.AuthorizeServices;
using IdentityServer.Application.Services.SendMailServices;
using IdentityServer.Application.Services.TokenServices;
using IdentityServer.Persistence;
using IdentityServer.Persistence.Extensions;
using IdentityServer.Shared.Commons;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace IdentityServer.Api.Extensions;

public static class HostingExtesions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddControllersWithViews();
        builder.Services.AddRazorPages();

        builder.Services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.FromMinutes(5);
            options.Cookie.HttpOnly = true;
            options.Cookie.IsEssential = true;
        });
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = false;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.LoginPath = "/Account/Login";
        });
        builder.Services.AddCors(options =>
        {
            options.AddPolicy("*", policy =>
            {
                policy.AllowAnyOrigin()
                      .AllowAnyMethod()
                      .AllowAnyHeader();
            });
        });

        builder.Services.AddScoped<IAuthorizeService, AuthorizeService>();
        builder.Services.AddScoped<ITokenService, TokenService>();
        builder.Services.AddTransient<IEmailSender, SendMailService>();
        builder.Services.ConfigureValidatedOptions<OptionsPattern.OpenIddict>();
        builder.Services.ConfigureValidatedOptions<OptionsPattern.MailSettings>();
        builder.Services.AddCustomDbContext(builder);
        builder.Services.AddCustomIdentity();
        builder.Services.AddCustomSwaggerGen();
        builder.Services.AddCustomOpenIddict(builder);
        builder.Services.AddHostedService<Worker>();

        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app, WebApplicationBuilder builder)
    {
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
            app.UseDeveloperExceptionPage();
        }
        app.UseStaticFiles();

        app.UseSession();
        app.UseRouting();
        app.UseHttpsRedirection();

        app.UseCors("*");
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapDefaultControllerRoute();
        app.MapRazorPages();

        return app;
    }
}
