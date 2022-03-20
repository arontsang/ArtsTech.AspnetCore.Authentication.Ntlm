# ArtsTech.AspnetCore.Authentication.Ntlm
An AspnetCore middleware for NTLM auth on Posix

## Requirements

 - Samba and Winbind installed
 - Samba joined to AD
 - Winbindd service running
 - ntlm_auth accessible on PATH

Configuration of Samba/Winbind is out of scope of this readme (and its quite beyond me).

## Usage

### Dotnet 6 Minimal API example
    
    using ArtsTech.AspnetCore.Authentication.Ntlm;
    var builder = WebApplication.CreateBuilder(args);   
    builder.Services
         .AddRazorPages()
         .AddAuthentication(NtlmDefaults.AuthenticationScheme)
         .AddNtlm();

    builder.Services.AddAuthorization();

    var app = builder.Build();
    app.UseStaticFiles();

    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapRazorPages();

    app.Run();

## FAQ

### Why doesn't this support role-based access control (RBAC)?

Sorry, I aim to do one thing with this project, and that is to implement NTLM auth on Linux. You add a custom [Claims Transform](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.iclaimstransformation.transformasync?view=aspnetcore-6.0) to add the Role claims from an LDAP query. Just register your `IClaimsTransformation` in your service provider.

