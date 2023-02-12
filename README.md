[![NuGet version (ArtsTech.AspnetCore.Authentication.Ntlm)](https://img.shields.io/nuget/v/ArtsTech.AspnetCore.Authentication.Ntlm.svg?style=flat-square)](https://www.nuget.org/packages/ArtsTech.AspnetCore.Authentication.Ntlm)

# ArtsTech.AspnetCore.Authentication.Ntlm
An AspnetCore middleware for NTLM auth on Posix

## Requirements

 - Samba and Winbind installed
 - Samba joined to AD
 - Winbindd service running
 - ntlm_auth accessible on PATH

## Optional

 - Samba Winbind Client libraries (include PrimarySid claim and GroupSid claims)

Configuration of Samba/Winbind is out of scope of this readme (and its quite beyond me).

## Usage

### Claims

This library will return a ClaimsPrinciple with a ClaimsIdentity.

The ClaimsIdentity will have the following claims:

    - ClaimTypes.Name
    - ClaimTypes.PrimarySid (Optional requires libwbclient)
    - ClaimTypes.GroupSid (Optional requires libwbclient)

**Note, we only return GroupSid for user's direct membership. We do not recursively search for user's group membership yet.

You can instead use an `IClaimsTransformation` to search LDAP for group memberships recursively. 

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



