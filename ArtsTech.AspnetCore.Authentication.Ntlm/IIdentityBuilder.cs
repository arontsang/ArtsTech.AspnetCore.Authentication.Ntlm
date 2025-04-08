using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace ArtsTech.AspnetCore.Authentication.Ntlm;

public interface IIdentityBuilder
{
    ClaimsPrincipal BuildPrincipal(AuthenticationScheme scheme, string username);
}