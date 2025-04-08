using System.Runtime.InteropServices;
using System.Security.Claims;
using ArtsTech.AspnetCore.Authentication.Ntlm.SquidHelper;
using Microsoft.AspNetCore.Authentication;

namespace ArtsTech.AspnetCore.Authentication.Ntlm;

public class NtlmOptions : AuthenticationSchemeOptions
{
    public INtlmAuthenticatorPool AuthenticatorPool { get; set; }
    public IIdentityBuilder IdentityBuilder { get; set; }

    public NtlmOptions()
    {
#if !NETSTANDARD2_0
        AuthenticatorPool = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? new WindowsAuthenticatorPool()
            : new NtlmSquidHelperPool();
        IdentityBuilder = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? new DefaultIdentityBuilder()
        : new NtlmIdentityBuilder();
#else
        AuthenticatorPool = new NtlmSquidHelperPool();
        IdentityBuilder = new NtlmIdentityBuilder();
#endif
    }

    private class DefaultIdentityBuilder : IIdentityBuilder
    {
        public ClaimsPrincipal BuildPrincipal(AuthenticationScheme scheme, string username)
        {
            var identity = new ClaimsIdentity(scheme.Name);
            identity.AddClaim(new Claim(ClaimTypes.Name, username));
            return new SambaPrincipal(identity);
        }
    }
}

