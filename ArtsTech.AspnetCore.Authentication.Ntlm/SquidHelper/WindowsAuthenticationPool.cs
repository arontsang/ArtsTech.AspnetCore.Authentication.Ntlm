#if !NETSTANDARD2_0
using System;
using System.Net.Security;
using System.Threading.Tasks;

namespace ArtsTech.AspnetCore.Authentication.Ntlm.SquidHelper;

internal class WindowsAuthenticatorPool : INtlmAuthenticatorPool
{
    public Task<INtlmAuthenticator> GetAuthenticator(string type1Message)
    {
        try
        {
            var authentication = new NegotiateAuthentication(new NegotiateAuthenticationServerOptions
                { Package = "NTLM" });
            var challenge = authentication.GetOutgoingBlob(type1Message, out var code)!;
            var ret = new WindowsAuthenticator(authentication) { AuthenticationChallenge = challenge };

            return Task.FromResult<INtlmAuthenticator>(ret);
        }
        catch (Exception ex)
        {
            return Task.FromException<INtlmAuthenticator>(ex);
        }
    }

    private record WindowsAuthenticator(NegotiateAuthentication NegotiateAuthentication) : INtlmAuthenticator
    {
        public void Dispose()
        {
            NegotiateAuthentication.Dispose();
        }

        public required string AuthenticationChallenge { get; init; }
        public Task<string?> Authenticate(string authToken)
        {
            try
            {
                var ret = NegotiateAuthentication.GetOutgoingBlob(authToken, out var code);
                if (code == NegotiateAuthenticationStatusCode.Completed)
                    return Task.FromResult(NegotiateAuthentication.RemoteIdentity.Name);
                return Task.FromResult(default(string?));
            }
            catch (Exception ex)
            {
                return Task.FromResult(default(string?));
            }
        }
    }
}

#endif