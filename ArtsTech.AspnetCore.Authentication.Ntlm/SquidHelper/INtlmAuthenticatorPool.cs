using System.Threading.Tasks;

namespace ArtsTech.AspnetCore.Authentication.Ntlm.SquidHelper;

internal interface INtlmAuthenticatorPool
{
    Task<INtlmAuthenticator> GetAuthenticator(string type1Message);
}