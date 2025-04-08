using System.Threading.Tasks;

namespace ArtsTech.AspnetCore.Authentication.Ntlm.SquidHelper;

public interface INtlmAuthenticatorPool
{
    Task<INtlmAuthenticator> GetAuthenticator(string type1Message);
}