using System;
using System.Threading.Tasks;

namespace ArtsTech.AspnetCore.Authentication.Ntlm.SquidHelper;

public interface INtlmAuthenticator : IDisposable
{
	string AuthenticationChallenge { get; }

	Task<string?> Authenticate(string authToken);
}