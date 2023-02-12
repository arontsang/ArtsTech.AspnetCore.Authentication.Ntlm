using System.Security.Claims;
using System.Security.Principal;

namespace ArtsTech.AspnetCore.Authentication.Ntlm;

public class SambaPrincipal : ClaimsPrincipal
{
	public SambaPrincipal(ClaimsIdentity identity) : base(identity)
	{
		
	}

	public SambaPrincipal(IPrincipal principal) : base(principal)
	{
	}

	public override bool IsInRole(string role)
	{
		if (NtlmIdentityBuilder.GetSecurityIdentifier(role) is { } roleSid)
		{
			if (HasClaim(ClaimTypes.GroupSid, roleSid))
			{
				return true;
			}
		}
		
		return base.IsInRole(role);
	}

	public override ClaimsPrincipal Clone()
	{
		return new SambaPrincipal(this);
	}
}