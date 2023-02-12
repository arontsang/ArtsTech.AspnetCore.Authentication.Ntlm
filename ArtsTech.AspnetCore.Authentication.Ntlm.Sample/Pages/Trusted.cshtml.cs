using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ArtsTech.AspnetCore.Authentication.Ntlm.Sample.Pages;

[Authorize(Roles = "Samdom\\Trusted-users")]    
public class TrustedModel : PageModel
{
	private readonly ILogger<TrustedModel> _logger;

	public TrustedModel(ILogger<TrustedModel> logger)
	{
		_logger = logger;
	}

	public void OnGet()
	{

	}
}