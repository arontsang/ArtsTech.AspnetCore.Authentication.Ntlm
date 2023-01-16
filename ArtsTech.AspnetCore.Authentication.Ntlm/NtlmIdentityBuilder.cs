using System;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using AdvancedDLSupport;

namespace ArtsTech.AspnetCore.Authentication.Ntlm;

public class NtlmIdentityBuilder
{
	
	private static readonly IWinBindClient? WinBindClient;
	private static readonly UTF8Encoding Utf8 = new(false);
	
	static NtlmIdentityBuilder()
	{
		try
		{
			var activator = new NativeLibraryBuilder();
			WinBindClient = activator.ActivateInterface<IWinBindClient>("libwbclient.so.0");
		}
		catch
		{
			// Do nothing. Unable to load libwbclient
		}
	}
	
	public ClaimsPrincipal BuildPrincipal(string username)
	{
		var ret = new GenericIdentity(username);
		if (GetSid(username) is { } sid)
		{
			ret.AddClaim(new Claim(ClaimTypes.PrimarySid, sid));
		}
		
		return new ClaimsPrincipal(ret);
	}

	private static string? GetSid(string username)
	{
		if (WinBindClient is {} lib 
			&& ExtractUserAndDomain(username) is ({ } domain, { } user))
		{
			return GetSid(lib, domain, user);
		}

		return null;
	}
	
	private static string? GetSid(IWinBindClient wbcLib, ReadOnlyMemory<char> domain, ReadOnlyMemory<char> user)
	{
		Span<byte> domainUtf8 = stackalloc byte[128];
		Span<byte> usernameUtf8 = stackalloc byte[128];


		GetUtf8String(domain, ref domainUtf8);
		GetUtf8String(user, ref usernameUtf8);
		
		return GetSid(
			wbcLib,
			domainUtf8,
			usernameUtf8
		);
	}
	
	private static string? GetSid(IWinBindClient wbcLib, ReadOnlySpan<byte> domain, ReadOnlySpan<byte> user)
	{
		Span<byte> sidBinary = stackalloc byte[128];
		WbcSidType type = default;

		if (wbcLib.wbcLookupName(domain, user, sidBinary, ref type) == WbcErrorType.WBC_ERR_SUCCESS)
		{
			return GetSidString(sidBinary);
		}

		return null;
	}
	
	
	
	private static string GetSidString(ReadOnlySpan<byte> byteCollection)
	{

		// sid[0] is the Revision, we allow only version 1, because it's the
		// only version that exists right now.
		if (byteCollection[0] != 1)
			throw new ArgumentOutOfRangeException("SID (bytes(0)) revision must be 1");

		var stringSidBuilder = new StringBuilder("S-1-");

		// The next byte specifies the numbers of sub authorities
		// (number of dashes minus two), should be 5 or less, but not enforcing that
		var subAuthorityCount = byteCollection[1];

		// IdentifierAuthority (6 bytes starting from the second) (big endian)
		long identifierAuthority = 0;

		var offset = 2;
		var size = 6;
		int i;

		for (i = 0; i <= size - 1; i++)
			identifierAuthority = identifierAuthority | System.Convert.ToInt64(byteCollection[offset + i]) << 8 * (size - 1 - i);

		stringSidBuilder.Append(identifierAuthority.ToString());

		// Iterate all the SubAuthority (little-endian)
		offset = 8;
		size = 4; // 32-bits (4 bytes) for each SubAuthority
		i = 0;
		while (i < subAuthorityCount)
		{
			long subAuthority = 0;

			for (var j = 0; j <= size - 1; j++)
				// the below "Or" is a logical Or not a boolean operator
				subAuthority = subAuthority | System.Convert.ToInt64(byteCollection[offset + j]) << 8 * j;
			stringSidBuilder.Append("-").Append(subAuthority);
			i += 1;
			offset += size;
		}

		return stringSidBuilder.ToString();
	}
	
	private static (ReadOnlyMemory<char> domain, ReadOnlyMemory<char> user)? ExtractUserAndDomain(string username)
	{
		if (username.IndexOf('\\') is { } indexOf and > 0)
		{
			var memory = username.AsMemory();
			return (memory.Slice(0, indexOf), memory.Slice(indexOf + 1));
		}

		return null;
	}
	
	private static void GetUtf8String(ReadOnlyMemory<char> input, ref Span<byte> ret)
	{
		unsafe
		{
			fixed (byte* retPtr = ret)
			fixed (char* inputPtr = input.Span)
			{
				var length = Utf8.GetBytes(inputPtr, input.Length, retPtr, ret.Length);
				ret[length] = 0x00;
			}
		}
	}
	
	
	public interface IWinBindClient
	{
		WbcErrorType wbcLookupName(ReadOnlySpan<byte> domainName, ReadOnlySpan<byte> userName, Span<byte> sid, ref WbcSidType sidType);
	}

	public enum WbcSidType
	{
		WBC_SID_NAME_USE_NONE=0,
		WBC_SID_NAME_USER=1,
		WBC_SID_NAME_DOM_GRP=2,
		WBC_SID_NAME_DOMAIN=3,
		WBC_SID_NAME_ALIAS=4,
		WBC_SID_NAME_WKN_GRP=5,
		WBC_SID_NAME_DELETED=6,
		WBC_SID_NAME_INVALID=7,
		WBC_SID_NAME_UNKNOWN=8,
		WBC_SID_NAME_COMPUTER=9
	}

	public enum WbcErrorType
	{
		WBC_ERR_SUCCESS = 0,    /**< Successful completion **/
		WBC_ERR_UNKNOWN_FAILURE,/**< General failure **/
		WBC_ERR_NO_MEMORY,      /**< Memory allocation error **/
		WBC_ERR_INVALID_SID,    /**< Invalid SID format **/
		WBC_ERR_INVALID_PARAM,  /**< An Invalid parameter was supplied **/
		WBC_ERR_WINBIND_NOT_AVAILABLE,   /**< Winbind daemon is not available **/
		WBC_ERR_DOMAIN_NOT_FOUND,        /**< Domain is not trusted or cannot be found **/
		WCB_INVALID_RESPONSE,        /**< Winbind returned an invalid response **/
	}
}