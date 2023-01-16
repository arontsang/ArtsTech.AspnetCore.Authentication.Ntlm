using System;
using System.Runtime.InteropServices;
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
		if (wbcLib.LookupName(domain, user, sidBinary, out var type) == WbcErrorType.WBC_ERR_SUCCESS)
		{
			return SidToString(wbcLib, sidBinary);
		}

		return null;
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
	
	private static string? SidToString(IWinBindClient winBind, ReadOnlySpan<byte> sidBinary)
	{
		var success = winBind.SidToString(sidBinary, out var ptr);
		try
		{
			if (success == WbcErrorType.WBC_ERR_SUCCESS)
			{
				return Marshal.PtrToStringAnsi(ptr);
			}
		}
		finally
		{
			if (ptr != IntPtr.Zero)
				winBind.FreeMemory(ptr);
		}

		return null;
	}
	
	
	public interface IWinBindClient
	{
		[NativeSymbol("wbcLookupName")]
		WbcErrorType LookupName(ReadOnlySpan<byte> domainName, ReadOnlySpan<byte> userName, Span<byte> sid, out WbcSidType sidType);

		[NativeSymbol("wbcSidToString")]
		WbcErrorType SidToString(ReadOnlySpan<byte> sidBinary, out IntPtr sidString);

		[NativeSymbol("wbcFreeMemory")]
		void FreeMemory(IntPtr ptr);
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


