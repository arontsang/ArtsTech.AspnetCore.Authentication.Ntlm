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
		var ret = new ClaimsIdentity(username);
		AddClaims(ret);
		return new ClaimsPrincipal(ret);
	}

	private static void AddClaims(ClaimsIdentity identity)
	{
		if (WinBindClient is {} lib 
			&& ExtractUserAndDomain(identity.Name) is ({ } domain, { } user))
		{
			Span<byte> sidBinary = stackalloc byte[68];
			if (TryGetSid(lib, domain, user, sidBinary))
			{
				identity.AddClaim(new Claim(ClaimTypes.PrimarySid, SidToString(lib, sidBinary)));
				GetUserGroupSids(lib, identity, sidBinary);
			}
		}
	}

	private static void GetUserGroupSids(IWinBindClient lib, ClaimsIdentity identity, ReadOnlySpan<byte> sidBinary)
	{
		unsafe
		{
			IntPtr buffer = IntPtr.Zero;

			try
			{
				if (lib.LookupUserSids(sidBinary, true, out int numberOfSids, out buffer) !=
				    WbcErrorType.WBC_ERR_SUCCESS)
					return;

				foreach (var groupSid in new Span<Sid>(buffer.ToPointer(), numberOfSids))
				{
					if (SidToString(lib, groupSid.Value) is {} sidString)
						identity.AddClaim(new Claim(ClaimTypes.GroupSid, sidString));

				}

				Console.WriteLine("hello");
			}
			finally
			{
				if (buffer != IntPtr.Zero)
					lib.FreeMemory(buffer);
			}
		}
	}

	private struct Sid
	{
		private unsafe fixed byte _value[68];
		public Span<byte> Value
		{
			get
			{
				unsafe
				{
					fixed(byte* ptr = _value)
						return new Span<byte>(ptr, 68);
				}
			}
		}
	}

	private static bool TryGetSid(IWinBindClient wbcLib, ReadOnlyMemory<char> domain, ReadOnlyMemory<char> user, Span<byte> sidBinary)
	{
		Span<byte> domainUtf8 = stackalloc byte[128];
		Span<byte> usernameUtf8 = stackalloc byte[128];


		GetUtf8String(domain, ref domainUtf8);
		GetUtf8String(user, ref usernameUtf8);
		
		return TryGetSid(
			wbcLib,
			domainUtf8,
			usernameUtf8,
			sidBinary
		);
	}
	
	private static bool TryGetSid(IWinBindClient wbcLib, ReadOnlySpan<byte> domain, ReadOnlySpan<byte> user, Span<byte> sidBinary)
	{
		return wbcLib.LookupName(domain, user, sidBinary, out _) == WbcErrorType.WBC_ERR_SUCCESS;
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
		
		[NativeSymbol("wbcLookupUserSids")]
		WbcErrorType LookupUserSids(ReadOnlySpan<byte> sidBinary, bool domainGroupsOnly, out int numberOfSids, out IntPtr buffer);

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


