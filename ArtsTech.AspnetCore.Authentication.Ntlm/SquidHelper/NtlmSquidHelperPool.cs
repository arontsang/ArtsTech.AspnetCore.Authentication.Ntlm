using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading.Tasks;

namespace ArtsTech.AspnetCore.Authentication.Ntlm.SquidHelper;

public class NtlmSquidHelperPool(ISquidHelperFactory squidHelperFactory) : INtlmAuthenticatorPool
{
	private readonly ConcurrentQueue<ISquidHelper> _recycleQueue = new();

	public NtlmSquidHelperPool() : this(new LocalSquidHelperFactory())
	{
		
	}
	
	public async Task<INtlmAuthenticator> GetAuthenticator(string type1Message)
	{
		NtlmSquidHelperPool parent = this;
		ISquidHelper ret = parent.DequeueNextRecycled() ?? squidHelperFactory.Build();
		string authenticationChallenge = await ret.HandleNtlmType1MessageAsync(type1Message);
		INtlmAuthenticator authenticator = new NtlmHelperContext(parent, authenticationChallenge, ret);
		return authenticator;
	}

	private ISquidHelper? DequeueNextRecycled()
	{
		while (_recycleQueue.TryDequeue(out var result))
		{
			if (result.IsRunning)
				return result;
			result.Dispose();
		}
		return null;
	}

	private void Return(ISquidHelper proxy)
	{
		if (proxy.IsRunning && _recycleQueue.Count < 8)
			_recycleQueue.Enqueue(proxy);
		else
			proxy.Dispose();
	}

	private class NtlmHelperContext : INtlmAuthenticator
	{
		private readonly ISquidHelper _proxy;
		private readonly NtlmSquidHelperPool _parent;

		public NtlmHelperContext(
			NtlmSquidHelperPool parent,
			string authenticationChallenge,
			ISquidHelper proxy)
		{
			_proxy = proxy;
			_parent = parent;
			AuthenticationChallenge = authenticationChallenge;
		}

		public void Dispose() => _parent.Return(_proxy);

		public string AuthenticationChallenge { get; }

		public async Task<string?> Authenticate(string authToken)
		{
			return await _proxy.HandleNtlmType3MessageAsync(authToken);
		}
	}

	private class LocalSquidHelperFactory : ISquidHelperFactory
	{
		public ISquidHelper Build()
		{
			return new NtlmSquidHelperProxy();
		}
	}
	
	private class NtlmSquidHelperProxy : ISquidHelper
	{
		private readonly Process _process = Process.Start(new ProcessStartInfo("/usr/bin/env", "ntlm_auth --helper-protocol=squid-2.5-ntlmssp")
		{
			RedirectStandardInput = true,
			RedirectStandardOutput = true
		})!;
		private bool _disposed;

		public bool IsRunning => !_disposed && !_process.HasExited;

		public async Task<string> HandleNtlmType1MessageAsync(string type1Message)
		{
			await _process.StandardInput.WriteLineAsync($"YR {type1Message}");
			var response = await _process.StandardOutput.ReadLineAsync();

			if (response == null)
				throw new Exception();


			var responseParts = response.Split(new[] { ' ' }, 2);

			switch (responseParts[0])
			{
				case "TT":
					return responseParts[1];
				case "BH":
					throw new Exception(responseParts[1]);
				default:
					throw new NotSupportedException($"Unknown response type {responseParts[0]}");
			}
		}

		public async Task<string?> HandleNtlmType3MessageAsync(string authToken)
		{
			await _process.StandardInput.WriteLineAsync($"KK {authToken}");
			var response = await _process.StandardOutput.ReadLineAsync();

			if (response == null)
				throw new Exception();


			var responseParts = response.Split(new[] { ' ' }, 2);

			switch (responseParts[0])
			{
				case "AF":
					return responseParts[1];
				case "NA":
					return null;
				case "BH":
					throw new Exception(responseParts[1]);
				default:
					throw new NotSupportedException($"Unknown response type {responseParts[0]}");
			}
		}

		public void Dispose()
		{
			_disposed = true;
			_process.Dispose();
		}
	}
}