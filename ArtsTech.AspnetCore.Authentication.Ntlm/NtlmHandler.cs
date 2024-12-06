using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using ArtsTech.AspnetCore.Authentication.Ntlm.SquidHelper;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http;

namespace ArtsTech.AspnetCore.Authentication.Ntlm;

// ReSharper disable once ClassNeverInstantiated.Global
public class NtlmHandler
    : AuthenticationHandler<NtlmOptions>
    , IAuthenticationRequestHandler
{
    private static readonly Memory<byte> NtlmSspCString =
        new(new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 });
    #if !NETSTANDARD2_0
    private static readonly INtlmAuthenticatorPool AuthenticatorPool = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? new WindowsAuthenticatorPool()
        : new NtlmAuthenticatorPool();
    private readonly NtlmIdentityBuilder? _identityBuilder = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? null
        : new();
    #else
    private static readonly INtlmAuthenticatorPool AuthenticatorPool = new NtlmAuthenticatorPool();
    private readonly NtlmIdentityBuilder _identityBuilder = new();
    #endif

    [UsedImplicitly]
    public NtlmHandler(
        IOptionsMonitor<NtlmOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }

    public async Task<bool> HandleRequestAsync()
    {
        try
        {
            // Exit early, if we are unable to store a connection state.
            if (GetNtlmState() is not { } connectionState) return false;
            
            
            foreach (var authorizationString in Request.Headers[HeaderNames.Authorization])
            {
                if (!authorizationString.StartsWith("NTLM "))
                    continue;
                var payloadBase64 = authorizationString.Substring(5);

                var payload = Convert.FromBase64String(payloadBase64).AsMemory();

                // If payload is not of type NTLMSSP we can't handle this.
                if (!payload.Slice(0, 8).Span.SequenceEqual(NtlmSspCString.Span) || payload.Length <= 12)
                    continue;

                var messageType = BinaryPrimitives.ReadInt32LittleEndian(payload.Slice(8, 4).Span);

                switch (messageType)
                {
                    case 1:
                    {
                        var authHelperProxy= connectionState.NtlmAuthHelperProxy = await AuthenticatorPool.GetAuthenticator(payloadBase64);
                        var challenge = authHelperProxy.AuthenticationChallenge;
                        Response.Headers.Add(HeaderNames.WWWAuthenticate, $"NTLM {challenge}");
                        Response.StatusCode = StatusCodes.Status401Unauthorized;
                        return true;
                    }
                    case 2:
                    {
                        Logger.LogWarning("Unexpected NTLM type 2 message from client");
                        return false;
                    }
                    case 3:
                    {
                        if (connectionState.NtlmAuthHelperProxy is {} ntlmHelper)
                        {
                            if (await ntlmHelper.Authenticate(payloadBase64) is {} username)
                            {
                                if (_identityBuilder is { } identityBuilder)
                                    connectionState.ConnectionUser = identityBuilder.BuildPrincipal(username);
                                else
                                {
                                    var identity = new ClaimsIdentity(Scheme.Name);
                                    identity.AddClaim(new Claim(ClaimTypes.Name, username));
                                    connectionState.ConnectionUser = new SambaPrincipal(identity);
                                }
                                // Dispose helper.
                                connectionState.NtlmAuthHelperProxy = null;
                            }
                        }
                        return false;
                    }
                    default:
                    {
                        Logger.LogWarning("Unknown NTLM message type {MessageType}", messageType);
                        return false;
                    }
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Unexpected error handling NTLM login");
            return false;
        }
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (GetNtlmState() is not { } connectionState)
            return Task.FromResult(AuthenticateResult.NoResult());
        
        if (connectionState is { ConnectionUser: {} connectionUser})
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(connectionUser.Clone(), Scheme.Name)));
        
        return Task.FromResult(AuthenticateResult.NoResult());
    }


    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.Add(HeaderNames.WWWAuthenticate, "NTLM");
        return base.HandleChallengeAsync(properties);
    }
    

    private static readonly object NtlmStateKey = new();

    private NtlmConnectionState? GetNtlmState()
    {
        if (Context.Features.Get<IConnectionItemsFeature>() is not { } connectionItems)
        {
            Logger.LogWarning($"NTLM authentication requires a server that supports {nameof(IConnectionItemsFeature)} like Kestrel.");
            return null;
        }

        if (Context.Features.Get<IConnectionCompleteFeature>() is not { } connectionLifetime)
        {
            Logger.LogWarning($"NTLM authentication requires a server that supports {nameof(IConnectionLifetimeFeature)} like Kestrel.");
            return null;
        }

        if (connectionItems.Items.TryGetValue(NtlmStateKey, out var ret) && ret is NtlmConnectionState state)
            return state;


        connectionItems.Items[NtlmStateKey] = state = new();
        connectionLifetime.OnCompleted(DisposeState, state);

        return state;
    }

    private static Task DisposeState(object s)
    {
        if (s is IDisposable disposable)
        {
            disposable.Dispose();
        }
        return Task.CompletedTask;
    }


}

public class NtlmHelperNotInitException : Exception
{

}
