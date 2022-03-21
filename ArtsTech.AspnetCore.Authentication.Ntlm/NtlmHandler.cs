using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System;
using System.Buffers.Binary;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Connections.Features;

namespace ArtsTech.AspnetCore.Authentication.Ntlm;

// ReSharper disable once ClassNeverInstantiated.Global
public class NtlmHandler
    : AuthenticationHandler<NtlmOptions>
{
    private static readonly Memory<byte> NtlmSspCString =
        new(new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 });

    private static readonly object ChallengeKey = new();
    private string? Challenge
    {
        get => Context.Items[ChallengeKey] as string;
        set => Context.Items[ChallengeKey] = value;
    }

    [UsedImplicitly]
    public NtlmHandler(
        IOptionsMonitor<NtlmOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var connectionState = GetNtlmState();
        try
        {
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
                        var authHelperProxy = connectionState.NtlmAuthHelperProxy ??= new NtlmSquidHelperProxy();
                        Challenge = await authHelperProxy.HandleNtlmType1MessageAsync(payloadBase64);
                        return AuthenticateResult.Fail("NTLM Challenge sent.");
                    }
                    case 2:
                        return AuthenticateResult.Fail(
                            new InvalidOperationException("NTLM type 2 message is not expected from client."));
                    case 3:
                    {
                        if (connectionState.NtlmAuthHelperProxy is { IsRunning: true } ntlmHelper 
                            && await ntlmHelper.HandleNtlmType3MessageAsync(payloadBase64) is {} username)
                        {
                            var user = connectionState.ConnectionUser = new ClaimsPrincipal(new GenericIdentity(username));
                                // Dispose helper.
                            connectionState.NtlmAuthHelperProxy = null;
                            return AuthenticateResult.Success(new AuthenticationTicket(user, Scheme.Name));
                        }
                        else
                        {
                            return AuthenticateResult.Fail(new NtlmHelperNotInitException());
                        }
                    }
                    default:
                        return AuthenticateResult.Fail(
                            new InvalidOperationException($"Unknown NTLM message type {messageType}."));

                }
            }

            if (connectionState.ConnectionUser is { } existingUser)
            {
                return AuthenticateResult.Success(new AuthenticationTicket(existingUser, Scheme.Name));
            }

            return AuthenticateResult.NoResult();
        }
        catch (Exception ex)
        {
            return AuthenticateResult.Fail(ex);
        }
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (Challenge is {} challenge)
        {
            Response.Headers.Add(HeaderNames.WWWAuthenticate, $"NTLM {challenge}");
        }
        else
        {
            Response.Headers.Add(HeaderNames.WWWAuthenticate, "NTLM");
        }

        return base.HandleChallengeAsync(properties);
    }
    

    private static object NtlmStateKey = new();

    private NtlmConnectionState GetNtlmState()
    {
        if (Context.Features.Get<IConnectionItemsFeature>() is not { } connectionItems)

            throw new NotSupportedException(
                $"NTLM authentication requires a server that supports {nameof(IConnectionItemsFeature)} like Kestrel.");


        if (Context.Features.Get<IConnectionCompleteFeature>() is not { } connectionLifetime)
            throw new NotSupportedException(
                $"NTLM authentication requires a server that supports {nameof(IConnectionLifetimeFeature)} like Kestrel.");

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
