using System;
using System.Security.Claims;
using ArtsTech.AspnetCore.Authentication.Ntlm.Reactive;
using ArtsTech.AspnetCore.Authentication.Ntlm.SquidHelper;

namespace ArtsTech.AspnetCore.Authentication.Ntlm;

internal class NtlmConnectionState : IDisposable
{
    private readonly SerialDisposable<INtlmAuthenticator> _ntlmAuthHelperProxy = new();

    public INtlmAuthenticator? NtlmAuthHelperProxy
    {
        get => _ntlmAuthHelperProxy.Disposable;
        set => _ntlmAuthHelperProxy.Disposable = value;
    }

    public ClaimsPrincipal? ConnectionUser { get; set; }


    public void Dispose()
    {
        _ntlmAuthHelperProxy.Dispose();
    }
}