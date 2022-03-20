using System;
using System.Security.Claims;
using ArtsTech.AspnetCore.Authentication.Ntlm.Reactive;

namespace ArtsTech.AspnetCore.Authentication.Ntlm;

internal class NtlmConnectionState : IDisposable
{
    private readonly SerialDisposable<NtlmSquidHelperProxy> _ntlmAuthHelperProxy = new();

    public NtlmSquidHelperProxy? NtlmAuthHelperProxy
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