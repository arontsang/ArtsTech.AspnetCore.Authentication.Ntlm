using System;
using System.Threading.Tasks;

namespace ArtsTech.AspnetCore.Authentication.Ntlm.SquidHelper;

public interface ISquidHelper : IDisposable
{
    bool IsRunning { get; }

    Task<string> HandleNtlmType1MessageAsync(string type1Message);

    Task<string?> HandleNtlmType3MessageAsync(string type3Message);
}