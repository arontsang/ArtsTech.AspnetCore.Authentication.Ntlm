using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace ArtsTech.AspnetCore.Authentication.Ntlm;

internal class NtlmSquidHelperProxy : IDisposable
{
    private readonly Process _process = Process.Start(
        new ProcessStartInfo("ntlm_auth", "--helper-protocol=squid-2.5-ntlmssp")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
        }
    )!;

    public bool IsRunning => !_process.HasExited;

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
        _process.Dispose();
    }
}