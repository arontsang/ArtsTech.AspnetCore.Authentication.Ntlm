using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace ArtsTech.AspnetCore.Authentication.Ntlm
{
    public class NtlmHandler
        : AuthenticationHandler<NtlmOptions>
    {
        private readonly Memory<byte> NtlmSspCString = new(new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 });

        public NtlmHandler(
            IOptionsMonitor<NtlmOptions> options, 
            ILoggerFactory logger, 
            UrlEncoder encoder, 
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
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
            }

            Response.Headers.Add(HeaderNames.WWWAuthenticate, "NTLM");
            return AuthenticateResult.NoResult();
        }
    }
}
