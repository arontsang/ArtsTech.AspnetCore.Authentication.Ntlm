using Microsoft.AspNetCore.Authentication;
using System;

namespace ArtsTech.AspnetCore.Authentication.Ntlm
{
    public static class NtlmExtensions
    {
        /// <summary>
        /// Configures the <see cref="AuthenticationBuilder"/> to use Ntlm (also known as Windows, Kerberos, or NTLM) authentication
        /// using the default scheme from <see cref="NtlmDefaults.AuthenticationScheme"/>.
        /// <para>
        /// This authentication handler supports Kerberos on Windows and Linux servers.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <returns>The original builder.</returns>
        public static AuthenticationBuilder AddNtlm(this AuthenticationBuilder builder)
            => builder.AddNtlm(NtlmDefaults.AuthenticationScheme, _ => { });

        /// <summary>
        /// Configures the <see cref="AuthenticationBuilder"/> to use Ntlm (also known as Windows, Kerberos, or NTLM) authentication
        /// using the default scheme. The default scheme is specified by <see cref="NtlmDefaults.AuthenticationScheme"/>.
        /// <para>
        /// This authentication handler supports Kerberos on Windows and Linux servers.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="configureOptions">Allows for configuring the authentication handler.</param>
        /// <returns>The original builder.</returns>
        public static AuthenticationBuilder AddNtlm(this AuthenticationBuilder builder, Action<NtlmOptions> configureOptions)
            => builder.AddNtlm(NtlmDefaults.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Configures the <see cref="AuthenticationBuilder"/> to use Ntlm (also known as Windows, Kerberos, or NTLM) authentication
        /// using the specified authentication scheme.
        /// <para>
        /// This authentication handler supports Kerberos on Windows and Linux servers.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The scheme name used to identify the authentication handler internally.</param>
        /// <param name="configureOptions">Allows for configuring the authentication handler.</param>
        /// <returns>The original builder.</returns>
        public static AuthenticationBuilder AddNtlm(this AuthenticationBuilder builder, string authenticationScheme, Action<NtlmOptions> configureOptions)
            => builder.AddNtlm(authenticationScheme, displayName: null, configureOptions: configureOptions);

        /// <summary>
        /// Configures the <see cref="AuthenticationBuilder"/> to use Ntlm (also known as Windows, Kerberos, or NTLM) authentication
        /// using the specified authentication scheme.
        /// <para>
        /// This authentication handler supports Kerberos on Windows and Linux servers.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The scheme name used to identify the authentication handler internally.</param>
        /// <param name="displayName">The name displayed to users when selecting an authentication handler. The default is null to prevent this from displaying.</param>
        /// <param name="configureOptions">Allows for configuring the authentication handler.</param>
        /// <returns>The original builder.</returns>
        public static AuthenticationBuilder AddNtlm(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<NtlmOptions> configureOptions)
        {
            //builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<NtlmOptions>, PostConfigureNtlmOptions>());
            //builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IStartupFilter>(new NtlmOptionsValidationStartupFilter(authenticationScheme)));
            return builder.AddScheme<NtlmOptions, NtlmHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
