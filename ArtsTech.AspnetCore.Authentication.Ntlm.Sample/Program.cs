using ArtsTech.AspnetCore.Authentication.Ntlm;
using ArtsTech.AspnetCore.Authentication.Ntlm.Sample;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
builder.Services.AddAuthentication(NtlmDefaults.AuthenticationScheme)
     .AddNtlm();

builder.Services.AddAuthorization();
//builder.Services.AddHostedService<WinBindService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}
app.UseStaticFiles();

app.UseRouting();

 app.UseAuthentication();
 app.UseAuthorization();

app.MapRazorPages();

app.Run();
