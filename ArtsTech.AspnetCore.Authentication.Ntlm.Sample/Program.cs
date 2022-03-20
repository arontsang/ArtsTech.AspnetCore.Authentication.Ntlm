using ArtsTech.AspnetCore.Authentication.Ntlm;
using ArtsTech.AspnetCore.Authentication.Ntlm.Sample;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
builder.Services.AddAuthentication(NtlmDefaults.AuthenticationScheme)
     .AddNtlm();

builder.Services.AddAuthorization();

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
