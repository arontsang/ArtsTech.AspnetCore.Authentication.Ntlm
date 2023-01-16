FROM mcr.microsoft.com/dotnet/aspnet:6.0-alpine3.17 AS base
WORKDIR /app
RUN apk add --update --no-cache samba-dc=4.16.8-r0 samba-winbind-clients=4.16.8-r0 krb5 

RUN rm /etc/samba/smb.conf
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["ArtsTech.AspnetCore.Authentication.Ntlm.Sample/ArtsTech.AspnetCore.Authentication.Ntlm.Sample.csproj", "ArtsTech.AspnetCore.Authentication.Ntlm.Sample/"]
COPY ["ArtsTech.AspnetCore.Authentication.Ntlm/ArtsTech.AspnetCore.Authentication.Ntlm.csproj", "ArtsTech.AspnetCore.Authentication.Ntlm/"]
COPY ["ArtsTech.Ntlm.FakeSquidHelper/ArtsTech.Ntlm.FakeSquidHelper.csproj", "ArtsTech.Ntlm.FakeSquidHelper/"]
RUN dotnet restore "ArtsTech.AspnetCore.Authentication.Ntlm.Sample/ArtsTech.AspnetCore.Authentication.Ntlm.Sample.csproj"
COPY . .
WORKDIR "/src/ArtsTech.AspnetCore.Authentication.Ntlm.Sample"
RUN dotnet build "ArtsTech.AspnetCore.Authentication.Ntlm.Sample.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "ArtsTech.AspnetCore.Authentication.Ntlm.Sample.csproj" -c Release -o /app/publish 

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "ArtsTech.AspnetCore.Authentication.Ntlm.Sample.dll"]
