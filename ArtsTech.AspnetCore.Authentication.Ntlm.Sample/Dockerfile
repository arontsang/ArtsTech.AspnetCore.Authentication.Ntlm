# syntax=docker/dockerfile:1.3-labs
#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0-focal AS base

ENV DEBIAN_FRONTEND noninteractive

RUN set -x && \
    apt-get -y update && \
    apt-get -y --no-install-recommends install \
        winbind \
        samba* smbclient libpam-winbind libnss-winbind krb5-kdc libpam-krb5 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#RUN rm /etc/samba/smb.conf && \
#    samba-tool domain provision --server-role=dc --use-rfc2307 --dns-backend=SAMBA_INTERNAL --realm=SAMDOM.EXAMPLE.COM --domain=SAMDOM --adminpass=Passw0rd


WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["ArtsTech.AspnetCore.Authentication.Ntlm/", "ArtsTech.AspnetCore.Authentication.Ntlm.Sample/"]
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