# Night Tech Sentinel server. Build from the repository root:
#   docker build -f src/NightTech.Sentinel.Server/Dockerfile -t nighttech-sentinel .
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY src/NightTech.Business.Core/ src/NightTech.Business.Core/
COPY src/NightTech.Sentinel.Server/ src/NightTech.Sentinel.Server/
RUN dotnet publish src/NightTech.Sentinel.Server/NightTech.Sentinel.Server.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_URLS=http://0.0.0.0:8080 SENTINEL_DATA=/data
RUN mkdir -p /data && chown app:app /data
USER app
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["dotnet", "NightTechSentinelServer.dll"]
