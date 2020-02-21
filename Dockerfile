FROM mcr.microsoft.com/dotnet/core/sdk:3.1-nanoserver-1903 AS build
WORKDIR /src
COPY ["RijndaelFileEncryption.csproj", "./"]
RUN dotnet restore "./RijndaelFileEncryption.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "RijndaelFileEncryption.csproj" -c Release -o /app/build
RUN dotnet publish "RijndaelFileEncryption.csproj" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/core/runtime:3.1-nanoserver-1903 AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["RijndaelFileEncryption.exe"]