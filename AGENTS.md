# Project guidance

## Project map

- `src/AspNet.Security.OAuth.OneID/` is the published Ontario Health OneID OAuth/OIDC middleware. It targets `net48` (OWIN/Katana, `NETFULL`) and `net8.0` (ASP.NET Core, `NETCORE`). Preserve both targets when changing shared code; platform handlers are in `OneIdAuthenticationHandler.NetFull.cs` and `OneIdAuthenticationHandler.NetCore.cs`.
- `src/ConsumerApp.Katana/` and `src/ConsumerApp.Kestrel/` are consumer examples.
- `tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj` is the xUnit test project; it targets `net9.0`. HTTP test infrastructure uses interception and `bundle.json` fixtures.
- `README.md` covers integration and contribution policy. `tutorial/index.md` routes to component documentation; consult the relevant component when needed.

## Build and compatibility

- Use the SDK selection in `global.json`. Project files define target frameworks; the SDK version and library targets are different.
- Library build: `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release`.
- Test command: `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj`. Add `--filter` for an affected test class or behavior. These are command references, not a checklist for every edit.
- Follow `.editorconfig` and the project analyzer settings. The library enables nullable analysis and treats warnings as errors.
- Keep the `Microsoft.IdentityModel.*` and `System.IdentityModel.*` dependency versions aligned, as required by the README. Package versioning uses Nerdbank.GitVersioning and `version.json`.

## Authentication boundaries

- Keep credentials, private certificate material, and live access/refresh tokens out of source, test fixtures, and logs. Live Ontario Health integration requires provisioned credentials and a PKI certificate; use synthetic data for automated tests.
- Preserve authentication validation and environment separation when modifying token, certificate, endpoint, or backchannel behavior.

## Contributions and releases

- The README identifies `develop` as the development branch and `master` as production, directs PRs to `master`, and prohibits additional branches in the main remote repository. Local working branches do not create remote branches.
- PRs require passing CI checks and positive reviews. `.github/workflows/main.yml` publishes NuGet packages on pushes to `master`; such pushes have release side effects.
