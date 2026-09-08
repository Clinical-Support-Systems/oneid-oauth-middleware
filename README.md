# Ontario Health (OH) OneID Authentication Middleware

- An easy to use library that makes connecting with [Ontario Health](https://www.ontariohealth.ca/) easy for .NET Kestrel/Owin/Katana applications.

 [![CI](https://github.com/Clinical-Support-Systems/oneid-oauth-middleware/actions/workflows/main.yml/badge.svg?branch=master)](https://github.com/Clinical-Support-Systems/oneid-oauth-middleware/actions/workflows/main.yml) [![Nuget](https://img.shields.io/nuget/v/AspNet.Security.OAuth.OneID)](https://www.nuget.org/packages/AspNet.Security.OAuth.OneID) [![Nuget](https://img.shields.io/nuget/dt/AspNet.Security.OAuth.OneID)](#) [![Tests](https://gist.githubusercontent.com/kfrancis/65229774df094982ad195fe336f6b4c2/raw/63321843226df7596eed98e96391eedc8cb02c14/oneid_middleware_tests.md_badge.svg)](https://gist.github.com/kfrancis/65229774df094982ad195fe336f6b4c2)

[About](#beginner-about) | [Usage](#sunny-usage) | [Development](#wrench-development) | [Gallery](#camera-gallery) | [Acknowledgement](#star2-creditacknowledgment) | [License](#lock-license)

---

# :beginner: About
This library was created by Clinical Support Systems and Kori Francis, who have experience integrating with APIs of varying complexity. We wanted to simplify the connection in .NET web applications so we could get on with the actual API implementation.

## Documentation

Check out our [detailed tutorial](./tutorial/index.md) for implementation guides and examples.

Additional documentation:
- [Authentication Options](./tutorial/01_oneidauthenticationoptions_.md)
- [Environment Settings](./tutorial/02_oneidauthenticationenvironment_.md)
- [Extension Methods](./tutorial/03_oneidauthenticationextensions_.md)
- [Authentication Handler](./tutorial/04_oneidauthenticationhandler_.md)
- [Back Channel Handling](./tutorial/05_oneidauthenticationbackchannelhandler_.md)
- [Helper Functions](./tutorial/06_oneidhelper_.md)

## :tada: Supported Ontario Health (OH) Services

To make integration simple, there's support in this middlewear to adjust the scope and profile depending on the service you're integrating with. As such, we currently support the following:

- :heavy_check_mark: [OLIS](https://ehealthontario.on.ca/en/standards/ontario-laboratories-information-system-standard)
- :heavy_check_mark: [DHDR](https://ehealthontario.on.ca/en/standards/digital-health-drug-repository-specification-fhir)
- :x: [DHIR](https://ehealthontario.on.ca/en/standards/digital-health-immunization-repository-consumer-access-specification-fhir)

This will allow you to perform authentication once but retrieve an `access_token` that can access multiple services.

## Supported oAuth/OIDC Features

- :heavy_check_mark: Authenticate    
- :heavy_check_mark: Discovery   
- :heavy_check_mark: User Info   
- :heavy_check_mark: Validation (use JSON Web Key Set)
- :heavy_check_mark: Manual refresh
- :x: End Session
- :x: Logout

# :sunny: Usage
Here is how to use this library in your project.

##  :electric_plug: NuGet Installation

```powershell
Install-Package AspNet.Security.OAuth.OneID
```

###  :package: Startup.cs

Add the following to your authentication pipeline:

**OWIN/Katana (ASP.NET)**
```c#
app.UseOneIdAuthentication(new OneIdAuthenticationOptions()
    {
        CertificateThumbprint = ConfigurationManager.AppSettings["EHS:CertificateThumbprint"],
        ClientId = ConfigurationManager.AppSettings["EHS:AuthClientId"],
        Environment = OneIdAuthenticationEnvironment.PartnerSelfTest
    });
```

**Kestrel (ASP.NET Core)**
```c#
services.AddAuthentication().AddOneId(options =>
    {
        options.ClientId = Configuration["EHS:AuthClientId"];
        options.CertificateThumbprint = Configuration["EHS:CertificateThumbprint"];
        options.Environment = OneIdAuthenticationEnvironment.PartnerSelfTest;
    });
```

In the case of multiple service usage, simply specify that in the authentication options:
```c#
services.AddAuthentication().AddOneId(OneIdAuthenticationDefaults.AuthenticationScheme, (OneIdAuthenticationOptions options) =>
    {
        // ...
        options.ServiceProfileOptions = OneIdAuthenticationServiceProfiles.OLIS | OneIdAuthenticationServiceProfiles.DHDR;
    });
```

### :lock: ID token validation

For the Core (`net8.0`) handler, `AddOneId` installs a default `IOneIdTokenValidator` that validates the OneID ID token's signature, issuer, audience, lifetime and nonce against the signing keys published by OneID's own discovery/JWKS endpoint - the library does not ship or trust any pre-seeded signing key, so a token can only validate against keys OneID itself currently publishes.

If `OneIdAuthenticationOptions.TokenValidator` is ever `null` when a token needs to be validated (for example, a hand-built `OneIdAuthenticationOptions` instance that bypassed `AddOneId`/`PostConfigure`), the default `OneIdAuthenticationEvents.ValidateIdToken` throws an `InvalidOperationException` naming `TokenValidator` rather than silently skipping validation. To customize or replace validation, provide your own `IOneIdTokenValidator` via `options.TokenValidator`, or override `ValidateIdToken` on a custom `OneIdAuthenticationEvents` subclass - both are honored in place of the default.

#  :wrench: Development
If you want other people to contribute to this project, this is the section, make sure you always add this.

## :notebook: Pre-Requisites

List all the pre-requisites the system needs to develop this project.

- You will need a PKI certificate from Ontario Health (OH)
- You will need login credentials from Ontario Health (OH)

## Running the tests

There are two test projects, because the library ships two implementations behind `net48`/`net8.0`:

```powershell
# Core (net8.0) handler - ASP.NET Core / Kestrel
dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj

# Framework (net48) handler - OWIN / Katana; Windows-only
dotnet test tests/AspNet.Security.OAuth.OneID.NetFull.Tests/AspNet.Security.OAuth.OneID.NetFull.Tests.csproj
```

The `net48` project is the only execution coverage for `OneIdAuthenticationHandler.NetFull.cs` (the OWIN/Katana handler) - the Core test project resolves the library's `net8.0` assets and never runs that code path. It uses an in-memory `Microsoft.Owin.Testing.TestServer`, so it needs no live OneID credentials, certificate, or network access.

## IdentityModel Package Version Consistency

Run this command:

```powershell
dotnet list package --include-transitive | sls "Microsoft.IdentityModel|System.IdentityModel"
```

If there are differences in the versions of the output, make sure to update those packages to all the same version. This is how the models and clients are kept in sync.

See [this](https://docs.duendesoftware.com/identityserver/v7/troubleshooting/wilson/) for more info.

 ###  :fire: Contribution

 Your contributions are always welcome and appreciated. Following are the things you can do to contribute to this project.

 1. **Report a bug** <br>
 If you think you have encountered a bug, and I should know about it, feel free to report it and I will take care of it.

 2. **Request a feature** <br>
 You can also request for a feature.

 3. **Create a pull request** <br>
 It can't get better then this, your pull request will be appreciated by the community. You can get started by picking up any open issues from [here](https://github.com/Clinical-Support-Systems/oneid-oauth-middleware/issues) and make a pull request.

 > If you are new to open-source, make sure to check read more about it [here](https://www.digitalocean.com/community/tutorial_series/an-introduction-to-open-source) and learn more about creating a pull request [here](https://www.digitalocean.com/community/tutorials/how-to-create-a-pull-request-on-github).


 ### :cactus: Branches

 I use an agile continuous integration methodology, so the version is frequently updated and development is really fast.

1. **`develop`** is the development branch.

2. **`master`** is the production branch.

4. No further branches should be created in the main repository.

**Steps to create a pull request**

1. Make a PR to `master` branch.
2. Comply with the best practices and guidelines e.g. where the PR concerns visual elements it should have an image showing the effect.
3. It must pass all continuous integration checks and get positive reviews.

After this, changes will be merged.

#  :camera: Gallery

![OneId Authentication](https://raw.githubusercontent.com/Clinical-Support-Systems/oneid-oauth-middleware/master/oneid.gif)

# :star2: Credit/Acknowledgment
 * Kori Francis
 * David Ball
 * Alex McKeever
 * Victoria Tolls

#  :lock: License

[License](https://raw.githubusercontent.com/Clinical-Support-Systems/oneid-oauth-middleware/master/LICENSE)

https://login.oneidfederation.ehealthontario.ca/sso/oauth2/realms/root/realms/idaasoidc/.well-known/openid-configuration
