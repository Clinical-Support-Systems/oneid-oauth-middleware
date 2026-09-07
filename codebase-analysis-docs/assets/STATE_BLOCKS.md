# Analysis phase state blocks

These checkpoints summarize the completed analysis passes. The source index is a static inventory; inclusion does not imply every byte was read.

## Phase 1 Initial context scan

```text
STATE BLOCK
INDEX_VERSION: 1 (2026-09-07; assets/file-index.json)
FILE_MAP_SUMMARY: top 50 indexed priority paths reproduced below; Library plus two consumer samples; dual-target package and net9 tests mapped.
OPEN_QUESTIONS: Which platform paths differ? What does active validation enforce?
KNOWN_RISKS: Sample versus library ownership; CI SDK mismatch.
GLOSSARY_DELTA: OneID, OAG, OLIS, DHDR, PST
NEXT_READ_QUEUE: none required for this source-analysis deliverable
```

- .github/workflows/main.yml
- global.json
- README.md
- src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj
- src/AspNet.Security.OAuth.OneID/AssemblyInfo.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationBackChannelHandler.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationClaimAction.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationConstants.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationDefaults.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEnvironment.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEvents.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationException.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetCore.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationMiddleware.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationPostConfigureOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationProvider.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthException.cs
- src/AspNet.Security.OAuth.OneID/OneIdHelper.cs
- src/AspNet.Security.OAuth.OneID/OneIdLoggerExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdTokenValidator.cs
- src/AspNet.Security.OAuth.OneID/OneIdValidateIdTokenContext.cs
- src/AspNet.Security.OAuth.OneID/PKCECode.cs
- src/AspNet.Security.OAuth.OneID/Properties/Resources.Designer.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdApplyRedirectContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatedContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatingContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticationHandlerFactory.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdReturnEndpointContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdTokenRequestContext.cs
- src/AspNet.Security.OAuth.OneID/TokenEndpoint.cs
- tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj
- tests/AspNet.Security.OAuth.OneID.Tests/bundle.json
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/ApplicationFactory.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/HttpRequestInterceptionFilter.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/LoopbackRedirectHandler.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/OAuthTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/Program.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationBackChannelHandlerTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationExtensionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerAdditionalNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDAuthenticationOptionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/TokenTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Usings.cs
- tests/AspNet.Security.OAuth.OneID.Tests/xunit.runner.json
- src/ConsumerApp.Katana/App_Start/IdentityConfig.cs

**Decisions/Findings:** Library plus two consumer samples; dual-target package and net9 tests mapped.

**Open Questions:** Which platform paths differ? What does active validation enforce?

**Next Steps:** Continue with the next analysis phase.

## Phase 2 Architecture deep dive

```text
STATE BLOCK
INDEX_VERSION: 1 (2026-09-07; assets/file-index.json)
FILE_MAP_SUMMARY: top 50 indexed priority paths reproduced below; Registration, both challenge/callback paths, assertion transport and validation mapped.
OPEN_QUESTIONS: How do tests initialize validators and cover callbacks?
KNOWN_RISKS: Katana protected-state ordering and contentless JWKS GET conflict.
GLOSSARY_DELTA: PKCE, nonce, correlation, JWKS, client assertion
NEXT_READ_QUEUE: none required for this source-analysis deliverable
```

- .github/workflows/main.yml
- global.json
- README.md
- src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj
- src/AspNet.Security.OAuth.OneID/AssemblyInfo.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationBackChannelHandler.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationClaimAction.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationConstants.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationDefaults.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEnvironment.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEvents.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationException.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetCore.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationMiddleware.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationPostConfigureOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationProvider.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthException.cs
- src/AspNet.Security.OAuth.OneID/OneIdHelper.cs
- src/AspNet.Security.OAuth.OneID/OneIdLoggerExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdTokenValidator.cs
- src/AspNet.Security.OAuth.OneID/OneIdValidateIdTokenContext.cs
- src/AspNet.Security.OAuth.OneID/PKCECode.cs
- src/AspNet.Security.OAuth.OneID/Properties/Resources.Designer.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdApplyRedirectContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatedContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatingContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticationHandlerFactory.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdReturnEndpointContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdTokenRequestContext.cs
- src/AspNet.Security.OAuth.OneID/TokenEndpoint.cs
- tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj
- tests/AspNet.Security.OAuth.OneID.Tests/bundle.json
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/ApplicationFactory.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/HttpRequestInterceptionFilter.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/LoopbackRedirectHandler.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/OAuthTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/Program.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationBackChannelHandlerTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationExtensionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerAdditionalNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDAuthenticationOptionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/TokenTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Usings.cs
- tests/AspNet.Security.OAuth.OneID.Tests/xunit.runner.json
- src/ConsumerApp.Katana/App_Start/IdentityConfig.cs

**Decisions/Findings:** Registration, both challenge/callback paths, assertion transport and validation mapped.

**Open Questions:** How do tests initialize validators and cover callbacks?

**Next Steps:** Continue with the next analysis phase.

## Phase 3 Feature catalog

```text
STATE BLOCK
INDEX_VERSION: 1 (2026-09-07; assets/file-index.json)
FILE_MAP_SUMMARY: top 50 indexed priority paths reproduced below; Profiles, claims, persistence, refresh, cleanup and local-account features cataloged.
OPEN_QUESTIONS: Which host-specific lifecycle assumptions are established by tests?
KNOWN_RISKS: Static sample token fields; scope accumulation; refresh rotation discarded.
GLOSSARY_DELTA: External cookie, Actor, service profile
NEXT_READ_QUEUE: none required for this source-analysis deliverable
```

- .github/workflows/main.yml
- global.json
- README.md
- src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj
- src/AspNet.Security.OAuth.OneID/AssemblyInfo.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationBackChannelHandler.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationClaimAction.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationConstants.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationDefaults.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEnvironment.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEvents.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationException.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetCore.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationMiddleware.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationPostConfigureOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationProvider.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthException.cs
- src/AspNet.Security.OAuth.OneID/OneIdHelper.cs
- src/AspNet.Security.OAuth.OneID/OneIdLoggerExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdTokenValidator.cs
- src/AspNet.Security.OAuth.OneID/OneIdValidateIdTokenContext.cs
- src/AspNet.Security.OAuth.OneID/PKCECode.cs
- src/AspNet.Security.OAuth.OneID/Properties/Resources.Designer.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdApplyRedirectContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatedContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatingContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticationHandlerFactory.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdReturnEndpointContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdTokenRequestContext.cs
- src/AspNet.Security.OAuth.OneID/TokenEndpoint.cs
- tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj
- tests/AspNet.Security.OAuth.OneID.Tests/bundle.json
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/ApplicationFactory.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/HttpRequestInterceptionFilter.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/LoopbackRedirectHandler.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/OAuthTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/Program.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationBackChannelHandlerTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationExtensionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerAdditionalNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDAuthenticationOptionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/TokenTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Usings.cs
- tests/AspNet.Security.OAuth.OneID.Tests/xunit.runner.json
- src/ConsumerApp.Katana/App_Start/IdentityConfig.cs

**Decisions/Findings:** Profiles, claims, persistence, refresh, cleanup and local-account features cataloged.

**Open Questions:** Which host-specific lifecycle assumptions are established by tests?

**Next Steps:** Continue with the next analysis phase.

## Phase 4 Cross-cutting concerns

```text
STATE BLOCK
INDEX_VERSION: 1 (2026-09-07; assets/file-index.json)
FILE_MAP_SUMMARY: top 50 indexed priority paths reproduced below; Security, transport caching, dead hooks, logging and build/release risks separated from confirmed behavior.
OPEN_QUESTIONS: What deployed version/framework/options are used? No production incident is inferred.
KNOWN_RISKS: Default validation key configuration; callback issuer trust; test integration gaps.
GLOSSARY_DELTA: Trust source, data protection, certificate lifecycle
NEXT_READ_QUEUE: none required for this source-analysis deliverable
```

- .github/workflows/main.yml
- global.json
- README.md
- src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj
- src/AspNet.Security.OAuth.OneID/AssemblyInfo.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationBackChannelHandler.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationClaimAction.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationConstants.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationDefaults.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEnvironment.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEvents.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationException.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetCore.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationMiddleware.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationPostConfigureOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationProvider.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthException.cs
- src/AspNet.Security.OAuth.OneID/OneIdHelper.cs
- src/AspNet.Security.OAuth.OneID/OneIdLoggerExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdTokenValidator.cs
- src/AspNet.Security.OAuth.OneID/OneIdValidateIdTokenContext.cs
- src/AspNet.Security.OAuth.OneID/PKCECode.cs
- src/AspNet.Security.OAuth.OneID/Properties/Resources.Designer.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdApplyRedirectContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatedContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatingContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticationHandlerFactory.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdReturnEndpointContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdTokenRequestContext.cs
- src/AspNet.Security.OAuth.OneID/TokenEndpoint.cs
- tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj
- tests/AspNet.Security.OAuth.OneID.Tests/bundle.json
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/ApplicationFactory.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/HttpRequestInterceptionFilter.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/LoopbackRedirectHandler.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/OAuthTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/Program.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationBackChannelHandlerTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationExtensionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerAdditionalNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDAuthenticationOptionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/TokenTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Usings.cs
- tests/AspNet.Security.OAuth.OneID.Tests/xunit.runner.json
- src/ConsumerApp.Katana/App_Start/IdentityConfig.cs

**Decisions/Findings:** Security, transport caching, dead hooks, logging and build/release risks separated from confirmed behavior.

**Open Questions:** What deployed version/framework/options are used? No production incident is inferred.

**Next Steps:** Continue with the next analysis phase.

## Phase 5 Technical reference

```text
STATE BLOCK
INDEX_VERSION: 1 (2026-09-07; assets/file-index.json)
FILE_MAP_SUMMARY: top 50 indexed priority paths reproduced below; Public surface, wire DTO, Identity schema, test map and glossary assembled.
OPEN_QUESTIONS: Live provider contract and runtime status remain unverified.
KNOWN_RISKS: Different EF stacks; do not transfer migrations or assume storage parity.
GLOSSARY_DELTA: Authentication ticket, token DTO, Identity login link
NEXT_READ_QUEUE: none required for this source-analysis deliverable
```

- .github/workflows/main.yml
- global.json
- README.md
- src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj
- src/AspNet.Security.OAuth.OneID/AssemblyInfo.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationBackChannelHandler.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationClaimAction.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationConstants.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationDefaults.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEnvironment.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEvents.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationException.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetCore.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationMiddleware.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationPostConfigureOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationProvider.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthException.cs
- src/AspNet.Security.OAuth.OneID/OneIdHelper.cs
- src/AspNet.Security.OAuth.OneID/OneIdLoggerExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdTokenValidator.cs
- src/AspNet.Security.OAuth.OneID/OneIdValidateIdTokenContext.cs
- src/AspNet.Security.OAuth.OneID/PKCECode.cs
- src/AspNet.Security.OAuth.OneID/Properties/Resources.Designer.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdApplyRedirectContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatedContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatingContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticationHandlerFactory.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdReturnEndpointContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdTokenRequestContext.cs
- src/AspNet.Security.OAuth.OneID/TokenEndpoint.cs
- tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj
- tests/AspNet.Security.OAuth.OneID.Tests/bundle.json
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/ApplicationFactory.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/HttpRequestInterceptionFilter.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/LoopbackRedirectHandler.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/OAuthTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/Program.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationBackChannelHandlerTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationExtensionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerAdditionalNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDAuthenticationOptionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/TokenTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Usings.cs
- tests/AspNet.Security.OAuth.OneID.Tests/xunit.runner.json
- src/ConsumerApp.Katana/App_Start/IdentityConfig.cs

**Decisions/Findings:** Public surface, wire DTO, Identity schema, test map and glossary assembled.

**Open Questions:** Live provider contract and runtime status remain unverified.

**Next Steps:** Continue with the next analysis phase.

## Phase 6 Final assembly

```text
STATE BLOCK
INDEX_VERSION: 1 (2026-09-07; assets/file-index.json)
FILE_MAP_SUMMARY: top 50 indexed priority paths reproduced below; Master document saved; production use recorded as user-confirmed; source anchors and documentation hygiene checked.
OPEN_QUESTIONS: Deployed artifact/framework/configuration, live endpoints and current tests remain outside scope.
KNOWN_RISKS: Static findings concern this checkout/default paths, not proof of production impact.
GLOSSARY_DELTA: No new terms
NEXT_READ_QUEUE: none required for this source-analysis deliverable
```

- .github/workflows/main.yml
- global.json
- README.md
- src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj
- src/AspNet.Security.OAuth.OneID/AssemblyInfo.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationBackChannelHandler.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationClaimAction.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationConstants.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationDefaults.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEnvironment.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEvents.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationException.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetCore.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationMiddleware.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationPostConfigureOptions.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationProvider.cs
- src/AspNet.Security.OAuth.OneID/OneIdAuthException.cs
- src/AspNet.Security.OAuth.OneID/OneIdHelper.cs
- src/AspNet.Security.OAuth.OneID/OneIdLoggerExtensions.cs
- src/AspNet.Security.OAuth.OneID/OneIdTokenValidator.cs
- src/AspNet.Security.OAuth.OneID/OneIdValidateIdTokenContext.cs
- src/AspNet.Security.OAuth.OneID/PKCECode.cs
- src/AspNet.Security.OAuth.OneID/Properties/Resources.Designer.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdApplyRedirectContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatedContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatingContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticationHandlerFactory.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdReturnEndpointContext.cs
- src/AspNet.Security.OAuth.OneID/Provider/OneIdTokenRequestContext.cs
- src/AspNet.Security.OAuth.OneID/TokenEndpoint.cs
- tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj
- tests/AspNet.Security.OAuth.OneID.Tests/bundle.json
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/ApplicationFactory.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/HttpRequestInterceptionFilter.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/LoopbackRedirectHandler.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/OAuthTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/Program.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationBackChannelHandlerTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationExtensionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerAdditionalNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerNetCoreTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDAuthenticationOptionsTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/OneIDTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/TokenTests.cs
- tests/AspNet.Security.OAuth.OneID.Tests/Usings.cs
- tests/AspNet.Security.OAuth.OneID.Tests/xunit.runner.json
- src/ConsumerApp.Katana/App_Start/IdentityConfig.cs

**Decisions/Findings:** Master document saved; production use recorded as user-confirmed; source anchors and documentation hygiene checked.

**Open Questions:** Deployed artifact/framework/configuration, live endpoints and current tests remain outside scope.

**Next Steps:** Use the master document for subsequent scoped implementation work.

