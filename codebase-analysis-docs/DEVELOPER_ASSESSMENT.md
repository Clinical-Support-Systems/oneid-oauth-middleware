# Library developer and testing assessment

Date: 2026-09-07. The owner confirms production use. Findings concern the inspected checkout; deployed version, framework and custom configuration remain unknown. This is a review, not authorization to change runtime behavior.

## Review correction (2026-09-07)

This assessment was re-checked against the source at `777d721` during a plan review. All cited evidence held. Two priorities below were ranked too low and have been re-scoped into separate P0 handoffs; the priority table in this file is kept as originally written for the record, but `IMPLEMENTATION_PLAN.md` supersedes it for execution order.

- **Priority 2's "Core seeds a symmetric signing key while validation adds JWKS keys" is a live defense-in-depth failure, not an open question.** `TokenValidationParameters.Clone()` preserves the singular `IssuerSigningKey`; `OneIdTokenValidator` sets only the plural `IssuerSigningKeys`; `GetAllSigningKeys()` returns both; no algorithm restriction exists on the Core path. The key is public (public repository, and shipped in the NuGet assembly). Exploitation still requires controlling the backchannel token response, so it is not a remote bypass — but signature validation gives no assurance by default. Now handled by task 008 (one-line removal, P0).
- **The Katana state-ordering issue breaks net48 sign-in entirely**, rather than being a correctness question to resolve with tests. `Protect` at `OneIdAuthenticationHandler.NetFull.cs:433` precedes the verifier (437) and nonce (443) writes, so the callback's guard at line 157 throws on every login. Introduced in `7285bbe`. Now handled by task 003 (one-line reorder, P0), with the net48 test project split into task 007.

Neither statement describes any deployed consumer; the deployed version, target and overrides remain unknown.

## Assessment

The library has a useful, focused purpose, conventional ASP.NET registration APIs, separation between Core and Katana handlers, certificate caching, nullable analysis, analyzers and a starting unit-test suite. It can be improved substantially without a rewrite. Its automated tests do not currently provide strong evidence for safe changes to authentication boundaries across both supported targets.

Production usage provides evidence for the paths actually deployed. It does not establish automated regression coverage for other configurations or targets.

## Priorities

| Order | Improvement | Developer benefit and evidence |
|---|---|---|
| 1 | Establish real callback and token-validation regression tests for both targets | Current test project targets net9.0, selecting Core rather than NETFULL. Full sign-in theory and creating-ticket integration facts are skipped. Sources: `tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj`, `OneIDTests.cs`, `Infrastructure/OAuthTests.cs` within that test directory. |
| 2 | Resolve default-path correctness/trust questions with targeted tests | Katana protects state before inserting nonce/verifier and uses the assertion transport for bodyless JWKS GET. Core seeds a symmetric signing key while validation adds JWKS keys; test accepted keys/algorithms explicitly. Sources: `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs`, `OneIdAuthenticationOptions.cs`, `OneIdTokenValidator.cs` within the same library directory. These observations do not establish an issue in the deployed production path. |
| 3 | Centralize endpoint resolution | Options, refresh, end-session and revoke currently construct URLs independently. Refresh ignores custom TokenEndpoint; revocation is PST-only; production Authority normalization differs from other endpoints. A single resolver reduces configuration surprises. Sources: `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs`, `src/AspNet.Security.OAuth.OneID/OneIdHelper.cs`. |
| 4 | Make public option behavior predictable | ServiceProfileOptions adds scopes without removing old service scopes. ValidateTokens does not control active validation. SaveTokens and TokenSaveOptions interact with session and inherited OAuth behavior. Deprecate misleading options with migration guidance; do not weaken validation to match their names. Sources: options, both handlers and events in `src/AspNet.Security.OAuth.OneID/`. |
| 5 | Add a typed refresh API | Return access token, rotated refresh token, ID token, type and expiration in a new result type. Keep the existing string-returning API as a compatibility wrapper. Current helper discards all but access_token. Source: `src/AspNet.Security.OAuth.OneID/OneIdHelper.cs:RefreshToken`. |
| 6 | Separate assertion creation from HTTP transport | A small assertion builder and composable transport would permit deterministic synthetic-certificate tests without reflection and real localhost connection attempts. Preserve the existing public backchannel API while changing internals. Sources: `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationBackChannelHandler.cs`, `tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationBackChannelHandlerTests.cs`. |
| 7 | Improve registration-time errors and integration examples | Validate certificate source conflicts, required profile and callback setup before the first login where possible; explain certificate lookup and private-key failures precisely. Clearly document host cookie/sign-in/session ownership. Current examples duplicate options and Kestrel stores tokens in static properties. Sources: `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs`, `src/ConsumerApp.Kestrel/Startup.cs`, `src/ConsumerApp.Kestrel/Pages/Index.cshtml.cs`. Sample issues are separate from package behavior. |
| 8 | Remove misleading/dead surfaces gradually | Examples include unused provider hooks, inactive Core context wrapper, and the empty contact-identifier helper. Public members require deprecation/compatibility treatment; private dead code can be simplified. Sources: `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationProvider.cs`, `src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticatedContext.cs`, `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetCore.cs`. |

## Test quality

Active unit tests exercise constructor arguments, option validation, scheme registration, claims mapping, actor fallback, direct ticket token saving, assertion form rewriting, and a small refresh regression. Those are useful tests, but many bypass the complete authentication lifecycle.

The signed-token validation path needs dedicated tests for success, wrong issuer/audience, expiration, missing/mismatched nonce, unsigned tokens, unexpected algorithms/keys, unavailable JWKS and key rotation. Full browser-to-callback tests should prove correlation, protected-state round trips and resulting cookie/session contents. NETFULL needs its own execution coverage.

`OneIdAuthenticationHandlerAdditionalNetCoreTests.cs` constructs unsigned synthetic JWTs and initializes handlers without normal post-configuration. Its validation-event test proves the event was called, not that a cryptographic validator rejected invalid tokens. `OneIdAuthenticationBackChannelHandlerTests.cs` attempts localhost transport and catches network failure after request mutation. Replacing that dependency with a fake transport would improve determinism.

## Coverage configuration

`tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj` references `coverlet.collector` 6.0.4. Coverage tooling is therefore installed in the project. No checked-in coverage report or runsettings was found in the initial file search. `.github/workflows/main.yml` has no explicit coverage collection argument, report publication or coverage threshold. Its test badge/report concerns test results; it is not evidence of code coverage.

Main CI only triggers on master pushes; CodeQL has a PR trigger but static analysis is not an authentication regression test. Main CI requests SDK 8.0.401; `global.json` requests 9.0.305 with patch roll-forward. CodeQL and dependency workflows request 6.0.x. Align SDK selection and add PR build/test/coverage checks separately from package publishing. Sources: `.github/workflows/main.yml`, `.github/workflows/codeql-analysis.yml`, `.github/workflows/dependencies.yml`, `global.json`.

Collect a baseline before choosing thresholds. Report line and branch coverage for the library, separately by target, and exclude only genuinely generated artifacts. A Core-only percentage must not be presented as coverage of the Framework implementation. Require important authentication scenarios even if a numerical threshold passes.

Coverage command attempted for this review:

```powershell
dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj --no-restore --collect "XPlat Code Coverage" --results-directory codebase-analysis-docs/assets/test-results --logger "trx;LogFileName=assessment.trx" -v minimal
```

Execution status: the sandboxed attempt stopped before tests because .NET could not write its first-run sentinel in the user profile. An elevated retry was requested and was awaiting approval when this assessment was written. No test pass/fail count or measured percentage is available yet. The existing test project.assets.json targets net8.0 while the current project targets net9.0, so a fresh restore is also needed before a valid baseline run. Source inspection found 31 active test-method declarations and four skipped method declarations (a theory may represent multiple cases); these are not executed test counts.

## Suggested implementation sequence

1. Identify the deployed package/framework and preserve its successful login behavior in integration tests using synthetic credentials and keys.
2. Establish repeatable Core and Framework tests and coverage reporting in PR CI.
3. Fix confirmed correctness and validation issues in small changes with regression tests.
4. Introduce endpoint resolution and typed refresh APIs compatibly.
5. Simplify options, transport internals, stale hooks and samples with migration documentation.

Decisions/Findings: Improve test confidence and API consistency incrementally; a rewrite is unnecessary.

Open Questions: Actual deployed configuration, measured coverage, current test outcome, and production impact of default-path findings.

Next Steps: Resolve test execution status and use the resulting baseline to scope the first implementation change.

