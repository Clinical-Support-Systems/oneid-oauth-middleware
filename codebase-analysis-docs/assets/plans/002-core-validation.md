# Task 002 — Test the default Core validator and remove unsafe test accommodations

## Status and objective

TODO; P1; medium effort; high change risk; security/tests. Planned at `777d721`, 2026-09-07; re-scoped 2026-09-07 after plan review. Prerequisite: **task 008** (removal of the seeded symmetric signing key) has landed and the existing Core suite passes. Task 001 is not a gate. Produce real signed-token regression tests and make the default validation event report a missing validator.

The seeded-signing-key removal that was previously step 3 of this task now lives in `008-remove-seeded-signing-key.md` so it can ship on its own. Do not redo it here; verify it is done (`OneIdAuthenticationOptions.TokenValidationParameters.IssuerSigningKey` is null by default) and build on it.

Production use is confirmed, but deployed configuration is unknown. Preserve public signatures and supported consumer-supplied validation customization. Do not change endpoints, add an unverified universal algorithm policy or replace OAuthHandler.

## Evidence and test approach

`src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEvents.cs:52–53`:

```csharp
var validator = context.Options.TokenValidator;
return validator is not null ? validator.ValidateAsync(context) : Task.CompletedTask;
```

`src/AspNet.Security.OAuth.OneID/OneIdTokenValidator.cs:135–139`:

```csharp
var validationParameters = context.Options.TokenValidationParameters.Clone();
// After the nonempty-JWKS check:
validationParameters.IssuerSigningKeys = configuration.JsonWebKeySet.Keys;
```

Note that `Clone()` copies the singular `IssuerSigningKey` as well, and the block above sets only the plural `IssuerSigningKeys` — that is why task 008 exists. Confirm 008 landed before you start; if `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs:112` still assigns a `SymmetricSecurityKey`, stop and run task 008 first. Never copy that literal into documentation, fixtures or reports. `OneIdAuthenticationPostConfigureOptions.PostConfigure` normally installs the default validator and parser. It is accessible for tests through resolved `IOptionsMonitor<OneIdAuthenticationOptions>.Get("OneID").TokenValidator`; no reflection or InternalsVisibleTo change is necessary.

`tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerAdditionalNetCoreTests.cs:54–60` constructs JWTs with alg none and calls ticket methods directly. Keep claim parsing tests, but explicitly inject a test-only no-op IOneIdTokenValidator there when validation is not under test. Never reintroduce a production null-validator bypass to support those tests.

Conventions: block-scoped C# namespaces, nullable enabled, xUnit [Fact]/[Theory], synthetic inputs and fake HTTP handlers as used in the existing additional handler test class. Library warnings are errors. Shared edits must compile for net48 and net8.0.

## Scope

- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEvents.cs`.
- `tests/AspNet.Security.OAuth.OneID.Tests/OneIdTokenValidatorTests.cs` (new).
- `tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/SyntheticOneIdTokens.cs` (new).
- `tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerAdditionalNetCoreTests.cs`: explicit test validator setup only.
- `README.md`: explain missing-validator failure/default trust setup.
- Task/index status and test reports under `codebase-analysis-docs/assets/test-results/`.

Out of scope: Framework validation, changing DefaultOneIdTokenValidator's discovery/retry logic, forcibly clearing caller-provided signing keys, changing public ValidateTokens behavior, authentication algorithm restrictions, any real certificate/token, unrelated test rewrites or package upgrades.

## Drift/Git gate

`git status --short` and `git diff --stat 777d721..HEAD -- src/AspNet.Security.OAuth.OneID tests/AspNet.Security.OAuth.OneID.Tests README.md` → account for task 008's one-line removal and any intentional user changes. Compare evidence before editing. Never push/publish/reset or overwrite user changes.

## Steps and gates

1. Create a disposable synthetic RSA key and signed JWT helper. Generate issuer, audience, subject, nonce, nbf and exp; choose expiration comfortably beyond clock skew for valid cases and well beyond it in the past for expiry failures. Build a static OpenIdConnectConfiguration with trusted Issuer and matching public JWKS, inject a static configuration manager, register AddOneId with valid dummy options and obtain its installed validator through resolved options. Gate: `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj --filter FullyQualifiedName~OneIdTokenValidatorTests` → a valid RS256 token with matching nonce passes without network/store access.
2. Add independent negative cases: wrong audience, wrong issuer, expired token, not-yet-valid token, absent expected nonce, missing token nonce, mismatched nonce, unsigned JWT, wrong RSA signing key, missing discovery issuer, empty key set with a fake JWKS response. Use trusted configuration with an empty JWKS object to avoid accidental fallback HTTP except in the one deliberately faked fallback case. Also prove configured custom IOneIdTokenValidator is honored by the default event. Gate: same filter → tests for existing guarantees pass; any unexpected security acceptance is reported before adding unrelated fixes.
3. Add regression `ValidateIdToken_ThrowsWhenValidatorMissing` expecting InvalidOperationException naming TokenValidator. Run the filter and record that failure before changing anything. Then change the default event (`OneIdAuthenticationEvents.cs:51-53`) to throw the named configuration error when the validator is absent, instead of returning `Task.CompletedTask`. Note the existing comment there claims the silent skip exists "to avoid NREs in unit tests" — that is the accommodation this step removes; the tests it protected are fixed in step 4, not preserved. Preserve caller-supplied keys and custom validator/event overrides; this plan improves defaults, not the entire customization trust contract. Gate: same filter → the new regression passes; the valid signed-token case from step 1 still passes.
4. Add a default-options test rejecting a JWT signed with a synthetic symmetric key not advertised by JWKS; no hardcoded repository key is required. Add a test that caller-provided TokenValidationParameters are not mutated during validation. Existing claim-only handler tests must explicitly configure a test fake validator so their intent is visible. Preserve `CreateTicketAsync_RunsValidation_When_ValidateTokens_Is_False`. Gate: `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj` → all active tests pass; no additional skip added.
5. Run `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release` and run a coverage pass once for the changed test suite (`dotnet test <test csproj> --collect "XPlat Code Coverage" --results-directory codebase-analysis-docs/assets/test-results/task-002`; task 001 owns the CI wiring, but you do not need it to run this locally). Expected: both target builds succeed; default validator ValidateAsync has measured execution, not merely constructor coverage. Record class/method coverage and executed scenario names.

## Acceptance checklist

- [ ] Task 008's removal is verified still in place; supplied custom key settings are not silently removed.
- [ ] Missing validator throws in default event; normal AddOneId path validates successfully.
- [ ] Signed-token positive and all listed negative cases execute without live services.
- [ ] Existing event-dispatch regression with ValidateTokens=false still passes.
- [ ] No production bypass, additional skip, signature-check suppression or universal algorithm policy introduced.
- [ ] Full Core suite and dual-target Release build exit 0; diff is scoped and clean.

## Stop conditions and review notes

Stop if default valid-token validation cannot be exercised through normal DI, existing callers/tests require unspecified compatibility changes, or unrelated validation gaps require editing out-of-scope validator logic. Do not force a pass by disabling lifetime, issuer, audience or signature checks. Reviewer must scrutinize test fake placement and default-versus-custom trust semantics. Provider algorithm policy and key-refresh retry remain task 006 decisions.
