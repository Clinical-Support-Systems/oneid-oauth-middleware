# Task 005 — Add a complete refresh result without breaking the existing helper

## Status and objective

TODO; P2; medium effort; medium risk; additive API/DX. Planned at `777d721`, 2026-09-07. Depends on task 007 (the net48 test project) for its Framework tests. Task 001 is not a gate; a green `dotnet test` on the existing Core suite is sufficient. Add `RefreshTokensAsync` and a result DTO so callers can receive refresh-token rotation and expiry information. Preserve the current `RefreshToken` signature, endpoint selection, return behavior and exceptions.

## Evidence and explicit design

`src/AspNet.Security.OAuth.OneID/OneIdHelper.cs:136` exposes:

```csharp
public static async Task<string> RefreshToken(HttpClient client, OneIdAuthenticationOptions options, string refreshToken, CancellationToken ct = default)
```

At lines 187–196 success deserializes a JObject and returns only access_token or empty string; failure throws OneIdAuthException with URI/status/body. Environment-based endpoint construction is separate from Options.TokenEndpoint. That existing behavior remains in this task; task 006 resolves endpoint semantics separately.

Add public sealed `OneIdRefreshTokenResult` in the library namespace with get-only properties and an internal constructor:

- `string AccessToken` (empty when omitted/null).
- `string? RefreshToken`, `string? IdToken`, `string? TokenType`, `string? Scope` (null when omitted/null; do not fabricate fallback values).
- `long? ExpiresIn` (seconds, null when absent/null; accept numeric JSON and numeric strings supported by existing JSON conversion; malformed numeric value throws rather than inventing an expiry).

Add `Task<OneIdRefreshTokenResult> OneIdHelper.RefreshTokensAsync(HttpClient client, OneIdAuthenticationOptions options, string refreshToken, CancellationToken ct = default)`. It performs the existing refresh request. Existing RefreshToken becomes an async compatibility wrapper returning the result's AccessToken. A caller must retain its previous refresh token if the result omits one; neither method persists anything. Do not add automatic retries, cookie writes, logging of values or a clock-dependent ExpiresAt property.

Keep current Newtonsoft.Json/JObject use in this helper on both targets. Do not reuse ASP.NET Core's `OAuthTokenResponse` as the result type: it is Core-only (unavailable on the net48 target) and its `ExpiresIn`/property defaults cannot distinguish an absent expiration from a returned zero. Define the new DTO in this library instead. Match existing cancellation and OneIdAuthException behavior. Do not log or put tokens in ToString overrides.

## Scope

- `src/AspNet.Security.OAuth.OneID/OneIdHelper.cs`: refresh method extraction/wrapper only.
- `src/AspNet.Security.OAuth.OneID/OneIdRefreshTokenResult.cs` (new).
- `tests/AspNet.Security.OAuth.OneID.Tests/OneIdRefreshTokenTests.cs` (new).
- `tests/AspNet.Security.OAuth.OneID.NetFull.Tests/OneIdRefreshTokenTests.cs` (new; equivalent small contract tests, no Core APIs).
- `README.md`: additive API example and rotation/storage responsibility.
- Task/index status and `codebase-analysis-docs/assets/test-results/` evidence.

Out of scope: logout/revoke, endpoint changes, automatic refresh/session persistence, TokenEndpoint DTO changes, samples, certificate handler refactor, public method removals or deprecations.

## Drift/Git gate

`git status --short`; `git diff --stat 777d721..HEAD -- src/AspNet.Security.OAuth.OneID/OneIdHelper.cs tests README.md`. Verify current method still matches the described success/error behavior. No staging, commit, push or release.

## Steps and gates

1. Add a fake HttpMessageHandler that captures URI, form fields, cancellation and invocation count, returns synthetic JSON/status, and makes no real network requests. Follow `FakeRefreshHandler` in `tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerAdditionalNetCoreTests.cs`, but assert payload as well. Characterize existing RefreshToken for all four environments, success, absent access token, JSON null, non-success status and invalid arguments. Gate: `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj --filter FullyQualifiedName~OneIdRefreshTokenTests` → baseline characterization passes. Record exact exception contracts before extraction.
2. Add the DTO and new method with extraction of all fields. Keep old input checks and request construction in the new method; old method delegates once. For root JSON null, preserve old wrapper empty-string result by producing an empty result; malformed JSON continues to throw. Gate: `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release` → both targets compile without warnings/errors; same old-method tests pass.
3. Add new-method tests for all returned fields, rotated refresh token, omitted/null optional fields, numeric and numeric-string expires_in, zero expiration versus missing expiration, malformed JSON/expiry and canceled request. Assert one HTTP send, correct form grant_type/refresh_token/client_id and unchanged options.ValidateTokens. Do not test client-assertion contents here; the caller-supplied transport owns assertion signing. Gate: the Core filter above exits 0.
4. Add equivalent Framework tests for full result, omitted rotation, old wrapper equivalence, URI/form contract, exception properties and cancellation. Gate: `dotnet test tests/AspNet.Security.OAuth.OneID.NetFull.Tests/AspNet.Security.OAuth.OneID.NetFull.Tests.csproj --filter FullyQualifiedName~OneIdRefreshTokenTests` → all pass with no network/store access.
5. Document explicit caller logic: use new access token; replace saved refresh token only when returned; process ExpiresIn if supplied; persist per user; signing HttpClient remains caller-provided. Run both complete suites, dual-target Release build and `git diff --check` → all exit 0. Verify old and new methods produce the same access token and same single request for the same response.

## Acceptance checklist

- [ ] Existing public method remains source/binary compatible in signature and behavior.
- [ ] New result exposes rotation and distinguishes missing expiry from zero.
- [ ] Both targets pass old-wrapper and new-result tests.
- [ ] Error URI/status/body and cancellation behavior remain equivalent.
- [ ] No endpoints, session, cookies, tokens in logs or credential fixtures changed.
- [ ] Full tests/build pass and documentation uses only synthetic placeholder values.

## Stop conditions and maintenance

Stop if current JSON conversion behavior differs from assumptions, extraction changes existing exception/endpoint contracts, or a public constructor/new dependency is required to satisfy an unstated consumer scenario. Do not repair revocation or endpoint duplication opportunistically. Future endpoint consolidation must keep wrapper/new method behavior aligned and deliberately announce any compatibility change.
