# Task 003 — Fix Katana challenge state serialization (PKCE verifier and nonce are lost)

## Status and objective

TODO; **P0**; small effort; low change risk; correctness. Planned at `777d721`, 2026-09-07; re-scoped 2026-09-07 after plan review. No prerequisites.

Move a single statement in the net48 (Katana/OWIN) challenge so that the PKCE code verifier and the nonce are inside the protected state that gets sent to the provider. Nothing else.

The net48 test project that was bundled into this task now lives in `007-netfull-test-project.md`. That split is deliberate — see "Why this ships before its test" below.

## The defect

`src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs`, in `ApplyResponseChallengeAsync` (the block beginning around line 424):

```csharp
// OAuth2 10.12 CSRF
GenerateCorrelationId(properties);

string scope = string.Join(" ", Options.Scope);

string state = Options.StateDataFormat!.Protect(properties);          // line 433

// Generate per-request PKCE verifier/challenge and persist verifier in protected state.
var pkceCode = PkceCode.GeneratePKCECodes();
properties.Dictionary[PkceCodeVerifierProperty] = pkceCode.CodeVerifier ?? string.Empty;   // line 437

// Add nonce
var nonceBytes = new byte[32];
CryptoRandom.GetBytes(nonceBytes);
var nonce = TextEncodings.Base64Url.Encode(nonceBytes);
properties.Dictionary[NonceProperty] = nonce;                          // line 443
```

`Protect` serializes `properties` to a string at the moment it is called. Mutating `properties.Dictionary` afterwards changes the in-memory object, which is then discarded — it cannot change the `state` string already built at line 433 and placed into the authorization redirect at line 451.

The callback reads both values back out of the round-tripped state:

- `NetFull.cs:157` — `properties.Dictionary.TryGetValue(PkceCodeVerifierProperty, out var codeVerifier);` and three lines later throws `InvalidOperationException("PKCE code_verifier is missing from authentication state.")` when it is empty.
- `NetFull.cs:204` — `properties.Dictionary.TryGetValue(NonceProperty, out var expectedNonce);` feeding `ValidateIdTokenAsync`.

The verifier is therefore **never** present at the callback, and every net48 sign-in fails at that throw. The comment on line 436 states the intended behavior ("persist verifier in protected state"); the code does not implement it.

Introduced in commit `7285bbe` ("OneID: cert caching, nonce/PKCE, token validation"), the most recent commit touching this file. Treat the net48 target as currently non-functional for sign-in, not as subtly degraded.

**Scope of the claim:** this is a defect in this checkout. It does not establish what any deployed consumer is running — a consumer on an earlier package version, or on the net8.0 target, is unaffected by this line.

## Conventions

Block-scoped (braced) namespaces, nullable enabled, warnings-as-errors. This file compiles for `net48` only (it is guarded by `NETFULL`), so do not introduce APIs unavailable there. Do not reformat surrounding code.

## Scope

May edit:

- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs` — **the position of the `Protect` call and nothing else.**
- This task's status line and `codebase-analysis-docs/IMPLEMENTATION_PLAN.md`.

Explicitly out of scope: the callback's host/`localhost` regex near line 145, `GenerateCorrelationId` placement, correlation cookie handling, the JWKS discovery at line 542, the `ValidateIssuer = !string.IsNullOrWhiteSpace(callbackIssuer)` decision at line 560 (task 006 owns that), the Core handler, the backchannel handler, options, samples, packages, CI, and creating any test project (task 007).

Do not "also fix" anything else you notice in this file. Report it instead.

## Drift gate

`git status --short`, then `git diff --stat 777d721..HEAD -- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs`.

If the `Protect` call is already positioned after the nonce assignment, **STOP and report** — the fix is already in. No push, commit, stage, stash, reset or publish.

## Steps and gates

1. Move the single line `string state = Options.StateDataFormat!.Protect(properties);` from its current position to immediately **after** the `properties.Dictionary[NonceProperty] = nonce;` assignment and **before** the `explicitParameters` dictionary is constructed.

   Leave in place and in order: `GenerateCorrelationId(properties)` first (it must still run before `Protect`, since the correlation value also has to survive the round trip), then the `scope` computation, then PKCE generation, then nonce generation, then `Protect`.

   Do not change `PkceCode.GeneratePKCECodes()`, the `S256` method, the dictionary keys, the `Uri.EscapeDataString` calls, the audience/profile parameters, or `properties.RedirectUri`.

2. Gate: `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release` → exit 0, both `net48` and `net8.0` outputs, no warnings (warnings are errors).

3. Gate: `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj` → exits 0 unchanged. This is the Core suite; it does not exercise this file, so it proves only that you broke nothing. Say so in your report rather than presenting it as verification of the fix.

4. Gate: `git diff -- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs` → the diff is one line moved, nothing else. `git diff --check` exits 0.

## Why this ships before its test

There is no way to regression-test the net48 handler without a net48 test host, and building one is a medium-effort task (007). Weighed against a target whose sign-in flow currently cannot complete at all, holding a one-line fix behind that is the wrong trade.

The consequence, which must be stated plainly in your report: **this fix is verified by code review and a dual-target build only.** It carries verification debt that task 007 discharges. Do not mark it DONE in a way that implies an automated regression exists.

## Acceptance checklist

- [ ] `Protect` is called after both the verifier and the nonce are written to `properties.Dictionary`.
- [ ] `GenerateCorrelationId` still runs before `Protect`.
- [ ] Redirect query parameters, keys, PKCE method and escaping are byte-for-byte unchanged.
- [ ] Dual-target Release build exits 0 with no warnings.
- [ ] Core suite still exits 0.
- [ ] Diff is exactly one moved line in one file.
- [ ] Report states explicitly that no automated test covers this yet and names task 007 as the follow-up.

## Stop conditions

Stop and report if: the fix requires touching anything beyond the `Protect` call position; moving it changes what `GenerateCorrelationId` or `properties.RedirectUri` observe in a way you cannot reason about; or the build surfaces a `net48` warning that was not there before.

## Maintenance note

The invariant to protect in every future review of this method: **`StateDataFormat.Protect` must be the last thing that reads `properties` before the redirect is built.** Any new value added to `properties.Dictionary` after that call is silently dropped, with no compiler or test signal. Task 007's regression asserts this invariant directly; keep it.
