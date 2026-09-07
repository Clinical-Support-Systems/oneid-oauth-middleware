# Task 004 — Make option updates deterministic

## Status and objective

TODO; P2; small effort; medium compatibility risk; correctness/DX. Planned at `777d721`, 2026-09-07. Depends on tasks 008 and 002 (both edit `OneIdAuthenticationOptions.cs` / validation defaults before this task does) and on task 007 for the Framework test harness. Task 001 is not a gate. Fix three precisely bounded behaviors: service-scope replacement, default callback initialization and secret restoration after validation failure.

## Evidence and intended contract

`src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs:225–234` adds openid and service scopes on each profile assignment but never removes the previous service scopes. Framework uses IList<string>, allowing duplicates. The contract for this task: ServiceProfileOptions owns only the two known service scope names. Setting it recomputes those scopes, keeps openid present once, and preserves all other caller scopes. If a caller manually adds one of the two owned scope strings, the next profile assignment still owns/removes it; document this explicit rule.

Core callback initialization at line 89 uses:

```csharp
CallbackPath = CallbackPath != null ? CallbackPath : new PathString(OneIdAuthenticationDefaults.CallbackPath);
```

Use a HasValue-based fallback to `/signin-oneid`. Explicit later caller overrides remain untouched.

Core Validate at lines 497–499 uses:

```csharp
if (string.IsNullOrEmpty(old)) ClientSecret = Guid.NewGuid().ToString();
base.Validate();
ClientSecret = old;
```

Wrap the temporary substitution/base validation in try/finally so original null/empty/nonempty secret is restored even on exception. Do not change the nonproduction secret requirement or bypass base validation.

Conventions: existing `tests/AspNet.Security.OAuth.OneID.Tests/OneIDAuthenticationOptionsTests.cs` uses xUnit and direct invalid options to assert throws. Keep nullable analysis, block-scoped namespaces and both compilation paths.

## Scope

- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs`: only these three behaviors.
- `tests/AspNet.Security.OAuth.OneID.Tests/OneIDAuthenticationOptionsTests.cs`.
- `tests/AspNet.Security.OAuth.OneID.NetFull.Tests/OneIdOptionsTests.cs` (new).
- `README.md`: concise scope-ownership/default callback explanation.
- Task/index status and test evidence under `codebase-analysis-docs/assets/test-results/`.

Out of scope: endpoint resolver/production Authority correction, default environment changes, certificate-store defaults, new services, ValidateTokens semantics, public API deletion, session/cookie storage.

## Drift/Git gate

`git status --short`; `git diff --stat 777d721..HEAD -- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs tests README.md`. Recognize task 008's removal of the seeded signing key and task 007's new net48 project. Stop if the three target sections changed independently. No push/commit/release.

## Steps and gates

1. Add Core tests for both→OLIS, OLIS→DHDR, repeated identical assignment, None, retention of an unrelated custom scope, and one openid. Add analogous Framework tests to catch IList duplicates; include manually duplicated owned service scopes and openid before assignment. Add Core default-callback/explicit-override tests. Add Core validation-failure tests with null and empty original secrets and a missing ClientId to force base.Validate to throw. Gate: `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj --filter FullyQualifiedName~OneIDAuthenticationOptionsTests` and `dotnet test tests/AspNet.Security.OAuth.OneID.NetFull.Tests/AspNet.Security.OAuth.OneID.NetFull.Tests.csproj --filter FullyQualifiedName~OneIdOptionsTests` → record only the relevant new failures before implementation.
2. In the profile setter remove all occurrences of the two owned service scopes; normalize openid to one entry; add selected service scopes in deterministic OLIS/DHDR order. Do not clear the whole scope collection. Avoid APIs missing on net48; ordinary Contains/Remove/Add loops suffice. Gate: both filters above exit 0; assert `_profile` serialization still matches selected flags and unrelated scopes survive.
3. Replace default callback test with HasValue logic, and ensure temporary ClientSecret restoration in finally. Preserve exception types and downstream checks. Gate: Core options filter exits 0, including existing validation tests and new restoration/default tests.
4. Update README scope ownership. Run both full test projects and `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release` → exit 0 for all; `git diff --check` → exit 0.

## Acceptance checklist

- [ ] Profile switches exactly replace owned scopes on both targets, preserve custom scopes and do not accumulate duplicates.
- [ ] Profile string output remains OLIS first, DHDR second, space separated.
- [ ] New Core options have default callback; user override still works.
- [ ] ClientSecret is restored after successful or failed base validation for null, empty and nonempty values.
- [ ] No environment, trust, token-storage or endpoint behavior changes beyond scope.
- [ ] Both suites and dual-target build pass; all changes are scoped.

## Stop conditions and maintenance

Stop if consumers or existing tests rely on manually retained owned service scopes and the documented ownership rule would violate an established contract; report that concrete conflict rather than inventing an opt-out. Do not validate profiles by changing supported flag values. Future service additions must update owned scopes and both target transition tests together.
