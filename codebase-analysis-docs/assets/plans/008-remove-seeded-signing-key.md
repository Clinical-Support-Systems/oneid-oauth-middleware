# Task 008 — Remove the hardcoded default signing key from Core options

## Status and objective

**DONE / MERGED**; **P0**; small effort; low change risk to correct configurations; security. Planned at `777d721`, 2026-09-07 (split out of task 002 during plan review). No prerequisites beyond a green existing test suite.

Executed 2026-09-07 by a dispatched executor in an isolated worktree, reviewed, then applied to `master` as commit **`4e09a2b`** at the owner's instruction (cherry-picked, attribution trailers omitted per the owner's request). **Committed locally, not pushed** — pushing `master` triggers NuGet publication via `.github/workflows/main.yml`. The executor worktree and its branch have been removed.

All acceptance criteria were independently re-verified by the reviewer before the merge: 32 passed / 0 failed / 4 pre-existing skips, dual-target Release build exit 0 with `TreatWarningsAsErrors=true`, diff exactly two files (-1 library line, +11 test lines), no using-directive changes, key literal absent from source, tests, commit message and reports.

Delete the hardcoded symmetric `IssuerSigningKey` that the Core options constructor installs into `TokenValidationParameters`, and add a regression test that keeps it gone. Nothing else. This is deliberately the smallest possible change so it can ship ahead of the larger validation work in task 002.

## Why this is P0 and separate

`src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs:112` (inside the `#if NET8_0_OR_GREATER` constructor block, in the `TokenValidationParameters` initializer that begins near line 104) assigns a fixed base64 symmetric key:

```csharp
ValidateIssuerSigningKey = true,
IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String("<redacted — the literal is on that line; do not copy it into code, tests, docs or reports>")),
```

Why that key is trusted at validation time, end to end:

1. `src/AspNet.Security.OAuth.OneID/OneIdTokenValidator.cs:135` clones the options' parameters:
   `var validationParameters = context.Options.TokenValidationParameters.Clone();`
   `Clone()` copies `IssuerSigningKey` along with everything else.
2. The next block (lines ~137-144) sets only `validationParameters.IssuerSigningKeys` — the **plural** property — from the discovered JWKS, and throws if the set is empty. It never clears the singular `IssuerSigningKey`.
3. `TokenValidationParameters.GetAllSigningKeys()` in `Microsoft.IdentityModel.Tokens` returns the union of `IssuerSigningKey` and `IssuerSigningKeys`. The seeded symmetric key therefore remains an accepted signing key for every default-configured Core consumer.
4. No `ValidAlgorithms` restriction is set anywhere on the Core path, so an `HS256` token is a legal candidate and matches a `SymmetricSecurityKey`.

The key is not a secret by any measure: this repository is public (`Clinical-Support-Systems/oneid-oauth-middleware`), the literal has been committed since `f06b18c`, and it is embedded in the published NuGet assembly regardless of repository visibility.

**Honest severity.** This is a defense-in-depth failure, not a demonstrated remote bypass. Forging an id_token that reaches the validator still requires controlling the backchannel token response (a TLS connection to the OneID token endpoint) or a compromised endpoint configuration. What is lost is the guarantee that signature validation provides *any* assurance in the default configuration: an attacker who reaches that position faces a signature check that a public constant satisfies. Do not describe this as an exploited or exploitable-from-the-internet vulnerability in commit messages, release notes or issues. Do describe it as removing an unusable trust anchor.

## Conventions to match

The library uses block-scoped (braced) namespaces, not file-scoped ones; match the surrounding file and do not reformat anything. Nullable is enabled and the library treats warnings as errors. Shared code must compile for both `net48` and `net8.0`; this edit is inside a `#if NET8_0_OR_GREATER` block, so the net48 path is untouched, but you must still build both targets.

Existing test style to follow: `tests/AspNet.Security.OAuth.OneID.Tests/OneIDAuthenticationOptionsTests.cs`. That file uses `[Fact]` on **`public static void`** methods, plain `Assert.*` (not Shouldly, even though Shouldly is a global using in this project), an `// Arrange` / `// Act and Assert` comment split, options constructed directly with an object initializer, and a braced `namespace AspNet.Security.OAuth.Providers.Tests`. Match that file, not the other test files.

## Scope

May edit:

- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs` — **remove the single `IssuerSigningKey = ...` assignment and nothing else.** Leave `ValidateIssuerSigningKey = true` in place. Leave every other property in that initializer alone.
- `tests/AspNet.Security.OAuth.OneID.Tests/OneIDAuthenticationOptionsTests.cs` — one new test.
- This task's status line and `codebase-analysis-docs/IMPLEMENTATION_PLAN.md`.

Out of scope, explicitly: the validator's key handling (task 002), the null-validator bypass in `OneIdAuthenticationEvents.cs` (task 002), adding `ValidAlgorithms` or any algorithm policy (task 006 decision), the net48 handler's own `TokenValidationParameters` at `OneIdAuthenticationHandler.NetFull.cs:551-561`, `ValidateTokens` semantics, endpoints, samples, package versions, CI.

Do not "also clear `IssuerSigningKeys`", do not add a null guard that reintroduces a default, and do not remove caller-supplied keys anywhere.

## Drift gate

Run `git status --short`, then `git diff --stat 777d721..HEAD -- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs tests/AspNet.Security.OAuth.OneID.Tests/OneIDAuthenticationOptionsTests.cs`.

If line 112 no longer contains a `SymmetricSecurityKey` assignment, someone has already done this — **STOP and report** rather than making a different change. Do not push, commit, stage, stash, reset or publish.

## Steps and gates

1. Add the failing regression to `OneIDAuthenticationOptionsTests.cs`:

   ```csharp
   [Fact]
   public static void NewOptions_DoNotSeedAnIssuerSigningKey()
   {
       // Arrange
       var options = new OneIdAuthenticationOptions();

       // Act and Assert
       Assert.Null(options.TokenValidationParameters.IssuerSigningKey);
       Assert.True(options.TokenValidationParameters.ValidateIssuerSigningKey);
   }
   ```

   Add it inside the existing `OneIDAuthenticationOptionsTests` class in that file. If `TokenValidationParameters` is not reachable from a plain `new OneIdAuthenticationOptions()` on the net9.0 test target, stop and report — do not reach for reflection.

   Gate: `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj --filter FullyQualifiedName~NewOptions_DoNotSeedAnIssuerSigningKey` → **expected to FAIL** with the key non-null. Record that failure output. If it passes before your change, stop — the premise is wrong and this whole task is moot.

2. Delete the `IssuerSigningKey = new SymmetricSecurityKey(...)` line from the constructor's `TokenValidationParameters` initializer. Check whether `SymmetricSecurityKey` / `Convert` are still used elsewhere in the file before touching `using` directives; the library treats warnings as errors, so an unused-using warning will break the build, and so will removing a still-needed one.

   Gate: same filter → passes.

3. Gate: `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj` → the full Core suite exits 0 with no newly skipped tests. If an existing test depended on the seeded key, **STOP and report which one** — that is a finding about the test, and repairing it may belong to task 002. Do not restore the key to make a test pass.

4. Gate: `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release` → exit 0, both `net48` and `net8.0` outputs produced, no warnings (warnings are errors here).

5. Gate: `git diff --check` exits 0, and `git diff --stat` shows exactly two files changed with a net removal of one line in the library.

## Acceptance checklist

- [ ] Default `OneIdAuthenticationOptions.TokenValidationParameters.IssuerSigningKey` is null.
- [ ] `ValidateIssuerSigningKey` is still `true`.
- [ ] Caller-supplied signing keys and `IssuerSigningKeys` behavior are untouched.
- [ ] Regression test failed before the edit and passes after; the before-failure is recorded.
- [ ] Full Core suite passes; no test was skipped, weakened or deleted to get there.
- [ ] Dual-target Release build exits 0.
- [ ] The removed key literal appears in no new file, test fixture, commit message, log line or report.

## Stop conditions

Stop and report, without improvising, if: an existing test or sample depends on the seeded key; removing it causes a validation path to throw somewhere unexpected; or you find yourself wanting to add an algorithm restriction, clear `IssuerSigningKeys`, or edit the validator to compensate. All of those are tasks 002 and 006.

## Maintenance note

After this lands, a default-configured Core consumer trusts exactly the keys that `OneIdTokenValidator` installs from discovery/JWKS, plus anything the caller supplied. Task 002 adds the signed-token tests that prove that end to end; until then, this change is verified only by the unit regression and the existing suite. Any future change that reintroduces a default key, or that adds a fallback when JWKS is unavailable, must be reviewed against this task.
