# Task 007 — Add an executable net48 test project and regress the Katana challenge state

## Status and objective

TODO; P1; medium effort; low change risk (test-only); tests/DX. Planned at `777d721`, 2026-09-07; split out of task 003 during plan review. Prerequisite: **task 003** has landed (the `Protect` reorder).

Create a Windows-only `net48` xUnit project that actually executes the Framework handler, and use it to lock in the challenge-state invariant that task 003 fixed. Then wire it into the solution and into task 001's validation workflow if that workflow exists yet.

**This task changes no runtime source.** If you find yourself editing anything under `src/`, stop.

## Why this project has to exist

The library targets `net48;net8.0` (`src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj:4`) and switches implementations on the `NETFULL`/`NETCORE` symbols — `OneIdAuthenticationHandler.NetFull.cs` versus `OneIdAuthenticationHandler.NetCore.cs`.

The only existing test project, `tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj`, targets `net9.0`. It therefore resolves the library's `net8.0` assets and executes the Core handler exclusively. **No line of `OneIdAuthenticationHandler.NetFull.cs` has ever been executed by a test in this repository.** Task 003's defect — `Protect` called before the PKCE verifier and nonce were written, breaking every Katana sign-in — reached `master` because of this gap, and nothing prevents the next one.

Do not retarget the existing project to fix this, and do not try to multi-target it: its `FrameworkReference Include="Microsoft.AspNetCore.App"` and its ASP.NET Core test fixtures (`Microsoft.AspNetCore.Mvc.Testing`, `Microsoft.AspNetCore.TestHost`) cannot build against `net48`. A second project is the correct shape.

## Evidence and seams to use

The public seams that let you drive a challenge without reflection:

- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationMiddleware.cs` constructs a `PropertiesDataFormat` when none is supplied, and accepts a caller-supplied `StateDataFormat` and `BackchannelHttpHandler` through options.
- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationProvider.cs` exposes `OnApplyRedirect`, letting you observe the real redirect the handler produces.
- `src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticationHandlerFactory.cs` and the public two-argument Framework handler constructor are extension points; do not change them, but you may use them.

The invariant under test, from `OneIdAuthenticationHandler.NetFull.cs` after task 003: the `state` query parameter of the authorization redirect, when unprotected, contains both `PkceCodeVerifierProperty` and `NonceProperty` entries, and the redirect's `nonce` parameter equals the one in the state.

The callback side that consumes them is at `NetFull.cs:157` (verifier; throws `InvalidOperationException("PKCE code_verifier is missing from authentication state.")` when absent) and `NetFull.cs:204` (nonce).

Package versions: the library references `Microsoft.Owin` and `Microsoft.Owin.Security.OAuth` at **4.2.2** for `net48` (csproj lines 62-64). Use `Microsoft.Owin.Testing` **4.2.2** to match. Do not upgrade the library's packages. If 4.2.2 of the testing package cannot resolve against the rest of the stack, consult the package metadata, pick the nearest compatible version, and **report the choice explicitly** rather than silently drifting.

Test style to match: xUnit `[Fact]`/`[Theory]`, Shouldly assertions, explicit `using` directives (the existing project relies on `ImplicitUsings` and global `Using` items — a `net48` project should declare its usings), block-scoped braced namespaces.

## Scope

May create/edit:

- `tests/AspNet.Security.OAuth.OneID.NetFull.Tests/AspNet.Security.OAuth.OneID.NetFull.Tests.csproj` (new).
- `tests/AspNet.Security.OAuth.OneID.NetFull.Tests/OneIdChallengeStateTests.cs` (new).
- `tests/AspNet.Security.OAuth.OneID.NetFull.Tests/Infrastructure/` (new; test host and fake transport fixtures only).
- `oneid-oauth-middleware.slnx` — add the new project. Follow the existing `<Project Path="..."/>` entries; note that the two ConsumerApp projects carry `<Build Solution="Release|*" Project="false" />` and the test project does not, so add yours the same way the existing test project is added.
- `.github/workflows/validation.yml` — **only if task 001 has already created it.** If it does not exist, skip that step and say so; do not create it here and do not touch `main.yml`.
- `README.md`, this task's status, `codebase-analysis-docs/IMPLEMENTATION_PLAN.md`, and reports under `codebase-analysis-docs/assets/test-results/netfull/`.

Out of scope: all runtime source, the Core handler and Core test project, the callback host regex, JWKS/discovery/issuer behavior (task 006), certificate import, sample apps, consolidating the two test projects, the release workflow, package upgrades in the library.

## Drift gate

`git status --short`, then `git diff --stat 777d721..HEAD -- src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs tests oneid-oauth-middleware.slnx .github/workflows`.

Confirm task 003's reorder is present — the `Protect` call must sit after the nonce assignment. If it does not, stop: run task 003 first, because step 3 below cannot pass otherwise. Reconcile any additions from task 001. No push, commit, stage, reset or publish.

## Steps and gates

1. Create the SDK-style project targeting `net48`, with a `ProjectReference` to the library, `Microsoft.NET.Test.Sdk`, `xunit`, `xunit.runner.visualstudio`, `Shouldly` and `Microsoft.Owin.Testing` 4.2.2. Add `coverlet.collector` only if it works on this target; if it does not, note that instead of forcing it. Add one smoke test that starts an OWIN `TestServer` with `AddOneId`-equivalent Katana registration using a synthetic `ClientId` and a fake backchannel handler that never touches the network.

   Gate: `dotnet test tests/AspNet.Security.OAuth.OneID.NetFull.Tests/AspNet.Security.OAuth.OneID.NetFull.Tests.csproj` → exit 0 **with a test actually executed on net48**. A project that merely compiles does not satisfy this step; quote the executed test count.

2. Build the challenge test host: OWIN application/external sign-in cookie setup as needed, explicit scheme, fake token transport. Use request host `app.example.test`, **not** `localhost` — the callback contains a host-prefix regex near `NetFull.cs:145` whose behavior on loopback hosts is a separate unresolved question (task 006) and must not contaminate this test.

   Supply a test `IDataProtector` through `Options.StateDataFormat` (as `PropertiesDataFormat`) that round-trips a **byte snapshot**. It must not capture or hand back a live reference to the `AuthenticationProperties` instance — a by-reference fake would have passed against the original buggy code and is the one mistake that makes this whole task worthless. This fake protects no real secret; it exists so the test can read what was serialized.

   Issue the challenge through the public OWIN authentication API and capture the `Location` header.

   Gate: the test can retrieve `state` from the real redirect and unprotect it. Assert nothing about secrecy — only about serialization fidelity.

3. Assert the invariant: the unprotected state contains a non-empty PKCE code verifier and the expected nonce; the redirect's `nonce` query parameter equals the nonce inside the state; and `base64url(SHA256(verifier))` equals the redirect's `code_challenge` with `code_challenge_method=S256`.

   Gate: `dotnet test <netfull csproj> --filter FullyQualifiedName~OneIdChallengeStateTests` → passes.

   **Verify the test is real:** temporarily move the `Protect` call back to its pre-003 position, confirm this test fails with the verifier absent, then restore the fix. Record both outcomes. Revert the temporary change completely — `git diff -- src/` must be empty when you finish.

4. Add: two independent challenges produce distinct verifiers and distinct nonces; the correlation value and the original `RedirectUri` survive the round trip; the verifier does not appear as a bare query parameter on the redirect.

   Gate: same filter → all pass, with no outbound HTTP and no certificate-store access.

5. If `.github/workflows/validation.yml` exists, add a separate step or job that restores, builds and tests this project on `windows-latest`, writing coverage to a directory distinct from the Core reports. Update `README.md` with the net48 test command.

   Gate: `dotnet test <netfull csproj> --collect "XPlat Code Coverage" --results-directory codebase-analysis-docs/assets/test-results/netfull` → exit 0 and the XML includes `OneIdAuthenticationHandler.NetFull`. If the collector cannot instrument `net48` here, report that as unresolved — **never** relabel Core coverage as Framework coverage, and never report Framework coverage as 0% when it is simply unmeasured.

6. Gate: `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj` → Core suite still exits 0. `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release` → exit 0, both targets. `git diff --check` → exit 0.

## Acceptance checklist

- [ ] A separate `net48` test project exists, executes tests on Windows, and is in `oneid-oauth-middleware.slnx`.
- [ ] The state-serialization regression passes on current code **and** was demonstrated to fail against the pre-003 ordering; both results are recorded.
- [ ] The data-protection fake serializes by value; this is stated explicitly in the report.
- [ ] Uniqueness, correlation preservation, return-URI preservation and PKCE recomputation all pass.
- [ ] No test requires a live provider, real certificate, token exchange or network access.
- [ ] `git diff -- src/` is empty; no runtime source was changed.
- [ ] Core suite and dual-target Release build exit 0; Core and Framework reports are stored separately and labeled.
- [ ] The report states plainly what is still uncovered: the full Katana callback, token exchange, JWKS discovery and issuer validation.

## Stop conditions

Stop and report if: constructing an OWIN test host requires changing a public handler/factory/middleware signature; `net48` tests cannot execute on the available machine (this needs Windows with the .NET Framework 4.8 targeting pack); or the state regression fails for a reason other than the ordering you are testing.

Do not, in this task, "fix" the callback host regex, the correlation implementation, discovery, or issuer validation — even if a test surfaces them. Record what you saw and leave it for task 006.

## Maintenance note

This project is the only execution coverage the `net48` target has. Every future change to `OneIdAuthenticationHandler.NetFull.cs` should add to it. The highest-value next addition is a full synthetic callback test — challenge, then a fabricated authorization response, through token exchange with a fake transport, to a signed-in identity — which would have caught the task 003 defect from the other end. That test needs the discovery-transport and trusted-issuer decisions from task 006 first.
