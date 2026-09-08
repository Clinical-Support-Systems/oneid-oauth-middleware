# Task 009 — Drop the net48 / OWIN-Katana target and ship the library as net8.0-only

## Status and objective

TODO; P1; large effort; **high change risk (public breaking change)**; tech-debt/migration. Planned at `a9dba7d`, 2026-09-07. Prerequisite: **task 002 must be committed first** (see the drift gate — its changes may still be sitting uncommitted in the working tree).

Make `AspNet.Security.OAuth.OneID` a single-target `net8.0` package. Delete the OWIN/Katana implementation, collapse every `#if !NETCORE` / `#elif !NETCORE` / `#if NETFULL` branch in the surviving shared files, remove the Katana consumer sample and the net48 test project, and publish the result as a **2.0.0** major version with a migration note.

This is a deliberate, owner-approved removal of a supported target framework. It is not a refactor and it is not reversible by a patch release. Execute it exactly as written; do not soften it into a deprecation warning, and do not preserve shims for the removed types.

## Why this is being done

The library targets `net48;net8.0` (`src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj:4`) and forks its entire implementation on the `NETFULL`/`NETCORE` compilation symbols defined at the bottom of that file (lines ~104-110).

Three facts drove the decision:

1. **The Katana sign-in flow was completely broken for three months and nobody reported it.** Commit `7285bbe` (2026-06-09) moved the `Protect` call above the PKCE-verifier and nonce writes in `OneIdAuthenticationHandler.NetFull.cs`, so the round-tripped state never contained either value and the callback threw unconditionally. It was fixed only by `aed06c1` (2026-09-07). Pushes to `master` publish to NuGet (`.github/workflows/main.yml`), so that breakage shipped. Every net48 sign-in failed for a quarter, in a published package, in silence.
2. **The net48 target is roughly 40% of the library's source and nearly all of its conditional complexity.** Nine files are wholly wrapped in a single net48-only guard and disappear entirely; several shared files are written twice, once per target.
3. **It blocks the remaining backlog.** Tasks 004 (options consistency) and 005 (typed refresh) are largely *about* the dual-target divergence, and task 006's open questions on Katana discovery/issuer handling become moot.

The owner has confirmed there is no net48 consumer they need to support. NuGet never unpublishes, so any unknown net48 consumer remains able to use the 1.3.x line indefinitely; this is why the removal ships as a major version rather than silently dropping a TFM in a minor.

## Current state — exact inventory

### Files that are wholly net48-only (delete outright)

Each of these has exactly **one** conditional-compilation guard: a single `#if !NETCORE` or `#if NETFULL` opening near line 32-34 and a matching `#endif` as the last line of the file. Nothing in them compiles on net8.0 today.

| File (under `src/AspNet.Security.OAuth.OneID/`) | Lines | Opening guard |
|---|---|---|
| `OneIdAuthenticationHandler.NetFull.cs` | 602 | `#if !NETCORE` (line 32) |
| `OneIdAuthenticationProvider.cs` | 144 | `#if !NETCORE` (line 32) |
| `OneIdAuthenticationMiddleware.cs` | 134 | `#if !NETCORE` (line 32) |
| `Provider/OneIdAuthenticationHandlerFactory.cs` | 88 | `#if NETFULL` (line 32) |
| `Provider/OneIdTokenRequestContext.cs` | 85 | `#if NETFULL` (line 32) |
| `PKCECode.cs` | 77 | `#if !NETCORE` (line 34) |
| `Provider/OneIdAuthenticatingContext.cs` | 74 | `#if NETFULL` (line 32) |
| `Provider/OneIdApplyRedirectContext.cs` | 67 | `#if NETFULL` (line 32) |
| `Provider/OneIdReturnEndpointContext.cs` | 52 | `#if NETFULL` (line 32) |
| **total** | **1,323** | |

After deleting the five files above under `Provider/`, only `Provider/OneIdAuthenticatedContext.cs` remains in that directory. **Do not delete `Provider/OneIdAuthenticatedContext.cs`** — it is dual-target (`#if NETFULL` at line 39, `#elif NETCORE` at line 44, `#if NETFULL` again at line 151) and its NETCORE half is live code. Keep the file and the directory; delete only its NETFULL branches.

### Files with interleaved branches (collapse, do not delete)

For each of these, delete the net48 side of every conditional and keep the net8.0 side, then remove the now-redundant `#if`/`#elif`/`#else`/`#endif` scaffolding entirely. The whole assembly compiles under `NET8_0_OR_GREATER` and `NETCORE` after this task, so **every** remaining `#if NET8_0_OR_GREATER`, `#if NETCORE`, `#if !NET8_0_OR_GREATER` and `#if !NETCORE` in `src/` becomes statically decidable and must go.

| File | Lines | Guard sites | Note |
|---|---|---|---|
| `TokenEndpoint.cs` | 234 | 13 `#if !NETCORE`/`#else` pairs + 1 `#if NET8_0_OR_GREATER` | Worst case: nearly every member is written twice, Newtonsoft attributes on the net48 side vs. the net8.0 side. |
| `OneIdAuthenticationOptions.cs` | 547 | guards at 43, 53, 67, 69, 82, 86, 141, 325, 366, 460, 470, 478, 489 | Includes the base-class swap and a 41-line `#if !NETCORE` property block at 325-365. |
| `OneIdAuthenticationBackChannelHandler.cs` | 405 | 9 `#if NET8_0_OR_GREATER`/`#else` pairs + `#if !NETCORE` at 334 | |
| `TokenEndpoint.cs`, above, plus `OneIdHelper.cs` | 199 | guards at 138/141, 181/183 | See the Newtonsoft caveat below. |
| `OneIdAuthenticationExtensions.cs` | 127 | `#if NET8_0_OR_GREATER` (37), `#elif !NETCORE` (44), and (52)/(95) | The `#elif !NETCORE` block holds the two public `UseOneIdAuthentication` OWIN overloads and an internal `ToQueryString` helper — all deleted. |
| `OneIdAuthException.cs` | 65 | guards at 32, 36, 38, 54 | |
| `OneIdAuthenticationClaimAction.cs` | 68 | `#if NET8_0_OR_GREATER` (33) | Whole body is already net8.0-only; just unwrap. |
| `OneIdAuthenticationEvents.cs` | 71 | `#if NET8_0_OR_GREATER` (32) | Unwrap only. **Task 002 modified this file** — see the drift gate. |
| `OneIdAuthenticationPostConfigureOptions.cs` | 103 | `#if NET8_0_OR_GREATER` (31) | Unwrap only. |
| `OneIdLoggerExtensions.cs` | 178 | `#if NET8_0_OR_GREATER` (32) | Unwrap only. |
| `OneIdTokenValidator.cs` | 182 | `#if NET8_0_OR_GREATER` (32) | Unwrap only. |
| `OneIdValidateIdTokenContext.cs` | 71 | `#if NET8_0_OR_GREATER` (32) | Unwrap only. |
| `OneIdAuthenticationHandler.NetCore.cs` | 484 | guards at 28, 58, 76 | Unwrap; the `#if !NET8_0_OR_GREATER` at 58 is dead code to delete. |
| `Provider/OneIdAuthenticatedContext.cs` | 239 | guards at 39, 44, 59, 61, 65, 80, 84, 151 | Keep the `#elif NETCORE` / `#if NET8_0_OR_GREATER` sides. |

Concrete example of the shape to produce — `OneIdAuthenticationOptions.cs:78-84` today:

```csharp
        public OneIdAuthenticationOptions()
#if !NETCORE
             : base(OneIdAuthenticationDefaults.DisplayName)
#endif
        {
#if NET8_0_OR_GREATER
```

becomes:

```csharp
        public OneIdAuthenticationOptions()
        {
```

And `OneIdAuthenticationExtensions.cs:44-93`, the `#elif !NETCORE` block containing `ToQueryString`, `UseOneIdAuthentication(IAppBuilder, OneIdAuthenticationOptions)` and `UseOneIdAuthentication(IAppBuilder, string, OneIdAuthenticationEnvironment)`, is deleted in full along with its `using Owin;` at line 45.

### Public API removed by this task (the breaking change)

Record this list verbatim in the README migration note and the release notes:

- `OneIdAuthenticationExtensions.UseOneIdAuthentication(this IAppBuilder, OneIdAuthenticationOptions)`
- `OneIdAuthenticationExtensions.UseOneIdAuthentication(this IAppBuilder, string, OneIdAuthenticationEnvironment)`
- `OneIdAuthenticationMiddleware`
- `OneIdAuthenticationProvider` and `IOneIdAuthenticationProvider`
- `IOneIdAuthenticationHandlerFactory` / `OneIdAuthenticationHandlerFactory`
- `OneIdApplyRedirectContext`, `OneIdAuthenticatingContext`, `OneIdReturnEndpointContext`, `OneIdTokenRequestContext`
- `PKCECode`
- The net48-only `OneIdAuthenticationOptions` members at lines 325-365: `AuthorizationEndpoint`, `TokenEndpoint`, `ClaimsIssuer`, `StateDataFormat`, `Provider`, `SignInAsAuthenticationType`, `CallbackPath` (net48 `PathString`), `BackchannelHttpHandler`, `AuthenticationHandlerFactory`, `BackchannelTimeout`, `Caption`, and the Katana base class. Note that several of these names *also* exist on the net8.0 side with different types — verify member-by-member which side you are deleting, and if the net8.0 build loses a member a Core consumer uses, that is a STOP condition.

Enumerate the removed surface from the built assembly rather than from memory: after step 4, diff the generated `src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.xml` documentation file against its pre-change version to confirm nothing unexpected vanished from the net8.0 surface.

### Dependencies removed

From `src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj`, the two `ItemGroup`s conditioned on `'$(TargetFramework)' == 'net48'` (lines ~62-73) go away entirely:

- `Microsoft.Owin` 4.2.2
- `Microsoft.Owin.Security.OAuth` 4.2.2
- `Microsoft.Net.Http` 2.2.29
- `System.IdentityModel.Tokens.Jwt` `[8.3.1,)`
- Framework references `System.Net.Http` and `System.Web`

**Newtonsoft.Json does NOT leave with net48.** `src/AspNet.Security.OAuth.OneID/OneIdHelper.cs:190` calls `JsonConvert.DeserializeObject<JObject>` inside `RefreshToken`, and that call is **not** inside any conditional — the net8.0 build uses Newtonsoft today. `Newtonsoft.Json` is an unconditional `PackageReference`. Leave it in place. Porting `RefreshToken` to `System.Text.Json` belongs to task 005 (typed refresh); do not attempt it here. Do check, after step 4, whether the *remaining* `using Newtonsoft.Json*` directives in `OneIdAuthenticationHandler.NetFull.cs` (deleted), `Provider/OneIdAuthenticatedContext.cs:43` and `TokenEndpoint.cs:35-36` are still reachable, and delete only the ones that became unused.

### Conventions to match

- Block-scoped braced namespaces (not file-scoped), nullable enabled, `TreatWarningsAsErrors` is **true** on the library — an unused `using` left behind after a guard collapse will fail the build, which is a useful signal.
- `AnalysisMode` is `AllEnabledByDefault` with `AnalysisLevel` `latest`. Do not add `#pragma warning disable` to get past an analyzer that fires on newly-unguarded code; fix the code or STOP.
- Every source file carries a `#region License, Terms and Conditions` header block ending around line 30. The target-guard `#if` typically opens immediately after `#endregion`. Preserve the license header exactly; delete only the guard.
- xUnit `[Fact]`/`[Theory]` with Shouldly in the net48 test project, plain `Assert` in the Core project. Only the Core project survives.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Library build (both targets, pre-change) | `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release` | exit 0, 0 warnings, `net48` + `net8.0` DLLs |
| Library build (post-change) | same command | exit 0, 0 warnings, **only** a `net8.0` DLL |
| Core tests | `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj` | exit 0 |
| net48 tests (pre-change only) | `dotnet test tests/AspNet.Security.OAuth.OneID.NetFull.Tests/AspNet.Security.OAuth.OneID.NetFull.Tests.csproj` | exit 0, 6 passed |
| Solution restore + build | `dotnet restore` then `dotnet build --no-restore -c Release` | exit 0 — this is what CI runs |
| Guard sweep | `grep -rn "NETFULL\|NETCORE\|NET8_0_OR_GREATER" --include=*.cs src/ \| grep -v "/obj/"` | no matches after step 4 |
| Hygiene | `git diff --check` | exit 0 |

## Scope

**May delete:**
- The nine wholly-net48 files listed in the inventory table.
- `src/ConsumerApp.Katana/` — the entire directory (127 tracked files); it is the OWIN sample and cannot build without the removed middleware.
- `tests/AspNet.Security.OAuth.OneID.NetFull.Tests/` — the entire directory (5 tracked files: the `.csproj`, `OneIdChallengeStateTests.cs`, and `Infrastructure/ChallengeTestHost.cs`, `Infrastructure/NetworkForbiddenHandler.cs`, `Infrastructure/PassthroughDataProtector.cs`).
- `codebase-analysis-docs/assets/test-results/netfull/coverage.cobertura.xml` — the net48 coverage report, now describing deleted code.

**May edit:**
- Every remaining `.cs` file under `src/AspNet.Security.OAuth.OneID/` that carries a target guard (the collapse table).
- `src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj`.
- `oneid-oauth-middleware.slnx` — remove the `ConsumerApp.Katana` and `AspNet.Security.OAuth.OneID.NetFull.Tests` `<Project>` entries.
- `version.json` — bump `"version"` from `"1.3"` to `"2.0"`.
- `README.md` — lines 3, 57-66 (the OWIN/Katana Startup.cs example), 106-116 (the two-test-projects section), plus a new migration note.
- `AGENTS.md` — the project-map and build/compatibility bullets that promise both targets.
- `tutorial/03_oneidauthenticationextensions_.md` and `tutorial/04_oneidauthenticationhandler_.md` — the OWIN/Katana sections (see step 6).
- `codebase-analysis-docs/IMPLEMENTATION_PLAN.md` — this task's status row.

**Out of scope — do NOT touch:**
- `.github/workflows/main.yml`. Editing the release workflow risks publishing. It runs solution-level `dotnet restore` / `dotnet build`, which keeps working once the solution no longer references the removed projects — that is the only interaction, and it needs no edit. Its `DOTNET_VERSION: '8.0.401'` vs. `global.json` mismatch is a separately-scoped known issue; leave it.
- `src/ConsumerApp.Kestrel/` — the Core sample, unaffected.
- `OneIdHelper.RefreshToken`'s Newtonsoft usage — task 005.
- `DefaultOneIdTokenValidator` discovery/JWKS/retry logic — task 006.
- Any behavior change to the net8.0 path. This task deletes and unwraps; it does not fix, improve, or reorganize surviving Core code. If a collapse tempts you to "clean up while you're in there", don't.
- Publishing, pushing, tagging, or creating a GitHub release.

## Drift gate (run before editing anything)

```
git status --short
git diff --stat a9dba7d..HEAD -- src tests README.md version.json oneid-oauth-middleware.slnx
```

**Task 002 is the critical one.** At the time this plan was written, task 002's changes (a modified `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationEvents.cs`, a modified `tests/AspNet.Security.OAuth.OneID.Tests/OneIdAuthenticationHandlerAdditionalNetCoreTests.cs`, a modified `README.md`, and two new files `tests/AspNet.Security.OAuth.OneID.Tests/OneIdTokenValidatorTests.cs` and `tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/SyntheticOneIdTokens.cs`) were **uncommitted in the working tree**.

- If `git status --short` shows those files dirty: **STOP and report.** Do not begin. Deleting ~1,300 lines underneath uncommitted work makes the diff unreviewable and the changes unrecoverable if anything goes wrong. The owner must commit task 002 first.
- If they are committed: confirm `OneIdAuthenticationEvents.cs` now throws `InvalidOperationException` when `context.Options.TokenValidator` is null. That file is on your collapse list; you are unwrapping its `#if NET8_0_OR_GREATER` (line 32) and must not revert task 002's logic while doing so.

Then confirm the pre-change baseline is green before you break anything — run the library build, the Core tests and the net48 tests, and record all three. If the net48 tests do not pass *before* you start, say so; you are still deleting them, but the record should be honest about what state they were in.

Never push, publish, tag, reset, stash, or overwrite user changes.

## Git workflow

- Branch: `task/009-drop-net48` off `master`.
- Conventional-commit style, matching `git log` (e.g. `test(007): add net48 xUnit project and regress Katana challenge state`). Suggested commits, one per step: `chore(009): delete net48-only sources`, `refactor(009): collapse target guards`, `build(009): single-target net8.0 and bump to 2.0`, `docs(009): document the 2.0 breaking change`.
- Do **not** merge to `master`, push, or tag. `master` publishes to NuGet; the owner decides when 2.0.0 ships.

## Steps and gates

### Step 1 — Record the pre-change baseline

Build the library, run both test suites, and save the current `src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.xml` (the generated documentation file, which is a proxy for the public API surface) to a scratch location outside the repo for later comparison.

**Gate:** Release build exits 0 producing both `bin/Release/net48/` and `bin/Release/net8.0/` assemblies; Core tests exit 0; net48 tests exit 0 with 6 passed. Quote all three results.

### Step 2 — Delete the wholly-net48 files, sample, and test project

Delete the nine files in the inventory table, `src/ConsumerApp.Katana/`, `tests/AspNet.Security.OAuth.OneID.NetFull.Tests/`, and `codebase-analysis-docs/assets/test-results/netfull/coverage.cobertura.xml`. Remove the two corresponding `<Project>` entries from `oneid-oauth-middleware.slnx`.

Do not touch `Provider/OneIdAuthenticatedContext.cs` in this step.

**Gate:** `git status --short` lists exactly the expected deletions and the one modified `.slnx`, nothing more. The build is expected to be **broken** at this point (net48 sources are gone but the csproj still targets net48) — that is fine; do not attempt to build yet.

### Step 3 — Single-target the csproj

In `src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj`:

- `<TargetFrameworks>net48;net8.0</TargetFrameworks>` → `<TargetFramework>net8.0</TargetFramework>` (note the singular element name).
- Delete both `ItemGroup`s conditioned on `'$(TargetFramework)' == 'net48'`.
- Delete the two `PropertyGroup`s conditioned on `'$(Configuration)|$(TargetFramework)|$(Platform)'=='Debug|net48|AnyCPU'` and `'...=='Release|net48|AnyCPU'`.
- Delete the `PropertyGroup Condition="'$(TargetFramework)' == 'net48'"` that defines `NET48;NETFULL`, and the `PropertyGroup Condition="'$(TargetFramework)' != 'net48'"` that defines `NETCORE`. **Both go** — `NETCORE` becomes meaningless once there is one target, and step 4 removes every reference to it.
- Make the `Microsoft.AspNetCore.Authentication.OpenIdConnect` `ItemGroup` unconditional (drop its `Condition`).
- Add `<PackageValidationBaselineVersion>` only if you can confirm the SDK in `global.json` supports it; otherwise skip it silently rather than guessing.

**Gate:** `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release` runs and produces compile errors **only** from unresolved net48 symbols in the guard-collapse files — not from missing packages or malformed MSBuild. If MSBuild itself fails to evaluate the project, fix that before proceeding.

### Step 4 — Collapse every target guard

Work through the collapse table file by file. For each guard: keep the `NET8_0_OR_GREATER` / `NETCORE` branch, delete the other branch, delete the `#if`/`#elif`/`#else`/`#endif` lines themselves, and delete any `using` directive that only served the removed branch. Re-indent the retained code to its correct nesting level — do not leave the extra indentation the guard implied.

Order the work to keep feedback tight: start with the "unwrap only" files (single `#if NET8_0_OR_GREATER` wrapping the whole body), then the interleaved ones, ending with `TokenEndpoint.cs` and `OneIdAuthenticationOptions.cs`.

`TreatWarningsAsErrors` will catch orphaned usings for you. Trust it rather than eyeballing.

**Gate:** `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release` → exit 0, **0 warnings**, one `net8.0` assembly and no `net48` output directory. Then `grep -rn "NETFULL\|NETCORE\|NET8_0_OR_GREATER" --include=*.cs src/ | grep -v "/obj/"` → **no matches**. A leftover guard means the collapse is incomplete; obj/ artifacts are stale build output and are excluded by the grep filter, not something to edit.

### Step 5 — Verify the surviving Core behavior is unchanged

Run the Core test suite. The Core test project targets `net9.0` and resolved the library's `net8.0` assets before this change, so it should be entirely unaffected — every test that passed in step 1 must still pass, with the same counts.

Then diff the regenerated `AspNet.Security.OAuth.OneID.xml` against the copy saved in step 1. Every removed entry must be attributable to the net48-only API list in "Public API removed by this task". A removal you cannot explain from that list means you deleted a live Core member.

**Gate:** `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj` → exit 0 with the **same** passed/skipped/failed counts as step 1. Quote both. The documentation diff shows only expected removals. Also run `dotnet restore && dotnet build --no-restore -c Release` at the repository root to prove the solution CI path still works with the two projects gone.

### Step 6 — Version bump and documentation

- `version.json`: `"version": "1.3"` → `"version": "2.0"`.
- `README.md`:
  - Line 3: drop `Owin/Katana` from the description, leaving Kestrel/ASP.NET Core.
  - Lines 57-66: delete the `**OWIN/Katana (ASP.NET)**` Startup.cs example and its heading, keeping the Kestrel one.
  - Lines 106-116: replace the two-test-projects section with the single Core command; delete the paragraph about the `net48` project being the only coverage for `OneIdAuthenticationHandler.NetFull.cs`.
  - Add a short **"2.0 breaking change: net48 support removed"** section stating: the package is now `net8.0`-only; consumers on ASP.NET Framework/OWIN should stay on the **1.3.x** line, which remains available on NuGet; and listing the removed public API from the inventory above. State plainly that there is no migration path from OWIN to ASP.NET Core within this library — moving forward requires moving the host application.
- `AGENTS.md`: update the project-map bullet that describes the two targets and the `NETFULL`/`NETCORE` split, the bullet naming `OneIdAuthenticationHandler.NetFull.cs`, and the ConsumerApp bullet.
- `tutorial/03_oneidauthenticationextensions_.md`: the OWIN/Katana half (`UseOneIdAuthentication`, at lines 16, 67-69, 106, 168, 181-193) documents deleted API. Mark that section as applying to 1.3.x only — a short note at the top of the section is sufficient. Do **not** rewrite the tutorials wholesale; they are generated narrative docs and a full rewrite is out of scope.
- `tutorial/04_oneidauthenticationhandler_.md`: same treatment for lines 24 and 123.

**Gate:** `grep -rn -i "net48\|katana\|owin" README.md AGENTS.md` returns only the intentional 1.3.x migration references. `grep -rn "ConsumerApp.Katana\|NetFull" oneid-oauth-middleware.slnx` returns nothing.

### Step 7 — Final hygiene

**Gate:** `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release` → exit 0, 0 warnings. `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj` → exit 0. `git diff --check` → exit 0. `git status --short` shows only in-scope paths.

Confirm the generated package name and version: the Release build writes `AspNet.Security.OAuth.OneID.<version>.nupkg` into `src/AspNet.Security.OAuth.OneID/bin/Release/`. It must now be a 2.0.x version and must contain only a `lib/net8.0/` folder. Inspect it (a `.nupkg` is a zip) rather than assuming.

## Acceptance checklist

- [ ] Task 002 was committed before this task began; its `InvalidOperationException` behavior survives the guard collapse in `OneIdAuthenticationEvents.cs`.
- [ ] All nine wholly-net48 source files, `src/ConsumerApp.Katana/`, and `tests/AspNet.Security.OAuth.OneID.NetFull.Tests/` are deleted; `Provider/OneIdAuthenticatedContext.cs` survives.
- [ ] `grep -rn "NETFULL\|NETCORE\|NET8_0_OR_GREATER" --include=*.cs src/ | grep -v "/obj/"` returns no matches.
- [ ] The csproj declares a single `<TargetFramework>net8.0</TargetFramework>`; all net48 package references, framework references, and per-target property groups are gone; `Newtonsoft.Json` is still referenced (deliberately — task 005 owns its removal).
- [ ] Release build exits 0 with **0 warnings** and emits only net8.0 output; the packed `.nupkg` contains only `lib/net8.0/`.
- [ ] Core test suite passes with counts identical to the step-1 baseline.
- [ ] Solution-level `dotnet restore && dotnet build --no-restore -c Release` exits 0.
- [ ] `version.json` reads `"2.0"`; README carries the breaking-change section naming the 1.3.x fallback and listing the removed public API.
- [ ] Nothing was pushed, tagged, merged to `master`, or published.

## Stop conditions

Stop immediately and report if:

- **Task 002's changes are still uncommitted** when you run the drift gate. This is the most likely blocker and the most damaging to ignore.
- Collapsing a guard would remove a member that the **net8.0** build or the Core test suite actually uses — that means the inventory above mis-classified something, and the plan needs correction before you continue.
- The Core test counts change in step 5, in either direction. A test that starts passing is as much a signal as one that starts failing.
- The build cannot reach 0 warnings without a `#pragma warning disable` or a suppression. Analyzers firing on newly-unguarded code are telling you something real; do not silence them to finish.
- `dotnet restore` at the solution root fails after the project removals in a way you cannot trace to the removed entries.
- You find a net48-only file that is *not* in the inventory table, or a file in the table whose guard structure does not match what is described.

Do not, in this task: port `RefreshToken` off Newtonsoft, touch `.github/workflows/main.yml`, change any net8.0 behavior, add shim types or `[Obsolete]` stand-ins for the removed OWIN API, or rewrite the tutorial documents beyond the version notes in step 6.

## Maintenance notes

For whoever owns this afterward:

- **Tasks 004, 005 and 006 must be re-scoped after this lands.** Task 004 (options consistency) was largely about dual-target divergence in `OneIdAuthenticationOptions.cs` and shrinks substantially. Task 005 (typed refresh) becomes the natural home for removing Newtonsoft entirely, since `OneIdHelper.RefreshToken` is then the only consumer worth converting. Task 006's questions about Katana discovery and issuer handling are moot; only its Core-side decisions survive.
- **This deletes the repository's only executable net48 coverage** (task 007's project). That is correct — there is nothing left to cover — but it means the `OneIdAuthenticationHandler.NetFull.cs` regression that task 003 fixed can never recur *and* can never be tested. If net48 support is ever restored, restore task 007 with it; do not restore the handler alone.
- **A reviewer should scrutinize the guard collapses most, not the deletions.** Deleting a wholly-guarded file is mechanical and safe. The risk lives in `TokenEndpoint.cs` and `OneIdAuthenticationOptions.cs`, where interleaved branches make it easy to keep the wrong side of an `#if` — especially where a member name exists on both sides with different types. Read those two diffs line by line against the retained-branch rule.
- **1.3.x is now the frozen OWIN line.** If a security fix is ever needed for a net48 consumer, it has to be branched from the last 1.3.x commit, and the removed files recovered from git history rather than rewritten.
