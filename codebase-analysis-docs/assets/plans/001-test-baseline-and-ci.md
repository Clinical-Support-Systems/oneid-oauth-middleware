# Task 001 — Establish an honest test and coverage baseline

## Status and objective

TODO; P2; medium effort; low change risk; category tests/DX. Planned at `777d721`, 2026-09-07; re-scoped 2026-09-07 after plan review. No prerequisites. Establish actual local results and PR coverage reporting **without editing runtime code**.

**This task does not gate any other task.** It was previously a prerequisite for tasks 002–005. It is not: none of those needs a measured coverage baseline or a PR workflow to be correct, and gating a one-line security fix (task 008) or a fix to a fully broken target (task 003) behind CI plumbing inverts the priority order. The only gate those tasks inherit is "the existing Core suite passes before and after your change" — which they each run themselves. Run this task in parallel with, or after, tasks 008/003/002.

The OneID authentication package is production-used and targets net48 and net8.0. Its existing xUnit project targets net9.0 and selects the Core library implementation. Core coverage must never be labeled as Framework coverage.

## Evidence and conventions

`tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj`:

```xml
<TargetFramework>net9.0</TargetFramework>
<PackageReference Include="coverlet.collector" Version="6.0.4">
```

`.github/workflows/main.yml` has `push: branches: [ master ]`, SDK `8.0.401`, and NuGet publishing after tests. `global.json` requests SDK 9.0.305 with latestPatch roll-forward. Never add a PR trigger to this release workflow without isolating publish steps; this task instead adds a separate validation workflow.

**Known latent issue, deliberately out of scope for this task:** `main.yml` pins `DOTNET_VERSION: '8.0.401'` and calls `actions/setup-dotnet@v4` with it, while `global.json` requests `9.0.305` with `latestPatch` roll-forward. `latestPatch` will not roll forward from 8.0.x to 9.0.305, so the release workflow succeeds only because `windows-latest` happens to preinstall a 9.0.x SDK alongside the one it installs. That is luck, not configuration. Do **not** fix it here — changing the release workflow is out of scope and a mistake there publishes packages. Record it in `BASELINE.md` as a known risk and leave it for a separately scoped change. Your new `validation.yml` must not repeat the mistake: give `setup-dotnet` the `global-json-file` input rather than a hardcoded version.

`tests/AspNet.Security.OAuth.OneID.Tests/OneIDTests.cs:32` skips the sign-in theory. `tests/AspNet.Security.OAuth.OneID.Tests/Infrastructure/OAuthTests.cs:79,106` skip creating-ticket integration tests. `tests/AspNet.Security.OAuth.OneID.Tests/TokenTests.cs:7` is a skipped manual production test: leave it skipped.

Tests use xUnit attributes and Assert/Shouldly. Project files use PackageReference. Match `OneIDAuthenticationOptionsTests.cs` for straightforward tests; do not add implementation-mirroring tests just to inflate coverage. No successful test execution has been established by the advisor. Existing obj restore assets were stale.

## Scope

May edit/create:

- `.github/workflows/validation.yml` (new; separate from release).
- `tests/coverage.runsettings` (new, only if needed for collector configuration).
- `tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj` only for test/coverage setup needed to run existing tests.
- `README.md` for exact local test/coverage instructions and known target limits.
- `codebase-analysis-docs/assets/test-results/` for baseline reports; standard bin/obj build artifacts remain ignored.
- This task's status and `codebase-analysis-docs/IMPLEMENTATION_PLAN.md`.

Out of scope: all runtime source, sample apps, existing test expectations, skipped tests, main release workflow, dependency automation, coverage thresholds, new live credentials or tokens.

## Drift and Git rules

Run `git status --short`, then `git diff --stat 777d721..HEAD -- .github/workflows tests README.md global.json`. Compare changed files against evidence above and any user edits. Do not discard changes. No push, commit, remote branch or publication is authorized.

## Steps and gates

1. Run `dotnet --version`, then `dotnet restore tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj`. Expected: selected SDK honors global.json; restore exits 0 and the test assets include net9.0. Restore is mandatory before --no-restore. If permissions/network block execution, use the normal approval mechanism; do not bypass sandbox restrictions. Record a blocker if permission is unavailable.
2. Run `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj --no-restore --logger "trx;LogFileName=baseline.trx" --results-directory codebase-analysis-docs/assets/test-results/baseline`. Expected: runner completes and produces TRX. Record actual passed/failed/skipped totals. A test failure is a baseline finding, not authorization to weaken tests or repair production code; stop and report it for a separately scoped repair before implementing CI intended to pass.
3. Run `dotnet test tests/AspNet.Security.OAuth.OneID.Tests/AspNet.Security.OAuth.Providers.Tests.csproj --no-restore --collect "XPlat Code Coverage" --results-directory codebase-analysis-docs/assets/test-results/coverage`. Expected: exit 0 and a nonempty `coverage.cobertura.xml`. Keep library namespaces in scope; exclude test assemblies/generated files only when clearly labeled. Record the **library package's** line/branch hit and total counts, not aggregate test-assembly statistics. Do not edit files to increase the number.
4. Run `dotnet build src/AspNet.Security.OAuth.OneID/AspNet.Security.OAuth.OneID.csproj -c Release`. Expected: both net48 and net8.0 outputs, exit 0. A Windows runner is needed for the later Framework runtime tests. Build failures are blockers, not a reason to drop a target or disable warnings-as-errors.
5. Add `validation.yml` for pull_request targeting master and manual workflow_dispatch, read-only repository permissions, windows-latest runner, checkout and setup-dotnet honoring global.json. Use existing setup-dotnet@v4's supported global-json input (verify its action metadata if uncertain). Restore the explicit library/test projects; build library Release; test existing project with Release configuration, TRX and XPlat coverage. Upload reports even on test failure, but retain a failed job when tests fail. There must be no NuGet push, release creation, deployment or write token in this workflow. Gate: `Get-Content .github/workflows/validation.yml` and `git diff --check` → expected triggers/commands present, no whitespace errors. Document that actual hosted workflow execution is not verified until a later authorized PR/run.
6. Write `codebase-analysis-docs/assets/test-results/BASELINE.md` containing timestamp, commit, SDK, exact commands, test counts, library-only line/branch counts and rates, report paths and net48 runtime coverage marked “not measured.” Update README with the runnable command. Gate: `[xml]$report = Get-Content <actual-cobertura-path>` in PowerShell → parses successfully; every reported count must match the selected library package in XML. Use the actual generated path, not a literal placeholder.

## Acceptance checklist

- [ ] Restore, baseline tests, coverage tests and dual-target Release build exit 0.
- [ ] TRX counts are quoted accurately; skipped live/incomplete tests remain explicit.
- [ ] Cobertura XML exists and includes the OneID library; branch and line denominators are recorded.
- [ ] Framework runtime coverage is explicitly not measured, rather than 0% or assumed equal to Core.
- [ ] PR validation workflow cannot publish and does not change the release workflow.
- [ ] `git diff --check` exits 0; `git status --short` contains only scoped edits plus pre-existing user changes and expected artifacts.

## Stop conditions and maintenance

Stop on a baseline failure requiring out-of-scope edits, missing compatible SDK/reference assemblies, unexplained source drift, or a collector producing no library instrumentation after one configuration correction. Do not invent a result or threshold. Later task 007 must add Framework reporting separately; the first percentage is only a Core baseline.
