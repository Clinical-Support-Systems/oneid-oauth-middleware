# OneID library improvement execution plan

Written against commit `777d721`, 2026-09-07; revised 2026-09-07 after a plan review (see Revision note below). **Status: planning complete; implementation not started.**

This package is used in production. The deployed package version, Core/Katana target and application overrides are unknown. Preserve both `net48` and `net8.0` and existing successful consumer behavior. Findings describe this checkout, not confirmed production incidents.

These handoffs follow the structure of the [shadcn/improve skill](https://github.com/shadcn/improve/blob/main/skills/improve/SKILL.md): independent tasks, evidence, commands, scope and stop conditions. The user's documentation location requirement takes precedence over the skill's default `plans/` location. No skill installation, implementation, build, test or release is part of this planning deliverable.

## Execution order

All paths below are relative to the repository root. Each task is self-contained. Read one task completely before changing anything. Work in the order given in the table. Tasks 008 and 003 touch disjoint files and may run in either order, but every other pair shares files; do not assign two of them concurrently to independent executors.

| ID | Handoff | Priority | Effort | Change risk | Prerequisites | Status |
|---|---|---|---|---|---|---|
| 008 | `codebase-analysis-docs/assets/plans/008-remove-seeded-signing-key.md` | **P0** | S | Low | None | **DONE / MERGED** — commit `4e09a2b` on `master`, 2026-09-07. Executed in a worktree, reviewed, then applied to master at the owner's instruction. Not pushed. |
| 003 | `codebase-analysis-docs/assets/plans/003-katana-state.md` | **P0** | S | Low | None | **DONE / MERGED** — commit `aed06c1` on `master`, 2026-09-07. Not pushed. Verified by review + dual-target build only; no automated regression until task 007. |
| 002 | `codebase-analysis-docs/assets/plans/002-core-validation.md` | P1 | M | High | 008 | TODO |
| 007 | `codebase-analysis-docs/assets/plans/007-netfull-test-project.md` | P1 | M | Low (test-only) | 003 | TODO |
| 006 | `codebase-analysis-docs/assets/plans/006-integration-design-decisions.md` | P1 design gate | L | Documentation only | May run first; consume 002/003/007 evidence when available | TODO |
| 001 | `codebase-analysis-docs/assets/plans/001-test-baseline-and-ci.md` | P2 | M | Low | None; **gates nothing** | TODO |
| 004 | `codebase-analysis-docs/assets/plans/004-options-consistency.md` | P2 | S | Medium | 008, 002, 007 | TODO |
| 005 | `codebase-analysis-docs/assets/plans/005-typed-refresh.md` | P2 | M | Medium | 007 | TODO |

Recommended sequence: **008 → 003 → 002 → 007 → 004 → 005**, with 001 and 006 running in parallel at any point. Complete 006 before releasing changes to Katana discovery/issuer handling, endpoint contracts or token-persistence behavior.

### Revision note (2026-09-07, plan review)

The original six-plan set was reviewed against the source at `777d721`; every quoted line number and excerpt was confirmed accurate. Four structural changes came out of that review:

1. **Task 008 split out of task 002.** Removing the hardcoded symmetric signing key is one deleted line. It does not need the signed-token test infrastructure that task 002 builds, and should not wait for it.
2. **Task 007 split out of task 003.** Task 003 is now the one-line `Protect` reorder alone; 007 is the net48 test project. Rationale in each file — briefly, the Katana target is currently non-functional and the fix should not wait on a medium-effort test harness. Task 003 ships with verification debt that 007 discharges, and both files say so.
3. **Task 001 no longer gates anything.** It was a prerequisite for 002-005. None of those needs a measured coverage baseline or a PR workflow in order to be correct, and gating a security fix behind CI plumbing inverts the priority order. 001 is now P2 and parallel.
4. **Severity corrections** to the two P0 items, recorded in "Confidence and rejected interpretations" below.

One content error was also corrected: task 005 previously said "do not reuse TokenEndpoint" where it meant `OAuthTokenResponse`. `TokenEndpoint` is a URL option; the sentence was unfollowable as written.

Task numbering is monotonic by creation, not by execution order. Read the table, not the filenames.

## What success means

- Repeatable test commands and real line/branch coverage, labeled by target.
- Signature/issuer/audience/lifetime/nonce tests using ephemeral synthetic keys.
- Executable Framework tests instead of assuming Core coverage covers Katana.
- Options whose observable effects match explicit contracts.
- An additive refresh API exposing rotation and expiry information without breaking the existing method.
- Written decisions for integration behavior that cannot safely be guessed from source alone.

No overall coverage percentage is currently established. Source inspection counted 31 active test-method declarations and four skipped declarations; a theory can represent multiple cases. Earlier coverage execution stopped at .NET first-run permissions; its pending retry was cancelled when the user requested planning only. Existing restore assets were stale (net8.0 assets for a now-net9.0 test project). Treat all command outcomes as unverified until task 001 records them.

## Executor contract

Use a cheaper model for **one numbered handoff at a time**. Do not switch models, dispatch agents, implement other tasks, publish packages or push changes automatically. A higher-capability review is appropriate for authentication trust changes and unresolved design decisions, not routine implementation steps.

For each task:

1. Read `AGENTS.md` and the complete handoff. Check `git status --short`, recorded commit drift and uncommitted changes before editing.
2. Read only the listed files and their required dependencies; do not repeat the repository-wide audit.
3. Record prerequisite outcomes. If a prerequisite changed a quoted section, compare intended prerequisite changes with live code; do not treat every new commit as a failure. Stop on unexplained semantic drift.
4. Implement only listed changes. Match `.editorconfig`, nullable rules and existing xUnit style. Never suppress a failing security assertion or analyzer merely to finish.
5. Run the named tests. For shared/library changes, finish with the dual-target Release build and applicable full suites. Each expected result is a required future outcome, not a claim that it passed during planning.
6. Record changed files, test counts, coverage paths, limitations and any blocker in the task status and index. Mark DONE only after every acceptance criterion passes; use BLOCKED with the exact command/error otherwise.

Use `git diff --check` and `git diff --name-only` as final hygiene checks, accounting separately for newly created/untracked files in `git status --short`. Do not stage, commit, reset, stash or remove someone else's changes. Do not create remote branches, open PRs or trigger releases without a later instruction. README directs PRs to master; pushes there publish packages.

## Paste-ready execution prompt

```text
Implement only codebase-analysis-docs/assets/plans/008-remove-seeded-signing-key.md.
Read that handoff and AGENTS.md first. The plan contains the required context.
Respect its file scope, prerequisites, compatibility rules and stop conditions.
Do not implement other plans, enable live-provider tests, install unrelated tools,
push, publish, or create remote branches. Preserve all pre-existing user changes.
Run its verification gates and report actual outcomes; do not invent a baseline.
Update this task's status in codebase-analysis-docs/IMPLEMENTATION_PLAN.md.
```

Replace only the task filename when moving to the next handoff.

## Deliberately deferred work

| Topic | Reason / next action |
|---|---|
| Broad rewrite or replacing OAuthHandler with OpenIdConnectHandler | Large compatibility change without sufficient regression evidence; not needed for this plan. |
| Universal RS256-only policy on Core | Framework enforces RS256, but the supported Core provider/custom-validator contract has not been verified. Task 002 tests current trust behavior without inventing a new algorithm policy. |
| Automatically retrying signing-key refresh | Requires explicit cache/retry/cancellation semantics; include in task 006 decision, not an incidental validator rewrite. |
| Centralizing every URL immediately | Port differences, Audience versus issuer, custom endpoints and revocation have unresolved compatibility semantics. Task 006 specifies these first. |
| Removing public options/hooks | Could break consumers; deprecations need a migration decision. Do not implement a validation bypass to make ValidateTokens match its name. |
| Authentication-property token filtering | Must first test the full inherited OAuth callback and host external-cookie transition; direct CreateTicketAsync tests are insufficient. |
| Sample token/session/logout overhaul | Static tokens and cleanup deserve a separate host-focused task; do not bundle sample changes into package fixes. |
| Arbitrary coverage target such as 80% | Establish honest target-specific baseline and scenario coverage first. A percentage cannot replace negative authentication tests. |
| Dependency/package upgrades | Align only what is required for test compatibility; broad upgrades and automated dependency workflow changes need separate scope. |
| Release-workflow SDK mismatch | `.github/workflows/main.yml` pins `DOTNET_VERSION: '8.0.401'` while `global.json` requests `9.0.305` with `latestPatch` roll-forward, which cannot cross from 8.0.x to 9.0.305. The workflow succeeds only because `windows-latest` preinstalls a 9.0.x SDK alongside the one it installs — luck, not configuration. Not fixed by any current task: editing the release workflow risks publishing packages. Task 001 records it in `BASELINE.md` and its new `validation.yml` must use `setup-dotnet`'s `global-json-file` input instead. Needs a separately scoped change. |

## Confidence and rejected interpretations

- High confidence: the test target does not execute NETFULL, integration tests are skipped, profile assignment only adds scopes, refresh discards response fields, and Katana protects state before adding verifier/nonce.
- **Corrected upward (2026-09-07 review): the seeded symmetric key is a live defense-in-depth failure, not merely a configuration smell.** `OneIdTokenValidator.cs:135` clones `TokenValidationParameters` — which copies the singular `IssuerSigningKey` — and then sets only the plural `IssuerSigningKeys` from JWKS. `TokenValidationParameters.GetAllSigningKeys()` returns the union of both, and no `ValidAlgorithms` restriction exists on the Core path, so an HS256 token signed with that key is an accepted candidate. The key is not secret: this repository is public and the literal ships inside the published NuGet assembly regardless. What is lost is the guarantee that signature validation provides any assurance in the default configuration. Practical exploitation still requires controlling the backchannel token response, so this is **not** a remote bypass — do not describe it as one in commit messages, issues or release notes. Task 008 removes it; task 002 proves the resulting behavior with tests. Never reproduce the key value.
- **Corrected upward (2026-09-07 review): the Katana state-ordering defect is total breakage of the net48 sign-in flow, not a subtle ordering issue.** `Protect` runs at `NetFull.cs:433`, before the verifier (437) and nonce (443) are written, so neither ever reaches the round-tripped state; the callback at `NetFull.cs:157` then throws unconditionally. Introduced in `7285bbe`, the newest commit on that file. This describes the checkout, not any deployed consumer — a consumer on an earlier package version or on the net8.0 target is unaffected.
- Rejected: “production is broken.” Deployed version, target and overrides are unknown.
- Rejected: “no tests” or “no coverage tooling.” Tests and Coverlet exist; measured coverage and sufficient scenario coverage are different questions.
- Rejected: “all CI lacks PR checks.” CodeQL has a PR trigger; the main build/test/release workflow does not.
- Rejected: “changing ValidateTokens to false should disable checks.” That would weaken current behavior and contradict an existing regression test.

This planning pass does not audit live deployment, provider availability, external credential provisioning, applied databases or external package advisories. It reuses direct source analysis and scopes further work to the library and test infrastructure.
