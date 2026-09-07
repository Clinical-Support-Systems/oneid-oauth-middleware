# Task 006 — Resolve deployment-sensitive integration contracts before implementation

## Status and objective

TODO; P1 design gate; medium effort; documentation only. Planned at `777d721`, 2026-09-07. No prerequisite to begin; incorporate actual results from tasks 001–003 when available. **This is a bounded investigation handoff, not permission to change code.** Produce concrete accepted/deferred decisions and narrower follow-up implementation plans where evidence is sufficient.

The project is production-used. We do not know the deployed version/target or custom transports/events. The inspected default paths contain conflicts; guessing provider endpoints or tightening every customizable setting could break a functioning integration.

## Evidence to reread

- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetFull.cs:542` fetches JWKS through `_httpClient`; line 560 sets `ValidateIssuer = !string.IsNullOrWhiteSpace(callbackIssuer)`.
- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationBackChannelHandler.cs:SendAsync` throws if request.Content is null.
- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationMiddleware.cs` creates the shared client from that handler and installs a public factory.
- `src/AspNet.Security.OAuth.OneID/Provider/OneIdAuthenticationHandlerFactory.cs` and the public two-argument Framework handler constructor expose extension compatibility boundaries.
- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationPostConfigureOptions.cs` deliberately uses plain factory HTTP for Core discovery; useful architecture reference, not an instruction to copy Core DI into Katana.
- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationOptions.cs:UpdateEndpoints` normalizes most production endpoints but not Authority.
- `src/AspNet.Security.OAuth.OneID/OneIdHelper.cs` reconstructs refresh/end-session URLs, includes special dev/QA end-session ports, and hardcodes PST revocation.
- `src/AspNet.Security.OAuth.OneID/OneIdAuthenticationHandler.NetCore.cs:CreateTicketAsync` calls the validation event and maps claims/session; its property saving adds tokens without removing base-saved tokens. Verify resolved OAuthHandler behavior before defining a new filtering contract.
- `src/ConsumerApp.Kestrel/Startup.cs` and `src/ConsumerApp.Kestrel/Pages/Index.cshtml.cs` illustrate separate options instances and per-user storage mistakes; they do not prove the actual deployed host uses them.

## Scope and constraints

Only create/edit `codebase-analysis-docs/assets/INTEGRATION_DECISIONS.md`, future handoffs under `codebase-analysis-docs/assets/plans/`, and task/index status. Read source, local package metadata and relevant existing docs. No code edits, package install, live credential inspection, provider requests using credentials, deployments or workflow triggers. If the provider PDF is needed, use the PDF skill and record exact pages; do not infer it was already verified.

Drift gate: `git status --short`; `git diff --stat 777d721..HEAD -- src/AspNet.Security.OAuth.OneID src/ConsumerApp.Kestrel`. Account for completed task changes and describe which source facts still apply. Preserve user changes; no push/commit/release.

## Steps and verification gates

1. Inventory nonsecret deployment facts available from repository/version history. Identify installed runtime/framework/version only if supported by evidence; otherwise ask the owner one bundled question for deployed package version, Core versus Katana, and whether custom backchannel/factory/validator overrides are used. Never request certificate passwords, private keys or tokens. Gate: `Get-Content codebase-analysis-docs/assets/INTEGRATION_DECISIONS.md` → a provenance table labels each item owner-confirmed, repository-confirmed, inferred or unknown. Unknown deployment facts may block a release decision without blocking source-only design work.
2. Specify Framework discovery transport ownership and trusted issuer validation. Required design properties: bodyless metadata/JWKS GET uses a plain transport; token POST retains certificate assertions; expected issuer comes from trusted configuration/discovery rather than callback input; callback iss may only be compared with that trusted value. Define cache/client lifetime, disposal, cancellation, discovery failure and key-refresh behavior; preserve existing public constructor/factory signatures using additive APIs or an internal adapter. Gate: the decision document lists each public signature affected, selected lifetime owner and at least seven synthetic integration cases (valid callback, missing/wrong callback iss, bad issuer/audience/signature, metadata/JWKS failure). If several designs remain viable, give a recommendation and record approval needed before producing an implementation-ready task.
3. Build a four-environment endpoint matrix for authority, authorize, token, assertion audience, issuer, metadata/JWKS, user info, end-session and revoke. Label repository-generated URL versus provider-verified URL; distinguish API audience from ID-token audience and assertion audience. Do not silently normalize dev/QA ports or invent production revocation. Define precedence for Environment, explicitly overridden endpoints and discovery values, including refresh's existing behavior. Gate: decision document has four environment rows and explicit unknowns, plus one chosen override-precedence rule or a named unresolved decision for each public option.
4. Inspect the locally resolved ASP.NET Core OAuthHandler callback code or official source matching its resolved version. Establish when SaveTokens populates properties relative to CreateTicketAsync. Specify independent session and ticket retention semantics; name how custom flags interact with inherited token_type/expires_at, external cookie and final application cookie. Gate: record exact framework version/source and a test matrix covering SaveTokens true/false, each selected token flag, session present/absent and host sign-in transition. No guessed blanket claim that flags fully control inherited persistence.
5. Write narrow follow-up plans only for decisions supported by evidence, with concrete files, compatibility notes, before/after tests and runtime acceptance gates. Mark provider-dependent unknowns BLOCKED with the missing fact. Gate: `git diff --check` exits 0 and `git status --short` shows only documentation changes beyond pre-existing work. Task is DONE when investigation outputs are complete; individual resulting implementation decisions can remain deferred/blocked explicitly.

## Acceptance checklist

- [ ] Source defects are not called production incidents without deployment evidence.
- [ ] Framework design separates signing transport and discovery, establishes trusted issuer source and names lifetime/disposal owners.
- [ ] No existing public factory/handler customization is silently broken.
- [ ] Endpoint matrix records environment differences and unknown provider facts.
- [ ] Storage proposal cites actual resolved framework behavior and specifies a full-callback test matrix.
- [ ] Follow-up plans are implementation-ready where possible, otherwise explicitly blocked rather than guessed.
- [ ] No runtime/test/project/workflow source edited.

## Stop conditions and maintenance

Stop dependent design work when provider facts cannot be verified or a public contract requires owner choice. Continue independent sections. Never relax issuer checks, put assertions on arbitrary discovery requests or remove target support to eliminate uncertainty. This gate exists to keep a cheaper executor from improvising on production authentication contracts.
