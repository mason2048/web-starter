# `releaseRuntimeTestReports` evidence adapter

This adapter turns three private, candidate-bound test reports into one
canonical summary. The formal release workflow and both release-evidence gate
passes consume the private raw bundle and independently recompute this summary;
only the canonical summary is uploaded.

## Fixed coverage

The Playwright JSON report must contain exactly the twenty tests declared by:

- `web-starter-web/e2e/release-runtime.spec.ts` — seven tests.
- `web-starter-web/e2e/frontend-quality-runtime.spec.ts` — four tests.
- `web-starter-web/e2e/v1-management-runtime.spec.ts` — nine tests for
  `AC-06` through `AC-14`.

Every title and resolved source file must match the committed test source. The
Playwright `config.rootDir` and sole project `testDir` must both resolve to the
candidate's fixed `web-starter-web/e2e` directory; reporter file basenames are
resolved relative to that directory, matching the Playwright 1.61 JSON format. Each
test must have `expectedStatus=passed`, one passing result, retry `0`, and no
annotations, errors, stdout, stderr, or diagnostic attachments. The aggregate
report must say `expected=20`, `skipped=0`, `unexpected=0`, and `flaky=0`.

The two Surefire inputs have fixed filenames and identities:

- `McpSdkRuntimeIT#initializesDiscoversReadsAndCallsThroughTheOfficialSdk`
- `McpSdkProjectListRuntimeIT#projectListWorksWhileProjectCreateIsDenied`

Each XML must contain exactly one test and zero failure, error, skip, flake,
retry, or rerun evidence. Additional raw files or reports are rejected.

Titles and method names alone are not behavioral identity. The validator keeps
reviewed SHA-256 constants for all three Playwright specs, both Java SDK integration
tests, `playwright.config.ts`, and `McpRuntimeToolExpectations.java`. A
legitimate behavior change requires explicit review and a simultaneous update
to those constants and the drift tests; candidate-supplied `sources` hashes do
not authorize the change.

## Acceptance mapping

The adapter is registered only for these frozen baseline rows:

| Acceptance | Exact support from the fixed 20+2 run |
|---|---|
| `AC-03` | Wrong credentials and a nonexistent account both receive the same generic 401; a correct password creates the HTTP-only `WEB_STARTER_SESSION`, the same browser context successfully reads `/api/auth/me`, and fixed Trace IDs read back exactly one sanitized SUCCESS and FAILURE login audit |
| `AC-04` | Two real browser Sessions are independently visible; targeted revocation invalidates the other Session, ordinary logout invalidates a replay of the original Cookie, and disabling a user makes the already-authenticated browser's next `/api/auth/me` return 401 without reviving after re-enable. The gate additionally requires the Redis-loss rehearsal to prove that an authenticated Session has Redis data and that clearing the isolated Redis database invalidates its old Cookie |
| `AC-05` | A reviewed matrix is independently regenerated from all eleven Web controllers plus the Spring Security logout endpoint. Its 36 write routes each return 403 for both an absent and an incorrect CSRF header; anonymous login creates no Session, every authenticated probe leaves `/api/auth/me` usable, and exact before/after snapshots of nine management domains plus the Session count remain unchanged, for exactly 72 rejected write attempts |
| `AC-06` | The browser creates a user with an assigned role, edits and disables it, re-enables it, resets its password, proves a new browser can log in with the reset password, deletes it, and reads back exact create/update/reset/delete operation audits |
| `AC-07` | Role creation assigns the exact Project list permission and Project menu, stale-version update returns 409, an assigned user initially reads Projects, and withdrawing the role permissions makes that already-authenticated user's next request return 403 before the role is deleted |
| `AC-08` | Self-delete and self-disable are rejected, the built-in administrator role cannot be deleted, disabled, or stripped of permissions/menus, and after a second administrator disables the owner the remaining administrator cannot surrender the last effective administrator assignment |
| `AC-09` | Withdrawing only the Project menu removes the visible navigation and sends direct browser navigation to the 403 page, while the separately retained list permission still permits the Project API |
| `AC-10` | A user with Project list but without Project create sees no create button; a manually issued create request still returns 403 and creates no Project |
| `AC-11` | Permission codes are unique, a temporary permission can be disabled and filtered by status, an assigned built-in permission cannot be deleted, and the unassigned temporary permission can be removed |
| `AC-12` | A non-sensitive configuration is created, edited, rendered and deleted through the browser; password, secret, token, credential and private-key-like keys are rejected without echoing or persisting their supplied values |
| `AC-13` | Project list paging, the 200-row size cap, keyword and status filtering, API detail, and the corresponding browser list/detail interaction are exercised against three real rows |
| `AC-14` | Project create/update/delete is exercised with case-insensitive code uniqueness, request validation, optimistic-version conflict, and post-delete list/detail absence proving logical deletion behavior |
| `AC-25` | Official SDK `initialize`, protocol identity, and subsequent session requests |
| `AC-28` | `prompts/list`, `project.summary`, hostile business text marked untrusted, followed by still-controlled Tool calls |
| `AC-30` | Official SDK `tools/list` is exactly the seven fixed Tool names and `unknown.tool` is rejected |
| `AC-32` | One authenticated browser context creates and safely cleans up user, role, menu, config, Project, personal token, service account, and OAuth Client resources; every unique Trace ID reads back exactly one complete operation audit with actor, resource, success result, non-negative duration, and redacted detail |
| `AC-35` | Real login plus all twelve frozen management surfaces; eight create/issue/register forms open and cancel safely, while all three audit pages execute real filtered refreshes |
| `AC-36` | Desktop and 390px operation plus loading, empty, validation, 401, 403, 409, and 500 feedback |
| `V2-AC-21` | URL query/page synchronization and the fixed UI-state/error/Trace matrix |
| `V2-AC-19` | Reviewed OpenAPI/type drift sources plus public-ingress 404 probes; the gate additionally requires the same candidate's passing frontend build layer |
| `V2-AC-20` | Project standard CRUD and the typed navigation projections; the gate additionally requires generator acceptance and the same candidate's passing frontend layer |
| `V2-AC-22` | Desktop/tablet/390px operation, keyboard focus and basic accessibility; the gate additionally requires the reviewed bundle-budget chain and passing frontend build |
| `V2-AC-23` | Current-password change, active sessions, targeted/other-device exit, and self-elevation denial |
| `V2-AC-25` | Account-plus-source progressive login protection without account enumeration or unrelated-account blocking |
| `V2-AC-30` | Credential lifecycle filters and no second display of one-time secrets |
| `V2-AC-39` | Login/operation/MCP filters, same-Trace correlation, and redacted display; the gate also retains the V1-upgrade evidence binding |

`AC-30` is limited to the exposed Tool identity set observed through the
official SDK. It does not claim that arbitrary implementations are safe merely
because they use an allowed name. The release also keeps the separate exact
Tool-contract proof for schema and annotation behavior.

For V2-AC-19/20/22 the validator also binds reviewed source hashes for the
OpenAPI renderer and generated TypeScript, bundle-budget checker, standard CRUD
foundation, Project page, typed navigation projections, their unit tests, and
the exact `DeveloperCommands` frontend quality chain. It independently rerenders
the private OpenAPI types, checks the exact Project operation inventory, fixed
bundle limits and navigation/CRUD projections. Those rows are accepted only
when the same release also supplies `unifiedVerify`, digest-bound runtime
identity and runtime acceptance; V2-AC-20 additionally requires the independent
generator canonical evidence. The browser test uses the public HTTPS ingress to
require 404 for OpenAPI and Explorer candidate paths.

This adapter does **not** establish the other V1 rows or the full 42-row V1
regression. It does not independently prove token expiry/revoke, every
Tool/permission/error combination, negative `system:info`, bundle budget, the
complete security matrix, empty-volume migration, Client Credentials, PAT
public-ingress denial, recovery, or supply-chain controls. Those rows retain
their own evidence or a non-PASS status.

## Private bundle contract

Capture the nanosecond start time before launching the three test commands.
Place only these files in an owned directory outside the repository:

```text
playwright-release-runtime.json
TEST-dev.webstarter.mcp.acceptance.McpSdkRuntimeIT.xml
TEST-dev.webstarter.mcp.acceptance.McpSdkProjectListRuntimeIT.xml
```

The directory must be mode `0700`; each file must be mode `0600`, regular,
single-link, and newer than the captured start. The producer opens all inputs
with `O_NOFOLLOW`, checks them before and after validation, and atomically adds
`release-runtime-test-reports-proof.json`. The proof contains hashes and
candidate identity only—never a reported status.

For a clean annotated `v2.0.0` candidate, the standalone interfaces are:

```bash
python3 -B scripts/create_release_runtime_test_reports_proof.py \
  --repository-root <clean-candidate-root> \
  --evidence-directory <private-raw-directory> \
  --candidate-commit <candidate-commit> \
  --candidate-version 2.0.0 \
  --candidate-tag v2.0.0 \
  --run-started-at-epoch-ns <captured-start>

python3 -B scripts/validate_release_runtime_test_reports_proof.py \
  --repository-root <clean-candidate-root> \
  --evidence-directory <private-raw-directory> \
  --expected-candidate-commit <candidate-commit> \
  --expected-candidate-version 2.0.0 \
  --expected-candidate-tag v2.0.0 \
  --expected-run-started-at-epoch-ns <captured-start> \
  --require-pass \
  --summary-output <empty-private-summary-directory>
```

The validator independently reopens and reparses every raw file, verifies the
clean annotated non-SNAPSHOT commit/tree/tag/version, rechecks candidate and
raw-file identity for drift, and writes the summary with `O_EXCL`. The summary
contains only fixed test identities and SHA-256 values and conforms to
`security/release-runtime-test-reports-summary.schema.json`.

The release runtime runner now supports this adapter behind the strict
`WEB_STARTER_RUN_RELEASE_RUNTIME_TEST_REPORTS_FORMAL=true` switch. In that mode
it rejects ambient `WEB_STARTER_MCP_EXPECTED_ADDITIONAL_TOOLS` and
`WEB_STARTER_MCP_EXPECT_PROJECT_LIST_DENIED`, clears them in each fixed SDK
subprocess, and pins the denial toggle to `false`. This prevents a caller from
expanding the seven-Tool expectation or switching the low-privilege assertion.
The detached candidate installs from the already-populated pnpm store with
`pnpm install --frozen-lockfile --offline`; preflight requires its local
Playwright executable and installed package to be exactly 1.61.1. A stale
public canonical summary is rejected in both formal and non-formal modes.

The runner captures the reports in an independent `${RUNNER_TEMP}` mode `0700`
directory, invokes the producer and validator from the clean candidate, and
publishes only the byte-identical mode `0600` canonical summary. The gate's
`build` and `verify` calls both reopen the raw bundle, rerun the validator,
compare exact canonical bytes, and bind report/source digests plus candidate
commit/tree/tag/version. Every mapped PASS additionally requires the same
job's digest-bound `runtimeVersionIdentity` and `releaseRuntimeAcceptance`;
the summary alone is not a self-sufficient image/runtime claim.

`AC-08` deliberately disables and re-enables the release owner, advancing that
identity's security epoch and permanently invalidating PATs issued before the
test. The runner must not reuse its initial read PAT after the browser phase.
It instead authenticates the re-enabled owner through the public TLS login,
uses the resulting Web Session only through the loopback private ingress to
issue a new PAT with exactly `system:info`, `project:list`, and `audit:list`,
and writes the one-time plaintext only to
`${RUNNER_TEMP}`-backed `pat-read-refreshed.json`. The credential directory is
an owned real mode-`0700` directory outside the repository; the manifest and
new token file are owned, single-link mode-`0600` regular files. The token is
never printed or returned by the list endpoint. This refreshed PAT feeds the
later private `McpSdkProjectListRuntimeIT`; the invalidated pre-`AC-08` PAT
remains unusable.

The seven-layer verifier must not execute the stateful 20+2 suite a second
time: a repeat `AC-08` would revoke the fixture PATs and make the credential
lifecycle filter no longer describe its frozen initial state. In formal mode,
its browser and MCP layers independently rerun this validator against the same
private raw bundle and candidate identity instead. After the browser proof is
revalidated, the verifier reauthenticates the owner and issues another exact
read-scope PAT to the separate private `pat-read-unified.json` file. The OAuth
layer uses that post-lifecycle credential for its private/public PAT boundary;
the MCP layer revalidates both official SDK reports and the separately bound
CRUD transaction proof without rerunning either SDK test.
