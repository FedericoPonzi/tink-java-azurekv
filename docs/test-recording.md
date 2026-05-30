# Recording and replaying Azure Managed HSM tests

The fast unit tests (`./gradlew test`) use an in-memory fake and never touch Azure.
They cover the ciphertext framing and URI parsing, but they cannot prove that the
request we send is one Azure actually accepts, nor that we parse a real response
correctly.

To close that gap without paying for an HSM on every CI run, we use a **record /
replay** integration test:

1. **Record once** against a real Managed HSM. The HTTP traffic is captured to a JSON
   file under `src/integrationTest/resources/session-records/`.
2. **Replay forever** offline from that committed recording — no Azure, no cost.

> **What RECORD validates:** the real Key Vault *wire contract* — that the request we
> build is accepted, and that we correctly read the `iv`, `tag` and ciphertext out of a
> genuine response.
>
> **What PLAYBACK validates:** that the current code still produces the *same* request
> bytes as the committed recording and still parses that recorded response. It is a
> regression guard against our code, **not** a check against Azure: a recording cannot
> detect Azure changing its API — re-record for that (see §5).
>
> **What neither validates:** cryptography. AES-GCM runs server-side with a
> server-chosen IV; on replay we just hand back the recorded ciphertext. Verifying
> AES-GCM is Azure's job, not this library's.

The integration test lives in an isolated `integrationTest` source set and is **never
part of `./gradlew build`**. It only runs when you invoke `./gradlew integrationTest`,
and without a committed recording the round-trip test simply **skips**.

## Why a custom client and not the Azure test proxy?

`azure-core-test`'s `TestProxyTestBase` resolves recordings relative to an `eng/` folder
inside a repository named `azure-sdk-for-java`; outside that monorepo it throws. So this
repo ships a tiny self-contained VCR, `RecordingHttpClient`, plugged into the SDK via
`CryptographyClientBuilder.httpClient(...)`. It needs no extra dependencies beyond
`azure-core` + `azure-json`, which are already on the classpath.

Its mechanics (sequential replay, sanitized matching, response synthesis) are covered by
the offline `RecordingHttpClientTest`, which always runs under `./gradlew integrationTest`.

---

## 1. Prerequisites

- An **Azure Managed HSM** (AES-GCM keys do not exist on the standard Key Vault tier).
- An **AES-256 key** (`oct-HSM`, 256-bit) created on that HSM, with the `encrypt` and
  `decrypt` permissions granted to your identity.
- Logged-in credentials that `DefaultAzureCredential` can pick up (e.g. `az login`, or
  `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`).
- A **versioned** key identifier (`.../keys/<name>/<version>`). The version is required so
  the sanitizer can rewrite the key path unambiguously; recording without one is rejected.

### Creating a throwaway HSM (cost note)

Managed HSM bills **per hour**, not per operation, so the cheapest path is: create it,
record, then delete it.

```bash
az keyvault create --hsm-name <hsm> --resource-group <rg> --location <region> \
  --administrators <your-object-id> --retention-days 7
# ... activate the HSM with the downloaded security domain ...
az keyvault key create --hsm-name <hsm> --name testkey --kty oct-HSM --size 256 \
  --ops encrypt decrypt
# when finished recording:
az keyvault delete --hsm-name <hsm>
az keyvault purge   --hsm-name <hsm>   # stops further billing
```

---

## 2. Record

```bash
export AZURE_TEST_MODE=RECORD
export AZURE_MANAGED_HSM_KEY_ID="https://<hsm>.managedhsm.azure.net/keys/testkey/<version>"
./gradlew integrationTest
```

This calls the live HSM (one `encrypt` + one `decrypt`, plus the initial auth-challenge
`401`) and writes
`src/integrationTest/resources/session-records/AzureKeyVaultAeadIT.encryptThenDecrypt_roundTrips.json`.

Recording fails fast if anything other than `POST .../encrypt` or `POST .../decrypt` with
status `200`/`401` is captured, so unexpected traffic is surfaced before you commit.

---

## 3. What gets stripped (and what does not)

Sanitization is configured in `AzureKeyVaultAeadIT.SANITIZERS` and applied **at record
time** to URLs, request/response bodies and the allow-listed headers. (The same
sanitizers also run on incoming requests during playback, which is what lets the synthetic
playback identifier match the recording.)

| Sanitizer / rule | What it removes |
|------------------|-----------------|
| `Authorization` dropped; only `Content-Type` + `WWW-Authenticate` are recorded | Bearer tokens and every other header (incl. `x-ms-*`, `Date`, `Content-Encoding`, `Content-Length`). |
| URL/body: `[A-Za-z0-9-]+\.managedhsm\.azure\.net` → `myhsm.managedhsm.azure.net` | Your HSM name in request URLs **and** in the response `kid`. |
| URL/body: `(?<=/keys/)[^/?"]+/[^/?"]+` → `testkey/testversion` | Your key name and version in request URLs **and** in the response `kid`. |
| Any header/body/URL GUID → `00000000-…-000000000000` | Tenant/object IDs (e.g. the authority in `WWW-Authenticate`). |

**What intentionally remains in the recording:** the algorithm (`A256GCM`) and the
base64url `value`/`iv`/`tag` fields. These are ciphertext and a nonce — not secret, and
not the key. The AES key material never leaves the HSM, so it is never in the traffic.

> ⚠️ **Always eyeball the JSON before committing.** Confirm no real hostname, tenant ID,
> object ID, or bearer token survived. The first recording in particular should be
> reviewed by hand — sanitizers only cover what we anticipated. Quick checklist:
>
> - `grep` the file for your real HSM name, key name, tenant GUID and object GUID — none
>   should appear.
> - The only headers present should be `Content-Type` and `WWW-Authenticate`.
> - `WWW-Authenticate` should contain no real tenant GUID (it is zeroed).

---

## 4. Replay (offline, free)

Once the recording is committed, the default mode is PLAYBACK:

```bash
./gradlew integrationTest
```

The test uses a static, no-network token credential and the synthetic key identifier
`https://myhsm.managedhsm.azure.net/keys/testkey/testversion`, which matches the sanitized
recording. Interactions are replayed strictly in order and matched on method, path, query
and request body, so a regression in the bytes we send fails the test. No network calls
are made.

To run it in CI, add a job that runs `./gradlew integrationTest` (it stays out of the
default `build`, so contributors without recordings are never blocked — the round-trip
test just skips).

---

## 5. Re-recording / drift

Playback cannot detect Azure changing its API or the SDK changing the bytes it emits.
Re-record by repeating §2 — in particular whenever the `azure-security-keyvault-keys` /
`azure-core` versions or `api-version` change — then review and commit the updated JSON.
