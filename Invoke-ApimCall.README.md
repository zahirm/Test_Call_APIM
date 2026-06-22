# Invoke-ApimCall.ps1

A tiny PowerShell CLI for testing an **Azure API Management (APIM)** endpoint and getting a
**plain-language diagnosis** of what went wrong — instead of a cryptic status code or a raw
TLS error.

It was built to triage common APIM failure modes: certificate-chain errors, 401/403 token
problems, and "POST doesn't show up in the logs" routing issues.

> Requires **PowerShell 7+ (pwsh)** — it uses `-SkipHttpErrorCheck` and `-SkipCertificateCheck`.

---

## What it does

1. Sends your request (any method, optional body, subscription key, bearer token, custom headers).
2. Decodes the bearer token up front and shows `aud`, `roles`, `scp`, `exp` (and flags expiry).
3. Interprets the result and prints a **DIAGNOSIS** section that maps the symptom to a likely cause.

---

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-Url` | Yes | Full APIM request URL. |
| `-Method` | No | HTTP method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`). Default `GET`. |
| `-SubscriptionKey` | No | Sets the `Ocp-Apim-Subscription-Key` header. |
| `-Token` | No | Bearer token. A leading `Bearer ` is optional (it gets stripped/normalised). |
| `-Body` | No | Request body string (used for `POST`/`PUT`/`PATCH`). |
| `-ContentType` | No | Body content type. Default `application/json`. |
| `-Headers` | No | Hashtable of extra headers, e.g. `@{ "x-correlation-id" = "abc" }`. |
| `-Trace` | No | Adds `Ocp-Apim-Trace: true` and surfaces the returned trace location. |
| `-IgnoreCertErrors` | No | **Testing only.** Skips TLS server-certificate validation. |

---

## Examples

Basic GET:

```powershell
.\Invoke-ApimCall.ps1 -Url "https://your-apim-host/path" -SubscriptionKey $key
```

POST with a token and body:

```powershell
.\Invoke-ApimCall.ps1 -Url "https://your-apim-host/orders" `
    -Method POST -SubscriptionKey $key -Token $accessToken -Body '{"id":42}'
```

Turn on APIM tracing and ignore a self-signed/incomplete cert chain while testing:

```powershell
.\Invoke-ApimCall.ps1 -Url "https://your-apim-host/orders" `
    -Trace -IgnoreCertErrors
```

Custom headers:

```powershell
.\Invoke-ApimCall.ps1 -Url "https://host/path" `
    -Headers @{ "x-correlation-id" = "12345"; "Accept" = "application/json" }
```

---

## How it reads the result

| Symptom | What the tool tells you |
|---|---|
| **No HTTP response** + `unable to get local issuer certificate` / chain error | Backend is presenting an **incomplete chain** (e.g. a missing intermediate CA). Fix the chain on the backend, or use `-IgnoreCertErrors` for testing. |
| **No HTTP response** + name mismatch / DNS / refused / timeout | Distinguishes cert-name mismatch, DNS failure, and TCP refused/timeout (firewall/NSG). |
| **401** | Authentication failed — checks for missing/expired token or missing subscription key; reads `WWW-Authenticate`. |
| **403** | Authorized identity but wrong **audience / roles / scopes** (compares the decoded token to `api://<api-app-id>`), or IP-filter, or downstream RBAC (`AuthorizationPermissionMismatch`). |
| **404 / 405** | The operation isn't matched in APIM — the classic reason a **POST doesn't appear in APIM logs** while GET/PUT do. Add the operation on the API. |
| **5xx** | Failure on the **APIM → backend hop**; if the body mentions TLS, points at the backend chain. Suggests `-Trace`. |

When `-Trace` is set and APIM returns one, it prints the `Ocp-Apim-Trace-Location` so you can
open the full inbound → backend → outbound trace.

---

## Notes

- `-IgnoreCertErrors` only affects the **client → APIM** hop. It does **not** change how APIM
  validates the backend certificate — that's controlled by the APIM Backend entity
  (`validateCertificateChain` / `validateCertificateName`).
- The token decode is offline (no network, no signature validation) — it's only there to let
  you eyeball the claims.
