<#
.SYNOPSIS
    Makes an Azure API Management (APIM) call and returns a detailed, plain-language
    diagnosis of what went wrong when the call fails.

.DESCRIPTION
    A simple diagnostic front-end for testing an APIM endpoint. It sends the request
    (any method, optional body, subscription key, bearer token, custom headers) and
    then interprets the result:

      - 2xx  -> success summary (status, timing, key response headers)
      - 401  -> authentication problems (missing/expired/invalid token or sub key)
      - 403  -> authorization problems (wrong audience, missing roles/scopes,
                IP restriction, product/subscription, RBAC on backend resource)
      - 404/405 -> operation/route not matched in APIM (often the cause of
                "POST not showing in logs" while GET/PUT work)
      - 5xx  -> backend failures, including the TLS/certificate chain error
                ("unable to get local issuer certificate") on the APIM->backend hop

    It also decodes the bearer token's aud / roles / scp / exp claims so you can
    immediately compare them to what the API expects, and surfaces APIM's
    Ocp-Apim-Trace-Location when tracing is enabled.

    This is a diagnostic tool. The -IgnoreCertErrors switch disables server
    certificate validation for the Postman/PowerShell -> APIM hop and is for
    TESTING ONLY.

.PARAMETER Url
    The full APIM request URL (e.g. https://apim-host/api/path).

.PARAMETER Method
    HTTP method. Default GET.

.PARAMETER SubscriptionKey
    Value for the Ocp-Apim-Subscription-Key header.

.PARAMETER Token
    Bearer token. A leading "Bearer " is optional and will be stripped.

.PARAMETER Body
    Request body (string). Used for POST/PUT/PATCH.

.PARAMETER ContentType
    Content type for the body. Default application/json.

.PARAMETER Headers
    Hashtable of additional custom headers, e.g. @{ "x-correlation-id" = "abc" }.

.PARAMETER Trace
    Adds Ocp-Apim-Trace: true so APIM returns a trace location (subscription must
    allow tracing).

.PARAMETER IgnoreCertErrors
    TESTING ONLY. Skips TLS server-certificate validation for the call.

.EXAMPLE
    .\Invoke-ApimCall.ps1 -Url "https://apim/api/orders" -Method POST `
        -SubscriptionKey $key -Token $token -Body '{"id":42}'

.EXAMPLE
    .\Invoke-ApimCall.ps1 -Url "https://apim/api/orders" -Trace -IgnoreCertErrors
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Url,

    [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')]
    [string] $Method = 'GET',

    [string] $SubscriptionKey,

    [string] $Token,

    [string] $Body,

    [string] $ContentType = 'application/json',

    [hashtable] $Headers,

    [switch] $Trace,

    [switch] $IgnoreCertErrors
)

# ---------- helpers ----------

function Write-Section {
    param([string] $Title)
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function ConvertFrom-Base64Url {
    param([string] $Value)
    $b64 = $Value.Replace('-', '+').Replace('_', '/')
    switch ($b64.Length % 4) {
        2 { $b64 += '==' }
        3 { $b64 += '=' }
        1 { return $null }
    }
    try {
        [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
    }
    catch { $null }
}

function Get-TokenSummary {
    param([string] $Jwt)
    if ([string]::IsNullOrWhiteSpace($Jwt)) { return $null }
    $clean = $Jwt.Trim() -replace '^(?i)bearer\s+', ''
    $parts = $clean.Split('.')
    if ($parts.Count -ne 3) { return $null }
    $payloadJson = ConvertFrom-Base64Url $parts[1]
    if (-not $payloadJson) { return $null }
    try { $p = $payloadJson | ConvertFrom-Json } catch { return $null }

    $expUtc = $null; $expired = $null
    if ($p.exp) {
        $expUtc = [DateTimeOffset]::FromUnixTimeSeconds([long]$p.exp)
        $expired = ([DateTimeOffset]::UtcNow -gt $expUtc)
    }
    [pscustomobject]@{
        Audience  = $p.aud
        Issuer    = $p.iss
        AppId     = $p.appid
        Azp       = $p.azp
        Roles     = ($p.roles -join ', ')
        Scopes    = $p.scp
        ExpiresAt = if ($expUtc) { $expUtc.LocalDateTime } else { $null }
        Expired   = $expired
    }
}

# ---------- build request ----------

$reqHeaders = @{}
if ($Headers) { $Headers.GetEnumerator() | ForEach-Object { $reqHeaders[$_.Key] = $_.Value } }
if ($SubscriptionKey) { $reqHeaders['Ocp-Apim-Subscription-Key'] = $SubscriptionKey }
if ($Token) {
    $bearer = $Token.Trim()
    if ($bearer -notmatch '^(?i)bearer\s+') { $bearer = "Bearer $bearer" }
    $reqHeaders['Authorization'] = $bearer
}
if ($Trace) { $reqHeaders['Ocp-Apim-Trace'] = 'true' }

$tokenInfo = Get-TokenSummary $Token

Write-Section "REQUEST"
Write-Host ("  {0,-14}: {1}" -f 'Method', $Method)
Write-Host ("  {0,-14}: {1}" -f 'URL', $Url)
Write-Host ("  {0,-14}: {1}" -f 'Sub key', (if ($SubscriptionKey) { 'present' } else { 'NOT SET' }))
Write-Host ("  {0,-14}: {1}" -f 'Bearer token', (if ($Token) { 'present' } else { 'NOT SET' }))
if ($Headers) { Write-Host ("  {0,-14}: {1}" -f 'Custom hdrs', (($Headers.Keys) -join ', ')) }
if ($IgnoreCertErrors) { Write-Host "  Cert check    : DISABLED (testing only)" -ForegroundColor Yellow }

if ($tokenInfo) {
    Write-Section "TOKEN CLAIMS (from supplied bearer token)"
    Write-Host ("  aud    : {0}" -f $tokenInfo.Audience)
    Write-Host ("  roles  : {0}" -f $tokenInfo.Roles)
    Write-Host ("  scp    : {0}" -f $tokenInfo.Scopes)
    Write-Host ("  appid  : {0}" -f $tokenInfo.AppId)
    Write-Host ("  azp    : {0}" -f $tokenInfo.Azp)
    Write-Host ("  expires: {0}" -f $tokenInfo.ExpiresAt)
    if ($tokenInfo.Expired -eq $true) {
        Write-Host "  >> TOKEN IS EXPIRED — this alone causes 401." -ForegroundColor Red
    }
}

# ---------- invoke ----------

$invokeParams = @{
    Uri                = $Url
    Method             = $Method
    Headers            = $reqHeaders
    SkipHttpErrorCheck = $true      # capture 4xx/5xx instead of throwing
    ErrorAction        = 'Stop'
}
if ($Body -and $Method -in 'POST', 'PUT', 'PATCH') {
    $invokeParams['Body'] = $Body
    $invokeParams['ContentType'] = $ContentType
}
if ($IgnoreCertErrors) { $invokeParams['SkipCertificateCheck'] = $true }

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$transportError = $null
$response = $null
try {
    $response = Invoke-WebRequest @invokeParams
}
catch {
    $transportError = $_
}
$sw.Stop()

# ---------- transport-level failure (no HTTP response at all) ----------

if ($transportError) {
    Write-Section "RESULT: CONNECTION FAILED (no HTTP response)"
    $msg = $transportError.Exception.Message
    Write-Host "  $msg" -ForegroundColor Red

    Write-Section "DIAGNOSIS"
    if ($msg -match 'local issuer certificate|chain|RemoteCertificateChainErrors|partial chain|UntrustedRoot') {
        Write-Host "  TLS certificate chain could not be validated." -ForegroundColor Yellow
        Write-Host "  - The server presented a cert whose issuing/intermediate CA was not trusted."
        Write-Host "  - Classic 'missing intermediate' case (issuing/intermediate CA not bundled by the server)."
        Write-Host "  Fix: install the full chain on the server, OR (test only) re-run with -IgnoreCertErrors."
    }
    elseif ($msg -match 'name|RemoteCertificateNameMismatch|CN') {
        Write-Host "  TLS certificate name mismatch — the host name does not match the cert subject/SAN." -ForegroundColor Yellow
    }
    elseif ($msg -match 'No such host|name or service not known|nodename') {
        Write-Host "  DNS resolution failed — the host name does not resolve." -ForegroundColor Yellow
    }
    elseif ($msg -match 'actively refused|target machine|connection.*refused|timed out|timeout') {
        Write-Host "  TCP connection refused/timed out — host/port unreachable, firewall, or NSG blocking." -ForegroundColor Yellow
    }
    else {
        Write-Host "  Unclassified transport error. See message above." -ForegroundColor Yellow
    }
    return
}

# ---------- HTTP response received ----------

$status = [int]$response.StatusCode
$rh = $response.Headers

Write-Section "RESULT"
$color = if ($status -lt 300) { 'Green' } elseif ($status -lt 500) { 'Yellow' } else { 'Red' }
Write-Host ("  HTTP {0} {1}" -f $status, $response.StatusDescription) -ForegroundColor $color
Write-Host ("  Time : {0} ms" -f $sw.ElapsedMilliseconds)

# selected APIM-relevant headers
function Get-Header { param($name) if ($rh.ContainsKey($name)) { ($rh[$name] -join ', ') } else { $null } }
$traceLoc = Get-Header 'Ocp-Apim-Trace-Location'

Write-Section "RESPONSE HEADERS (selected)"
foreach ($h in 'Content-Type', 'WWW-Authenticate', 'x-ms-request-id', 'Request-Id', 'Ocp-Apim-Trace-Location') {
    $v = Get-Header $h
    if ($v) { Write-Host ("  {0,-26}: {1}" -f $h, $v) }
}

# body (truncated)
$bodyText = $response.Content
if ($bodyText) {
    Write-Section "RESPONSE BODY (first 1000 chars)"
    Write-Host ($bodyText.Substring(0, [Math]::Min(1000, $bodyText.Length)))
}

# ---------- diagnosis ----------

Write-Section "DIAGNOSIS"
switch ($status) {
    { $_ -lt 300 } {
        Write-Host "  Success. The request was accepted and routed to the backend." -ForegroundColor Green
        break
    }
    400 {
        Write-Host "  400 Bad Request — APIM or backend rejected the request shape." -ForegroundColor Yellow
        Write-Host "  Check required headers, body schema, and content type."
        break
    }
    401 {
        Write-Host "  401 Unauthorized — authentication failed (identity not established)." -ForegroundColor Yellow
        if (-not $SubscriptionKey) { Write-Host "  - No subscription key sent; if the API/product requires one, that's the cause." }
        if (-not $Token)           { Write-Host "  - No bearer token sent; if a validate-jwt policy is present, that's the cause." }
        if ($tokenInfo.Expired -eq $true) { Write-Host "  - Supplied token is EXPIRED." -ForegroundColor Red }
        $wa = Get-Header 'WWW-Authenticate'
        if ($wa) { Write-Host "  - WWW-Authenticate: $wa  (often names the exact reason: invalid audience/signature/expired)." }
        break
    }
    403 {
        Write-Host "  403 Forbidden — authenticated but NOT authorized." -ForegroundColor Yellow
        Write-Host "  Most common causes, in order:"
        Write-Host "   1. Subscription key valid but not for THIS product/API."
        if ($tokenInfo) {
            Write-Host "   2. Token audience/roles mismatch. From your token:"
            Write-Host ("        aud   = {0}" -f $tokenInfo.Audience)
            Write-Host ("        roles = {0}" -f $tokenInfo.Roles)
            Write-Host ("        scp   = {0}" -f $tokenInfo.Scopes)
            Write-Host "      -> Confirm 'aud' equals the API's expected audience (api://<api-app-id>)"
            Write-Host "         and that the required app role/scope is present."
        }
        else {
            Write-Host "   2. No token decoded — if a validate-jwt requires roles/scopes, that's likely it."
        }
        Write-Host "   3. IP restriction / ip-filter policy blocking the caller."
        Write-Host "   4. Downstream RBAC: backend resource (Storage/Service Bus) returns"
        Write-Host "      AuthorizationPermissionMismatch -> assign the data-plane role to the identity."
        break
    }
    404 {
        Write-Host "  404 Not Found — APIM did not match an operation/route for this method+path." -ForegroundColor Yellow
        Write-Host "  This is the classic reason a method (e.g. POST) does NOT appear in APIM logs"
        Write-Host "  while GET/PUT do: the POST operation is not defined on the API path."
        Write-Host "  Fix: APIM -> your API -> Design -> add the missing operation for this URL template."
        break
    }
    405 {
        Write-Host "  405 Method Not Allowed — path exists but not for method '$Method'." -ForegroundColor Yellow
        Write-Host "  Add/enable the '$Method' operation on this API path in APIM."
        break
    }
    { $_ -ge 500 } {
        Write-Host "  $status — failure on the APIM->backend hop (backend error or unreachable)." -ForegroundColor Red
        if ($bodyText -match 'certificate|chain|SSL|TLS|local issuer') {
            Write-Host "  Body mentions certificate/TLS: backend is presenting an INCOMPLETE chain."
            Write-Host "  -> This is the APIM->backend TLS validation failing (e.g. a missing intermediate CA)."
            Write-Host "  Fix: full-chain cert on backend, OR relax validateCertificateChain on an APIM Backend entity,"
            Write-Host "       OR upload the CA cert to APIM."
        }
        else {
            Write-Host "  Enable APIM tracing (-Trace) and inspect the backend section to see the exact failure."
        }
        break
    }
    default {
        Write-Host "  Unhandled status $status. Inspect headers/body above."
    }
}

if ($traceLoc) {
    Write-Section "APIM TRACE"
    Write-Host "  Trace available (open to see inbound -> backend -> outbound):"
    Write-Host "  $traceLoc"
}
elseif ($Trace) {
    Write-Host ""
    Write-Host "  (-Trace was set but no Ocp-Apim-Trace-Location returned — the subscription may not allow tracing.)" -ForegroundColor DarkYellow
}
