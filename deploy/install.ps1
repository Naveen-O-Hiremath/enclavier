<#
.SYNOPSIS
  Enclavier self-host installer for Windows (Docker Desktop or Docker Engine).
  Safe to run again: it never overwrites an existing .env.

.PARAMETER Domain
  Public host name, e.g. vault.example.com. Turns on built-in HTTPS with an
  automatic Let's Encrypt certificate (DNS must point here; ports 80/443 open).
.PARAMETER PublicUrl
  Use when your own load balancer or reverse proxy terminates TLS.
.PARAMETER Port
  Local port of the web vault (default 8080).
.PARAMETER Registry
  Pull images from a registry, e.g. ghcr.io/your-org.
.PARAMETER Version
  Image version to run (default: latest).
.PARAMETER OpenSignups
  Let anyone who can reach the server create an account. Default: only the
  first account, then invitations and SSO.
.PARAMETER Offline
  Load images from images.tar.gz in this folder (air-gapped).

.EXAMPLE
  .\install.ps1 -Domain vault.example.com
#>
[CmdletBinding()]
param(
  [string]$Domain = '',
  [string]$PublicUrl = '',
  [int]$Port = 8080,
  [string]$Registry = '',
  [string]$Version = '',
  [switch]$OpenSignups,
  [switch]$Offline
)

# 'Continue': Windows PowerShell 5.1 turns anything a native command writes to stderr into an
# error record, which would abort the script under 'Stop'. Exit codes are checked explicitly.
$ErrorActionPreference = 'Continue'
Set-Location -LiteralPath $PSScriptRoot

function Say($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Die($m) { Write-Host "Error: $m" -ForegroundColor Red; exit 1 }
function Invoke-Docker { & docker @args; if ($LASTEXITCODE -ne 0) { Die "docker $($args -join ' ') failed" } }

# ---- prerequisites -----------------------------------------------------------
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Die 'Docker is not installed. Install Docker Desktop or Docker Engine first.' }
& docker compose version *> $null; if ($LASTEXITCODE -ne 0) { Die "Docker Compose v2 is required (the 'docker compose' command)." }
& docker info *> $null; if ($LASTEXITCODE -ne 0) { Die 'Cannot talk to Docker. Start Docker Desktop and try again.' }
if ($Domain -and $PublicUrl) { Die 'Use either -Domain (built-in HTTPS) or -PublicUrl (your own proxy), not both.' }

function New-Secret {
  $bytes = New-Object byte[] 48
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  ([Convert]::ToBase64String($bytes) -replace '[/+=]', '').Substring(0, 48)
}

# ---- where do the images come from? --------------------------------------------
$source = (Test-Path '..\apps\server\package.json') -and (Test-Path 'docker-compose.build.yml')
if ($Offline -or ((Test-Path 'images.tar.gz') -and -not $Registry -and -not $source)) {
  if (-not (Test-Path 'images.tar.gz')) { Die '-Offline needs images.tar.gz next to this script (from the offline bundle).' }
  Say 'Loading images from images.tar.gz'
  Invoke-Docker load -i images.tar.gz
  $source = $false; $Registry = ''
}
# Release bundles carry their version (and, for the online bundle, their registry).
if ((Test-Path 'VERSION') -and -not $Version) { $Version = (Get-Content 'VERSION' -Raw).Trim() }

# ---- configuration -------------------------------------------------------------
if (Test-Path '.env') {
  Say 'Keeping the existing .env (secrets and settings are unchanged)'
} else {
  Say 'Creating .env with new secrets'
  if ($Domain) { $url = "https://$Domain" } elseif ($PublicUrl) { $url = $PublicUrl.TrimEnd('/') } else { $url = "http://localhost:$Port" }
  $signups = if ($OpenSignups) { 'true' } else { 'false' }
  $mailDomain = if ($Domain) { $Domain } else { 'example.com' }
  $lines = @(
    "# Enclavier configuration. Created by install.ps1 on $((Get-Date).ToUniversalTime().ToString('s'))Z.",
    '# Keep this file secret and include it in your backups: without SERVER_SECRET,',
    "# stored authenticator seeds and SIEM credentials can't be read after a restore.",
    "POSTGRES_PASSWORD=$(New-Secret)",
    "JWT_SECRET=$(New-Secret)",
    "SERVER_SECRET=$(New-Secret)",
    '',
    "PUBLIC_URL=$url",
    "ENCLAVIER_PORT=$Port",
    '# false: only the first account can sign up; everyone else is invited or uses SSO.',
    "SIGNUPS_ENABLED=$signups",
    'LOG_LEVEL=info'
  )
  if ($Domain) { $lines += @('', "# Built-in HTTPS (Caddy + Let's Encrypt).", "ENCLAVIER_DOMAIN=$Domain", 'COMPOSE_PROFILES=tls', 'ENCLAVIER_BIND=127.0.0.1') }
  if ($source) { $lines += @('', '# Build images from this source checkout.', 'COMPOSE_PATH_SEPARATOR=:', 'COMPOSE_FILE=docker-compose.yml:docker-compose.build.yml') }
  if ($Registry) { $r = $Registry.TrimEnd('/'); $lines += @('', "ENCLAVIER_SERVER_IMAGE=$r/enclavier-server", "ENCLAVIER_WEB_IMAGE=$r/enclavier-web") }
  if (-not $Registry -and -not $source -and -not $Offline -and -not (Test-Path 'images.tar.gz') -and (Test-Path 'registry.env')) { $lines += @('') + (Get-Content 'registry.env') }
  if ($Version) { $lines += "ENCLAVIER_VERSION=$Version" }
  $hibp = if ($Offline) { 'HIBP_API_URL=' } else { 'HIBP_API_URL=https://api.pwnedpasswords.com' }
  $lines += @(
    '',
    '# ---- Outgoing e-mail (invitations, security notices) ----',
    '# Leave SMTP_HOST empty to write e-mails to the server log instead.',
    'SMTP_HOST=', 'SMTP_PORT=465', 'SMTP_SECURE=true', 'SMTP_USER=', 'SMTP_PASS=',
    "SMTP_FROM=Enclavier <no-reply@$mailDomain>",
    '',
    '# Self-hosted: allow log streaming and identity providers on your internal network.',
    'ALLOW_PRIVATE_LOG_DESTINATIONS=true',
    'ALLOW_PRIVATE_SSO_ENDPOINTS=true',
    '# Breach checks. Point at an offline mirror, or leave empty to disable (air-gapped).',
    $hibp
  )
  # UTF-8 without BOM, LF line endings: Docker Compose reads this file.
  [System.IO.File]::WriteAllText((Join-Path $PSScriptRoot '.env'), (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding $false))
  # Only the current user and administrators may read the secrets.
  & icacls '.env' /inheritance:r /grant:r "$($env:USERNAME):(R,W)" 'Administrators:(F)' *> $null
}

# ---- start ---------------------------------------------------------------------
$envText = Get-Content '.env' -Raw
if ($source) {
  Say 'Building and starting Enclavier (first build takes a few minutes)'
  Invoke-Docker compose up -d --build
} else {
  if ($Registry -or $envText -match '(?m)^ENCLAVIER_SERVER_IMAGE=') { Say 'Pulling images'; Invoke-Docker compose pull }
  Say 'Starting Enclavier'
  Invoke-Docker compose up -d
}

$portNow = if ($envText -match '(?m)^ENCLAVIER_PORT=(\d+)') { $Matches[1] } else { '8080' }
$urlNow = if ($envText -match '(?m)^PUBLIC_URL=(.+)$') { $Matches[1].Trim() } else { "http://localhost:$portNow" }
Say 'Waiting for the server to become healthy'
$ok = $false
for ($i = 0; $i -lt 60; $i++) {
  & docker compose exec -T server wget -qO- http://127.0.0.1:8080/health *> $null
  if ($LASTEXITCODE -eq 0) { $ok = $true; break }
  Start-Sleep -Seconds 2
}
if (-not $ok) { Die 'The server did not become healthy. Check: .\enclavier.ps1 logs' }

Write-Host @"

Enclavier is running.

  Vault:        $urlNow
  Local port:   http://localhost:$portNow
  Config:       $PSScriptRoot\.env   (back this file up; it holds your secrets)

Next steps
  1. Open the vault and create the first account. Create your organization
     from there and invite the team.
  2. Set SMTP_* in .env so invitations can be e-mailed, then: .\enclavier.ps1 restart
  3. Schedule backups:  .\enclavier.ps1 backup     (see docs\SELF_HOSTING.md)

Manage:  .\enclavier.ps1 status | logs | update | backup | restore <file> | stop
"@
if (-not $urlNow.StartsWith('https://')) {
  Write-Host "`nNote: $urlNow is not HTTPS. Use -Domain (built-in HTTPS) or put your own TLS proxy in front before real use." -ForegroundColor Yellow
}
