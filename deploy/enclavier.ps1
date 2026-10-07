<#
.SYNOPSIS
  Day-to-day management of a self-hosted Enclavier on Windows.

.EXAMPLE
  .\enclavier.ps1 status
  .\enclavier.ps1 backup D:\Backups
  .\enclavier.ps1 restore .\backups\enclavier-20261003-101500.zip
#>
param(
  [Parameter(Position = 0)][string]$Command = 'help',
  [Parameter(Position = 1)][string]$Argument = ''
)

# Exit codes are checked explicitly (see install.ps1 for why this is not 'Stop').
$ErrorActionPreference = 'Continue'
Set-Location -LiteralPath $PSScriptRoot

function Say($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Die($m) { Write-Host "Error: $m" -ForegroundColor Red; exit 1 }
function Dc { & docker compose @args; if ($LASTEXITCODE -ne 0) { Die "docker compose $($args -join ' ') failed" } }

if ($Command -notin @('help', '-h', '--help') -and -not (Test-Path '.env')) { Die 'No .env here. Run .\install.ps1 first.' }

function Backup([string]$Dir) {
  if (-not $Dir) { $Dir = 'backups' }
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "enclavier-backup-$stamp"
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  try {
    Say 'Dumping the database'
    # Dump inside the container and copy it out: PowerShell pipes would corrupt binary data.
    Dc exec -T db pg_dump -U enclavier -d enclavier --format=custom --no-owner -f /tmp/enclavier.dump
    Dc cp db:/tmp/enclavier.dump (Join-Path $tmp 'db.dump')
    Dc exec -T db rm -f /tmp/enclavier.dump
    if ((Get-Item (Join-Path $tmp 'db.dump')).Length -eq 0) { Die 'The database dump is empty.' }
    Copy-Item '.env' (Join-Path $tmp 'env')
    $out = Join-Path (Resolve-Path $Dir) "enclavier-$stamp.zip"
    Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $out
    Say "Backup written to $out"
    Write-Host "    It contains your server secrets and every user's encrypted vault. Store it"
    Write-Host '    encrypted and off this machine.'
  } finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}

function Restore([string]$File) {
  if (-not $File -or -not (Test-Path $File)) { Die 'Usage: .\enclavier.ps1 restore <backup.zip>' }
  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "enclavier-restore-$(Get-Random)"
  try {
    Expand-Archive -Path $File -DestinationPath $tmp
    if (-not (Test-Path (Join-Path $tmp 'db.dump'))) { Die 'This archive has no database dump.' }
    $answer = Read-Host 'This replaces ALL current Enclavier data with the backup. Type "restore" to continue'
    if ($answer -ne 'restore') { Die 'Cancelled.' }
    Say 'Stopping the server'
    Dc stop server web
    Say 'Restoring the database'
    Dc cp (Join-Path $tmp 'db.dump') db:/tmp/enclavier.dump
    Dc exec -T db psql -U enclavier -d postgres -q -c 'DROP DATABASE IF EXISTS enclavier WITH (FORCE);' -c 'CREATE DATABASE enclavier OWNER enclavier;'
    Dc exec -T db pg_restore -U enclavier -d enclavier --no-owner --exit-on-error /tmp/enclavier.dump
    Dc exec -T -u root db rm -f /tmp/enclavier.dump
    Say 'Starting'
    Dc up -d
    Say 'Restore complete. Run .\enclavier.ps1 verify-audit to check the audit log.'
  } finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}

$builds = (Test-Path '.env') -and ((Get-Content '.env' -Raw) -match '(?m)^COMPOSE_FILE=.*docker-compose\.build\.yml')

switch ($Command) {
  'status' {
    Dc ps
    Write-Host ''
    Write-Host -NoNewline 'Version: '; & docker compose exec -T server sh -c 'echo "${ENCLAVIER_VERSION:-unknown}"'
    Write-Host -NoNewline 'Health:  '; & docker compose exec -T server wget -qO- http://127.0.0.1:8080/health; Write-Host ''
  }
  'start' { Dc up -d }
  'stop' { Dc stop }
  'restart' { Dc up -d --force-recreate server web }
  'logs' { if ($Argument) { & docker compose logs -f --tail 200 $Argument } else { & docker compose logs -f --tail 200 } }
  'update' {
    Backup 'backups'
    if ($Argument) {
      $text = Get-Content '.env' -Raw
      if ($text -match '(?m)^ENCLAVIER_VERSION=') { $text = $text -replace '(?m)^ENCLAVIER_VERSION=.*$', "ENCLAVIER_VERSION=$Argument" } else { $text = $text.TrimEnd() + "`nENCLAVIER_VERSION=$Argument`n" }
      [System.IO.File]::WriteAllText((Join-Path $PSScriptRoot '.env'), $text, (New-Object System.Text.UTF8Encoding $false))
    }
    if ($builds) { Say 'Rebuilding from source'; Dc up -d --build } else { Say 'Pulling images'; Dc pull; Dc up -d }
    Say 'Updated. Database migrations run automatically when the server starts.'
  }
  'backup' { Backup $Argument }
  'restore' { Restore $Argument }
  'verify-audit' { Dc exec -T server node apps/server/dist/verify-audit.js }
  'test-mail' { if (-not $Argument) { Die 'Usage: .\enclavier.ps1 test-mail you@example.com' }; Dc exec -T server node apps/server/dist/test-mail.js $Argument }
  'uninstall' {
    $a = Read-Host 'Stop and remove the Enclavier containers? Data volumes are kept. [y/N]'
    if ($a -ne 'y') { Die 'Cancelled.' }
    Dc down
    Write-Host 'Removed. To delete all data as well: docker compose down -v'
  }
  default {
    Write-Host @'
Usage: .\enclavier.ps1 <command>

  status              Show containers, version and health
  start | stop | restart
  logs [service]      Follow logs (server, web, db, proxy)
  update [version]    Pull (or rebuild) and restart on a new version; backs up first
  backup [dir]        Write a backup archive (database + .env) to .\backups or dir
  restore <file>      Restore the database from a backup archive
  verify-audit        Check the tamper-evident audit log
  test-mail <address> Send a test e-mail with the SMTP settings
  uninstall           Stop and remove containers (data volumes are kept)
'@
  }
}
