<#
.SYNOPSIS
  Run Elasticsearch locally for Aura DFIR — NO DOCKER REQUIRED.

.DESCRIPTION
  Downloads the official Elasticsearch Windows ZIP (which bundles its own Java —
  nothing else to install), configures it for single-node local development with
  security disabled, and starts it in the foreground at http://localhost:9200.

  Leave this window open while you use Aura DFIR. Press Ctrl+C to stop.
  The download (~600 MB) happens only once; subsequent runs start immediately.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\setup_elasticsearch.ps1

.NOTES
  Security is disabled for convenience on a local dev box. For any real/shared
  deployment, enable xpack.security and set ES_USER / ES_PASSWORD in .env.
#>
param(
    [string]$Version = "8.13.4",
    [string]$HeapSize = "512m"
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # speeds up Invoke-WebRequest a lot

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$InstallDir = Join-Path $RepoRoot ".elasticsearch"
$EsHome     = Join-Path $InstallDir "elasticsearch-$Version"
$Zip        = Join-Path $InstallDir "elasticsearch-$Version.zip"
$Url        = "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$Version-windows-x86_64.zip"

if (-not (Test-Path $EsHome)) {
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    if (-not (Test-Path $Zip)) {
        Write-Host "Downloading Elasticsearch $Version (~600 MB, one-time)..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $Url -OutFile $Zip
    }
    Write-Host "Extracting..." -ForegroundColor Cyan
    Expand-Archive -Path $Zip -DestinationPath $InstallDir -Force
    Remove-Item $Zip -Force
}

# Configure for single-node local dev (security off). LOCAL DEV ONLY.
$Yml = Join-Path $EsHome "config\elasticsearch.yml"
@"
# Written by Aura DFIR scripts/setup_elasticsearch.ps1 (local dev, no Docker)
cluster.name: aura-dfir
discovery.type: single-node
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
"@ | Set-Content -Encoding utf8 $Yml

$env:ES_JAVA_OPTS = "-Xms$HeapSize -Xmx$HeapSize"

Write-Host ""
Write-Host "Starting Elasticsearch at http://localhost:9200 (heap $HeapSize)" -ForegroundColor Green
Write-Host "Leave this window open. Press Ctrl+C to stop." -ForegroundColor Green
Write-Host ""
& (Join-Path $EsHome "bin\elasticsearch.bat")
