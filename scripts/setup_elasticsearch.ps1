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
    [string]$Version = "8.19.18",
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
        Write-Host "Downloading Elasticsearch $Version (~500 MB, one-time)..." -ForegroundColor Cyan
        $maxAttempts = 5
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            try {
                Invoke-WebRequest -Uri $Url -OutFile $Zip
                break
            } catch {
                Write-Host "  Attempt $attempt/$maxAttempts failed: $($_.Exception.Message)" -ForegroundColor Yellow
                if (Test-Path $Zip) { Remove-Item $Zip -Force }   # never leave a corrupt partial file
                if ($attempt -eq $maxAttempts) {
                    throw "Could not download Elasticsearch after $maxAttempts attempts. Check your internet connection/proxy/firewall, or download the Windows zip manually from https://www.elastic.co/downloads/elasticsearch and unzip it into: $InstallDir"
                }
                Write-Host "  Retrying..." -ForegroundColor Yellow
                Start-Sleep -Seconds 3
            }
        }
    }
    Write-Host "Extracting..." -ForegroundColor Cyan
    try {
        Expand-Archive -Path $Zip -DestinationPath $InstallDir -Force
    } catch {
        Remove-Item $Zip -Force -ErrorAction SilentlyContinue
        throw "The downloaded Elasticsearch archive was corrupt. Please run this script again to retry."
    }
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
