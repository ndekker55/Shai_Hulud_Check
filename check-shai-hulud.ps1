<#
.SYNOPSIS
    Checks for Shai-Hulud npm worm infection indicators.

.DESCRIPTION
    This script scans local files and Docker containers for indicators of compromise (IOCs)
    related to the Shai-Hulud npm supply chain attack.

.PARAMETER Path
    The local path to scan. Defaults to current directory.

.PARAMETER DockerService
    Optional Docker Compose service name to scan.

.PARAMETER DockerProfile
    Optional Docker Compose profile (e.g., "dev", "prod").

.EXAMPLE
    .\check-shai-hulud.ps1

.EXAMPLE
    .\check-shai-hulud.ps1 -Path "C:\myproject" -DockerService "app-dev" -DockerProfile "dev"
#>

param(
    [string]$Path = ".",
    [string]$DockerService = "",
    [string]$DockerProfile = ""
)

$ErrorActionPreference = "SilentlyContinue"

# Known malicious file hashes (SHA256)
$MaliciousHashes = @{
    "setup_bun.js" = "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
    "bun_environment.js" = @(
        "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0",
        "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd",
        "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068"
    )
}

$InfectionFound = $false
$Results = @{
    MaliciousFiles = @()
    SuspiciousScripts = @()
    ShaiHuludReferences = @()
    MetadataExfiltration = @()
    HashMatches = @()
}

function Write-Status {
    param([string]$Message, [string]$Status = "INFO")
    $color = switch ($Status) {
        "OK"      { "Green" }
        "WARNING" { "Yellow" }
        "DANGER"  { "Red" }
        "INFO"    { "Cyan" }
        default   { "White" }
    }
    Write-Host "[$Status] " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Blue
    Write-Host " $Title" -ForegroundColor Blue
    Write-Host ("=" * 60) -ForegroundColor Blue
}

# ============================================================
# LOCAL FILE SYSTEM CHECKS
# ============================================================

Write-Header "Shai-Hulud NPM Worm Scanner"
Write-Host "Scan started: $(Get-Date)"
Write-Host "Local path: $((Resolve-Path $Path).Path)"

Write-Header "Checking Local File System"

# Check 1: Malicious files
Write-Status "Scanning for malicious files (setup_bun.js, bun_environment.js)..." "INFO"
$maliciousFiles = Get-ChildItem -Path $Path -Recurse -Name -Include "setup_bun.js", "bun_environment.js" 2>$null

if ($maliciousFiles) {
    $script:InfectionFound = $true
    foreach ($file in $maliciousFiles) {
        Write-Status "FOUND: $file" "DANGER"
        $Results.MaliciousFiles += $file

        # Check hash
        $fullPath = Join-Path $Path $file
        $hash = (Get-FileHash -Path $fullPath -Algorithm SHA256).Hash.ToLower()
        $fileName = Split-Path $file -Leaf

        if ($MaliciousHashes[$fileName] -contains $hash -or $MaliciousHashes[$fileName] -eq $hash) {
            Write-Status "HASH MATCH - Confirmed malicious: $hash" "DANGER"
            $Results.HashMatches += @{File = $file; Hash = $hash}
        }
    }
} else {
    Write-Status "No malicious files found" "OK"
}

# Check 2: Suspicious preinstall/postinstall scripts
Write-Status "Scanning package.json files for suspicious scripts..." "INFO"
$packageFiles = Get-ChildItem -Path $Path -Recurse -Name -Include "package.json" 2>$null

foreach ($pkgFile in $packageFiles) {
    $fullPath = Join-Path $Path $pkgFile
    $content = Get-Content -Path $fullPath -Raw 2>$null

    if ($content -match '"preinstall"\s*:\s*"[^"]*(?:setup_bun|bun_environment|curl|wget|eval)[^"]*"') {
        $script:InfectionFound = $true
        Write-Status "Suspicious preinstall script in: $pkgFile" "DANGER"
        $Results.SuspiciousScripts += $pkgFile
    }
    if ($content -match '"postinstall"\s*:\s*"[^"]*(?:setup_bun|bun_environment|curl|wget|eval)[^"]*"') {
        $script:InfectionFound = $true
        Write-Status "Suspicious postinstall script in: $pkgFile" "DANGER"
        $Results.SuspiciousScripts += $pkgFile
    }
}

if ($Results.SuspiciousScripts.Count -eq 0) {
    Write-Status "No suspicious install scripts found" "OK"
}

# Check 3: Shai-Hulud references
Write-Status "Scanning for Shai-Hulud references..." "INFO"
$shaiFiles = Get-ChildItem -Path $Path -Recurse -Include "*.js", "*.json", "*.ts" 2>$null |
    Select-String -Pattern "shai.?hulud|bun_environment|setup_bun" -List 2>$null

if ($shaiFiles) {
    $script:InfectionFound = $true
    foreach ($match in $shaiFiles) {
        Write-Status "Reference found in: $($match.Path)" "DANGER"
        $Results.ShaiHuludReferences += $match.Path
    }
} else {
    Write-Status "No Shai-Hulud references found" "OK"
}

# Check 4: Cloud metadata exfiltration patterns
Write-Status "Scanning for cloud metadata exfiltration patterns..." "INFO"
$metadataFiles = Get-ChildItem -Path $Path -Recurse -Include "*.js", "*.ts" 2>$null |
    Select-String -Pattern "169\.254\.169\.254|metadata\.google\.internal|instance-data" -List 2>$null

if ($metadataFiles) {
    foreach ($match in $metadataFiles) {
        # Skip if in node_modules documentation or test files
        if ($match.Path -notmatch "node_modules[\\/].*[\\/](README|test|spec|__test__)") {
            Write-Status "Potential metadata exfiltration in: $($match.Path)" "WARNING"
            $Results.MetadataExfiltration += $match.Path
        }
    }
}

if ($Results.MetadataExfiltration.Count -eq 0) {
    Write-Status "No metadata exfiltration patterns found" "OK"
}

# ============================================================
# DOCKER CONTAINER CHECKS
# ============================================================

if ($DockerService) {
    Write-Header "Checking Docker Container: $DockerService"

    # Build docker compose command args
    $composeArgs = @()
    if ($DockerProfile) {
        $composeArgs += "--profile"
        $composeArgs += $DockerProfile
    }

    # Check if container is running
    $psArgs = $composeArgs + @("ps", "--format", "json")
    $containerJson = & docker compose @psArgs 2>$null
    $containerStatus = $null

    if ($containerJson) {
        try {
            $containers = $containerJson | ConvertFrom-Json
            $containerStatus = $containers | Where-Object { $_.Service -eq $DockerService -or $_.Name -like "*$DockerService*" }
        } catch {
            # JSON parsing failed, container might not exist
        }
    }

    if (-not $containerStatus) {
        Write-Status "Container '$DockerService' is not running. Skipping Docker checks." "WARNING"
    } else {
        Write-Status "Container is running: $($containerStatus.Name)" "INFO"

        # Docker Check 1: Malicious files
        Write-Status "Scanning container for malicious files..." "INFO"
        $execArgs = $composeArgs + @("exec", $DockerService, "find", "/app/node_modules", "-name", "setup_bun.js", "-o", "-name", "bun_environment.js")
        $dockerFiles = & docker compose @execArgs 2>$null

        if ($dockerFiles) {
            $script:InfectionFound = $true
            Write-Status "FOUND in container: $dockerFiles" "DANGER"
        } else {
            Write-Status "No malicious files in container" "OK"
        }

        # Docker Check 2: Shai-Hulud references
        Write-Status "Scanning container for Shai-Hulud references..." "INFO"
        $execArgs = $composeArgs + @("exec", $DockerService, "grep", "-ri", "shai.hulud", "/app/node_modules")
        $dockerShai = & docker compose @execArgs 2>$null

        if ($dockerShai) {
            $script:InfectionFound = $true
            Write-Status "References found in container!" "DANGER"
            $dockerShai | ForEach-Object { Write-Status $_ "DANGER" }
        } else {
            Write-Status "No Shai-Hulud references in container" "OK"
        }

        # Docker Check 3: Metadata exfiltration
        Write-Status "Scanning container for metadata exfiltration patterns..." "INFO"
        $execArgs = $composeArgs + @("exec", $DockerService, "grep", "-r", "169.254.169.254", "/app/node_modules")
        $dockerMeta = & docker compose @execArgs 2>$null

        if ($dockerMeta) {
            Write-Status "Potential metadata exfiltration in container!" "WARNING"
            $dockerMeta | ForEach-Object { Write-Status $_ "WARNING" }
        } else {
            Write-Status "No metadata exfiltration patterns in container" "OK"
        }
    }
}

# ============================================================
# SUMMARY
# ============================================================

Write-Header "Scan Summary"

if ($InfectionFound) {
    Write-Host ""
    Write-Host "  ****  DANGER  ****" -ForegroundColor Red
    Write-Host ""
    Write-Status "POTENTIAL INFECTION DETECTED!" "DANGER"
    Write-Host ""
    Write-Host "Recommended actions:" -ForegroundColor Yellow
    Write-Host "  1. Do NOT run 'npm install' until the infection is cleaned" -ForegroundColor Yellow
    Write-Host "  2. Revoke and regenerate: npm tokens, GitHub PATs, SSH keys, cloud credentials" -ForegroundColor Yellow
    Write-Host "  3. Check GitHub for repos with description 'Sha1-Hulud: The Second Coming'" -ForegroundColor Yellow
    Write-Host "  4. Roll back to pre-November 21, 2025 package-lock.json" -ForegroundColor Yellow
    Write-Host "  5. Review: https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0" -ForegroundColor Yellow
    Write-Host ""

    exit 1
} else {
    Write-Host ""
    Write-Host "  ****  CLEAN  ****" -ForegroundColor Green
    Write-Host ""
    Write-Status "No indicators of Shai-Hulud infection found." "OK"
    Write-Host ""

    exit 0
}
