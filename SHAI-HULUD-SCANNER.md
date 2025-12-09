# Shai-Hulud NPM Worm Scanner

A PowerShell script to detect indicators of the Shai-Hulud npm supply chain attack in your local files and Docker containers.

## Background

In September-November 2025, a self-replicating worm called "Shai-Hulud" compromised hundreds of packages in the npm ecosystem. The malware:

- Injects malicious files (`setup_bun.js`, `bun_environment.js`) into packages
- Harvests credentials (npm tokens, GitHub PATs, SSH keys, cloud credentials)
- Exfiltrates data to GitHub repositories
- Self-propagates by publishing infected versions of other packages you maintain

**References:**
- [CISA Alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Datadog Security Labs Analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Wiz Blog](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Official IOC Repository](https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0)

## What This Script Checks

| Check | Description |
|-------|-------------|
| Malicious files | Scans for `setup_bun.js` and `bun_environment.js` |
| File hashes | Compares found files against known malicious SHA256 hashes |
| Install scripts | Detects suspicious `preinstall`/`postinstall` scripts in package.json |
| Code references | Searches for "shai-hulud" patterns in JS/TS/JSON files |
| Metadata exfiltration | Looks for cloud metadata service calls (169.254.169.254) |
| Docker containers | Runs the same checks inside running containers |

## Usage

YOU MUST FIRST ALLOW THE SYSTEM TO RUN THE POWERSHELL SCRIPT

```powershell
Set-ExcecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Basic scan (current directory)

```powershell
.\check-shai-hulud.ps1
```

### Scan a specific path

```powershell
.\check-shai-hulud.ps1 -Path "C:\projects\my-app"
```

### Scan with Docker container

```powershell
.\check-shai-hulud.ps1 -DockerService "DOCKER_CONTAINER_NAME" -DockerProfile "PROFILE"
```

### Full scan (local + Docker)

```powershell
.\check-shai-hulud.ps1 -Path "." -DockerService "DOCKER_CONTAINER_NAME" -DockerProfile "PROFILE"
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-Path` | No | `.` | Local directory to scan |
| `-DockerService` | No | - | Docker Compose service name to scan |
| `-DockerProfile` | No | - | Docker Compose profile (e.g., "dev", "prod") |

## Exit Codes

- `0` - Clean, no infection indicators found
- `1` - Potential infection detected

## If Infection Is Detected

1. **Stop immediately** - Do NOT run `npm install` or `npm publish`
2. **Revoke credentials** - Rotate all potentially exposed secrets:
   - npm tokens
   - GitHub Personal Access Tokens
   - SSH keys
   - AWS/Azure/GCP credentials
3. **Check for data exfiltration** - Search GitHub for repositories with description "Sha1-Hulud: The Second Coming"
4. **Roll back** - Restore `package-lock.json` from before November 21, 2025
5. **Clean install** - Delete `node_modules` and reinstall from known-good lock file
6. **Audit** - Run `npm audit` and review the [official IOC list](https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0)

## Requirements

- PowerShell 5.1 or later
- Docker (optional, for container scanning)
- Docker Compose (optional, for container scanning)

## Limitations

- This script checks for known IOCs and may not detect new variants
- Always refer to the latest security advisories for updated indicators
- This is a detection tool, not a remediation tool
