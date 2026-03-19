<#
.SYNOPSIS
    HomeLab SOC v2 - Infrastructure Collection Script

.DESCRIPTION
    Pulls all SOC configs/scripts from deployed infrastructure and 
    syncs to GitHub repo + Astro website assets.
    
    Run from PITBOSS (Windows workstation).

.AUTHOR
    Brian Chaplow

.NOTES
    Updated: January 2026
    
    Hosts:
      - QNAP (smokehouse): 10.10.20.10:2222
      - GCP VM: via gcloud
      - pitcrew: 10.10.30.20
      - smoker: 10.10.30.21
#>

param(
    [switch]$QnapOnly,
    [switch]$GcpOnly,
    [switch]$SkipAstro,
    [switch]$DryRun,
    [switch]$Verbose
)

# =============================================================================
# CONFIGURATION
# =============================================================================

$Config = @{
    # Local repo locations
    GitHubRepo = "C:\Projects\HomeLab-SOC-v2"
    AstroRepo  = "C:\Projects\brianchaplow-astro"
    
    # Remote hosts
    QnapHost   = "bchaplow@10.10.20.10"
    QnapPort   = 2222
    GcpVm      = "wordpress-1-vm"
    GcpZone    = "us-east4-a"
    Pitcrew    = "root@10.10.30.20"
    Smoker     = "root@10.10.30.21"
    
    # QNAP paths
    QnapSocRoot       = "/share/Container/SOC"
    QnapAutomationRoot = "/share/Container/soc-automation"  # NEW: soc-automation path
    QnapDocker        = "/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker"
    
    # Staging
    StagingDir = "$env:TEMP\soc-collect-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info","Success","Warning","Error","Section")]
        [string]$Type = "Info"
    )
    
    $colors = @{
        Info    = "Cyan"
        Success = "Green"
        Warning = "Yellow"
        Error   = "Red"
        Section = "Magenta"
    }
    
    $symbols = @{
        Info    = "[*]"
        Success = "[+]"
        Warning = "[!]"
        Error   = "[X]"
        Section = "==="
    }
    
    Write-Host "$($symbols[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host " $Title" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Green
}

function Test-SshHost {
    param(
        [string]$HostName,
        [int]$Port = 22
    )
    
    $result = ssh -p $Port -o ConnectTimeout=5 -o BatchMode=yes $HostName "echo ok" 2>$null
    return $result -eq "ok"
}

# =============================================================================
# COLLECTION FUNCTIONS
# =============================================================================

function Get-QnapFiles {
    Write-Section "Collecting from QNAP (smokehouse)"
    
    if (-not (Test-SshHost -HostName $Config.QnapHost -Port $Config.QnapPort)) {
        Write-Status "Cannot connect to QNAP" -Type Error
        return $false
    }
    
    Write-Status "Connected to QNAP" -Type Success
    
    $dest = Join-Path $Config.StagingDir "qnap"
    
    # Create directory structure
    $dirs = @(
        "$dest",
        "$dest\configs",
        "$dest\configs\suricata",
        "$dest\configs\fluent-bit",
        "$dest\configs\syslog-ng",
        "$dest\configs\telegraf",
        "$dest\scripts"
    )
    foreach ($dir in $dirs) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    
    # Define files to collect from /share/Container/SOC/
    $files = @(
        @{ Remote = "compose/docker-compose.yml"; Local = "configs\docker-compose.yml" },
        @{ Remote = "containers/suricata/config/suricata.yaml"; Local = "configs\suricata\suricata.yaml" },
        @{ Remote = "containers/suricata/config/update.yaml"; Local = "configs\suricata\update.yaml" },
        @{ Remote = "containers/suricata/rules/local.rules"; Local = "configs\suricata\local.rules" },
        @{ Remote = "containers/syslog-ng/config/syslog-ng.conf"; Local = "configs\syslog-ng\syslog-ng.conf" },
        @{ Remote = "containers/telegraf/telegraf.conf"; Local = "configs\telegraf\telegraf-qnap.conf" },
        @{ Remote = "ingestion/fluentbit/fluent-bit.conf"; Local = "configs\fluent-bit\fluent-bit-qnap.conf" },
        @{ Remote = "ingestion/fluentbit/parsers.conf"; Local = "configs\fluent-bit\parsers-qnap.conf" },
        @{ Remote = "scripts/soc-startup.sh"; Local = "scripts\soc-startup.sh" },
        @{ Remote = "scripts/update-geoip.sh"; Local = "scripts\update-geoip.sh" }
    )
    
    foreach ($file in $files) {
        $remotePath = "$($Config.QnapSocRoot)/$($file.Remote)"
        $localPath = Join-Path $dest $file.Local
        
        Write-Status "Fetching $($file.Remote)..." -Type Info
        
        if ($DryRun) {
            Write-Status "DRY RUN: Would copy $remotePath" -Type Warning
        } else {
            $null = scp -P $Config.QnapPort "$($Config.QnapHost):$remotePath" $localPath 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Status $file.Local -Type Success
            } else {
                Write-Status "Failed: $($file.Local)" -Type Warning
            }
        }
    }
    
    if (-not $DryRun) {
        # Get metrics using full docker path
        Write-Status "Fetching current metrics..." -Type Info
        
        $dockerPath = $Config.QnapDocker
        
        # Get rule count
        $ruleCmd = "$dockerPath exec suricata-live wc -l /var/lib/suricata/rules/suricata.rules"
        $ruleResult = ssh -p $Config.QnapPort $Config.QnapHost $ruleCmd 2>$null
        $ruleCount = if ($ruleResult -match '(\d+)') { $matches[1] } else { "N/A" }
        
        # Get container count
        $countCmd = "$dockerPath ps --format '{{.Names}}'"
        $containerList = ssh -p $Config.QnapPort $Config.QnapHost $countCmd 2>$null
        $containers = $containerList -split "`n" | Where-Object { $_ -ne "" }
        $containerCount = $containers.Count
        
        # Save metrics
        @{
            SuricataRules = $ruleCount
            ContainerCount = $containerCount
            Containers = $containers
            CollectedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        } | ConvertTo-Json | Out-File (Join-Path $dest "metrics.json")
        
        Write-Status "QNAP collection complete (Rules: $ruleCount, Containers: $containerCount)" -Type Success
    } else {
        Write-Status "QNAP collection complete (DRY RUN)" -Type Success
    }
    return $true
}

# =============================================================================
# NEW: SOC-AUTOMATION COLLECTION (ML Scorer, Enrichment, etc.)
# =============================================================================

function Get-SocAutomationFiles {
    Write-Section "Collecting SOC Automation (ML Scorer + Scripts)"
    
    if (-not (Test-SshHost -HostName $Config.QnapHost -Port $Config.QnapPort)) {
        Write-Status "Cannot connect to QNAP for soc-automation" -Type Error
        return $false
    }
    
    $dest = Join-Path $Config.StagingDir "soc-automation"
    
    # Create directory structure matching GitHub repo layout
    $dirs = @(
        "$dest",
        "$dest\scripts",
        "$dest\scripts\utils",
        "$dest\config",
        "$dest\cron",
        "$dest\models"
    )
    foreach ($dir in $dirs) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    
    # Define files to collect from /share/Container/soc-automation/
    $files = @(
        # Root config files
        @{ Remote = "Dockerfile"; Local = "Dockerfile" },
        @{ Remote = "docker-compose.yml"; Local = "docker-compose.yml" },
        @{ Remote = "entrypoint.sh"; Local = "entrypoint.sh" },
        @{ Remote = "requirements.txt"; Local = "requirements.txt" },
        @{ Remote = ".env.example"; Local = ".env.example" },
        @{ Remote = "backup-local.sh"; Local = "backup-local.sh" },
        
        # Config
        @{ Remote = "config/config.yaml"; Local = "config\config.yaml" },
        
        # Cron
        @{ Remote = "cron/crontab"; Local = "cron\crontab" },
        
        # Main scripts (including ML scorer)
        @{ Remote = "scripts/__init__.py"; Local = "scripts\__init__.py" },
        @{ Remote = "scripts/enrichment.py"; Local = "scripts\enrichment.py" },
        @{ Remote = "scripts/autoblock.py"; Local = "scripts\autoblock.py" },
        @{ Remote = "scripts/digest.py"; Local = "scripts\digest.py" },
        @{ Remote = "scripts/ml_scorer.py"; Local = "scripts\ml_scorer.py" },
        
        # Utils
        @{ Remote = "scripts/utils/__init__.py"; Local = "scripts\utils\__init__.py" },
        @{ Remote = "scripts/utils/opensearch_client.py"; Local = "scripts\utils\opensearch_client.py" },
        @{ Remote = "scripts/utils/discord_notify.py"; Local = "scripts\utils\discord_notify.py" }
    )
    
    foreach ($file in $files) {
        $remotePath = "$($Config.QnapAutomationRoot)/$($file.Remote)"
        $localPath = Join-Path $dest $file.Local
        
        Write-Status "Fetching soc-automation/$($file.Remote)..." -Type Info
        
        if ($DryRun) {
            Write-Status "DRY RUN: Would copy $remotePath" -Type Warning
        } else {
            $null = scp -P $Config.QnapPort "$($Config.QnapHost):$remotePath" $localPath 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Status "soc-automation/$($file.Local)" -Type Success
            } else {
                Write-Status "Failed: soc-automation/$($file.Local)" -Type Warning
            }
        }
    }
    
    # Create models README (models themselves are not synced - too large + sensitive)
    if (-not $DryRun) {
        $modelsReadme = @"
# ML Models Directory

This directory contains trained ML models for threat detection.

## Current Production Model

- **Path on QNAP:** `/share/Container/soc-automation/models/`
- **Active model:** `ground_truth_v2_xgb_20260127_171501/`

## Model Files (not synced to repo)

| File | Purpose |
|------|---------|
| `model.json` | XGBoost model (native format) |
| `feature_engineer.pkl` | Scikit-learn feature engineering pipeline |
| `metadata.json` | Training metadata, thresholds, feature list |

## Training Location

Models are trained on the Kali system (sear) at:
- `/home/butcher/soc-ml/`

## Why Models Aren't in Repo

1. **Size:** Models can be large (10MB+)
2. **Sensitive:** Trained on production network patterns
3. **Versioned separately:** Model versions tracked in metadata.json

## Retraining

See `docs/ml-detection.md` for training procedures.
"@
        $modelsReadme | Out-File (Join-Path $dest "models\README.md") -Encoding utf8
        Write-Status "Created models/README.md" -Type Success
    }
    
    Write-Status "SOC Automation collection complete" -Type Success
    return $true
}

function Get-GcpFiles {
    Write-Section "Collecting from GCP VM"
    
    $dest = Join-Path $Config.StagingDir "gcp"
    New-Item -ItemType Directory -Path "$dest\fluent-bit" -Force | Out-Null
    
    $files = @(
        @{ Remote = "/etc/fluent-bit/fluent-bit.conf"; Local = "fluent-bit\fluent-bit-vm.conf" },
        @{ Remote = "/etc/fluent-bit/honeypot.conf"; Local = "fluent-bit\honeypot.conf" },
        @{ Remote = "/etc/fluent-bit/parsers.conf"; Local = "fluent-bit\parsers-vm.conf" }
    )
    
    foreach ($file in $files) {
        $localPath = Join-Path $dest $file.Local
        
        Write-Status "Fetching $($file.Remote)..." -Type Info
        
        if ($DryRun) {
            Write-Status "DRY RUN: Would copy $($file.Remote)" -Type Warning
        } else {
            gcloud compute scp "$($Config.GcpVm):$($file.Remote)" $localPath --zone=$($Config.GcpZone) 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Status $file.Local -Type Success
            } else {
                Write-Status "Failed: $($file.Local)" -Type Warning
            }
        }
    }
    
    Write-Status "GCP collection complete" -Type Success
    return $true
}

function Get-ProxmoxFiles {
    Write-Section "Collecting from Proxmox hosts"
    
    $dest = Join-Path $Config.StagingDir "proxmox"
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    
    # Telegraf configs from Proxmox hosts
    if (Test-SshHost -HostName $Config.Pitcrew) {
        Write-Status "Fetching from pitcrew..." -Type Info
        if (-not $DryRun) {
            scp "$($Config.Pitcrew):/etc/telegraf/telegraf.conf" "$dest\telegraf-pitcrew.conf" 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Status "telegraf-pitcrew.conf" -Type Success
            } else {
                Write-Status "Failed: telegraf-pitcrew.conf" -Type Warning
            }
        } else {
            Write-Status "DRY RUN: Would copy telegraf from pitcrew" -Type Warning
        }
    } else {
        Write-Status "Cannot connect to pitcrew" -Type Warning
    }
    
    if (Test-SshHost -HostName $Config.Smoker) {
        Write-Status "Fetching from smoker..." -Type Info
        if (-not $DryRun) {
            scp "$($Config.Smoker):/etc/telegraf/telegraf.conf" "$dest\telegraf-smoker.conf" 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Status "telegraf-smoker.conf" -Type Success
            } else {
                Write-Status "Failed: telegraf-smoker.conf" -Type Warning
            }
        } else {
            Write-Status "DRY RUN: Would copy telegraf from smoker" -Type Warning
        }
    } else {
        Write-Status "Cannot connect to smoker" -Type Warning
    }
    
    Write-Status "Proxmox collection complete" -Type Success
    return $true
}

# =============================================================================
# SYNC FUNCTIONS
# =============================================================================

function Sync-ToGitHubRepo {
    Write-Section "Syncing to GitHub repo"
    
    $repo = $Config.GitHubRepo
    
    if (-not (Test-Path $repo)) {
        Write-Status "GitHub repo not found at $repo" -Type Error
        return $false
    }
    
    # Create directory structure in repo
    $dirs = @(
        "configs",
        "configs\fluent-bit",
        "configs\suricata",
        "configs\syslog-ng",
        "configs\telegraf",
        "configs\opensearch",
        "scripts",
        "scripts\soc-automation",
        "scripts\soc-automation\scripts",
        "scripts\soc-automation\scripts\utils",
        "scripts\soc-automation\config",
        "scripts\soc-automation\cron",
        "scripts\soc-automation\models"
    )
    
    foreach ($dir in $dirs) {
        $path = Join-Path $repo $dir
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
    
    # Copy QNAP files
    $qnapStaging = Join-Path $Config.StagingDir "qnap"
    if (Test-Path $qnapStaging) {
        Write-Status "Copying QNAP files..." -Type Info
        
        # Configs
        Copy-Item "$qnapStaging\configs\docker-compose.yml" -Destination "$repo\configs\" -Force -ErrorAction SilentlyContinue
        Copy-Item "$qnapStaging\configs\suricata\*" -Destination "$repo\configs\suricata\" -Force -ErrorAction SilentlyContinue
        Copy-Item "$qnapStaging\configs\syslog-ng\*" -Destination "$repo\configs\syslog-ng\" -Force -ErrorAction SilentlyContinue
        Copy-Item "$qnapStaging\configs\telegraf\*" -Destination "$repo\configs\telegraf\" -Force -ErrorAction SilentlyContinue
        Copy-Item "$qnapStaging\configs\fluent-bit\*" -Destination "$repo\configs\fluent-bit\" -Force -ErrorAction SilentlyContinue
        
        # Scripts
        Copy-Item "$qnapStaging\scripts\*" -Destination "$repo\scripts\" -Force -ErrorAction SilentlyContinue
    }
    
    # Copy SOC Automation files (NEW)
    $automationStaging = Join-Path $Config.StagingDir "soc-automation"
    if (Test-Path $automationStaging) {
        Write-Status "Copying SOC Automation files (including ML scorer)..." -Type Info
        
        # Root files
        Copy-Item "$automationStaging\Dockerfile" -Destination "$repo\scripts\soc-automation\" -Force -ErrorAction SilentlyContinue
        Copy-Item "$automationStaging\docker-compose.yml" -Destination "$repo\scripts\soc-automation\" -Force -ErrorAction SilentlyContinue
        Copy-Item "$automationStaging\entrypoint.sh" -Destination "$repo\scripts\soc-automation\" -Force -ErrorAction SilentlyContinue
        Copy-Item "$automationStaging\requirements.txt" -Destination "$repo\scripts\soc-automation\" -Force -ErrorAction SilentlyContinue
        Copy-Item "$automationStaging\.env.example" -Destination "$repo\scripts\soc-automation\" -Force -ErrorAction SilentlyContinue
        Copy-Item "$automationStaging\backup-local.sh" -Destination "$repo\scripts\soc-automation\" -Force -ErrorAction SilentlyContinue
        
        # Config
        Copy-Item "$automationStaging\config\*" -Destination "$repo\scripts\soc-automation\config\" -Force -ErrorAction SilentlyContinue
        
        # Cron
        Copy-Item "$automationStaging\cron\*" -Destination "$repo\scripts\soc-automation\cron\" -Force -ErrorAction SilentlyContinue
        
        # Scripts (including ml_scorer.py)
        Copy-Item "$automationStaging\scripts\*.py" -Destination "$repo\scripts\soc-automation\scripts\" -Force -ErrorAction SilentlyContinue
        
        # Utils
        Copy-Item "$automationStaging\scripts\utils\*" -Destination "$repo\scripts\soc-automation\scripts\utils\" -Force -ErrorAction SilentlyContinue
        
        # Models README
        Copy-Item "$automationStaging\models\README.md" -Destination "$repo\scripts\soc-automation\models\" -Force -ErrorAction SilentlyContinue
        
        # Create .gitkeep for models directory
        "" | Out-File "$repo\scripts\soc-automation\models\.gitkeep" -NoNewline
    }
    
    # Copy GCP files
    $gcpStaging = Join-Path $Config.StagingDir "gcp"
    if (Test-Path $gcpStaging) {
        Write-Status "Copying GCP files..." -Type Info
        Copy-Item "$gcpStaging\fluent-bit\*" -Destination "$repo\configs\fluent-bit\" -Force -ErrorAction SilentlyContinue
    }
    
    # Copy Proxmox files
    $proxStaging = Join-Path $Config.StagingDir "proxmox"
    if (Test-Path $proxStaging) {
        Write-Status "Copying Proxmox files..." -Type Info
        Copy-Item "$proxStaging\*.conf" -Destination "$repo\configs\telegraf\" -Force -ErrorAction SilentlyContinue
    }
    
    Write-Status "GitHub repo sync complete" -Type Success
    return $true
}

function Sync-ToAstroRepo {
    if ($SkipAstro) {
        Write-Status "Skipping Astro sync (-SkipAstro)" -Type Info
        return $true
    }
    
    Write-Section "Syncing to Astro website"
    
    $repo = $Config.AstroRepo
    
    if (-not (Test-Path $repo)) {
        Write-Status "Astro repo not found at $repo - skipping" -Type Warning
        return $true
    }
    
    $assetsDir = Join-Path $repo "public\images\projects\homelab-soc-v2"
    if (-not (Test-Path $assetsDir)) {
        New-Item -ItemType Directory -Path $assetsDir -Force | Out-Null
    }
    
    # Copy screenshots from GitHub repo (single source of truth)
    $screenshots = Join-Path $Config.GitHubRepo "screenshots"
    if (Test-Path $screenshots) {
        $pngFiles = Get-ChildItem "$screenshots\*.png" -ErrorAction SilentlyContinue
        if ($pngFiles) {
            Copy-Item $pngFiles -Destination $assetsDir -Force -ErrorAction SilentlyContinue
            Write-Status "Screenshots synced to Astro ($($pngFiles.Count) files)" -Type Success
        } else {
            Write-Status "No screenshots found" -Type Warning
        }
    }
    
    return $true
}

# =============================================================================
# REPORTING
# =============================================================================

function Show-Summary {
    Write-Section "Collection Summary"
    
    # Show collected files
    Write-Host "`nFiles collected:" -ForegroundColor Cyan
    Get-ChildItem -Path $Config.StagingDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $rel = $_.FullName.Replace($Config.StagingDir, "").TrimStart("\")
        Write-Host "  $rel" -ForegroundColor Gray
    }
    
    # Show metrics
    $metricsFile = Join-Path $Config.StagingDir "qnap\metrics.json"
    if (Test-Path $metricsFile) {
        $metrics = Get-Content $metricsFile | ConvertFrom-Json
        Write-Host "`nInfrastructure Metrics:" -ForegroundColor Cyan
        Write-Host "  Suricata Rules: $($metrics.SuricataRules)" -ForegroundColor Gray
        Write-Host "  Containers: $($metrics.ContainerCount)" -ForegroundColor Gray
        Write-Host "  Container List:" -ForegroundColor Gray
        $metrics.Containers | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkGray }
    }
    
    Write-Host "`nSynced to:" -ForegroundColor Cyan
    Write-Host "  GitHub: $($Config.GitHubRepo)" -ForegroundColor Gray
    Write-Host "  Astro:  $($Config.AstroRepo)" -ForegroundColor Gray
}

function Show-GitStatus {
    Write-Section "Git Status"
    
    if (Test-Path $Config.GitHubRepo) {
        Write-Host "GitHub Repo Changes:" -ForegroundColor Yellow
        Push-Location $Config.GitHubRepo
        git status --short
        Pop-Location
        Write-Host ""
    }
    
    if ((Test-Path $Config.AstroRepo) -and (-not $SkipAstro)) {
        $astroGit = Join-Path $Config.AstroRepo ".git"
        if (Test-Path $astroGit) {
            Write-Host "Astro Repo Changes:" -ForegroundColor Yellow
            Push-Location $Config.AstroRepo
            git status --short
            Pop-Location
        }
    }
}

# =============================================================================
# MAIN
# =============================================================================

function Main {
    Clear-Host
    Write-Host ""
    Write-Host "+================================================================+" -ForegroundColor Cyan
    Write-Host "|        HomeLab SOC v2 - Infrastructure Collection              |" -ForegroundColor Cyan
    Write-Host "|                                                                |" -ForegroundColor Cyan
    Write-Host "|  Collecting from: QNAP, GCP VM, Proxmox, SOC-Automation        |" -ForegroundColor Cyan
    Write-Host "|  Syncing to: GitHub repo + Astro website                       |" -ForegroundColor Cyan
    Write-Host "+================================================================+" -ForegroundColor Cyan
    Write-Host ""
    
    if ($DryRun) {
        Write-Status "DRY RUN MODE - No files will be copied" -Type Warning
        Write-Host ""
    }
    
    # Create staging directory
    New-Item -ItemType Directory -Path $Config.StagingDir -Force | Out-Null
    
    try {
        # Collect from sources
        if ($QnapOnly) {
            Get-QnapFiles | Out-Null
            Get-SocAutomationFiles | Out-Null  # Always include with QNAP
        }
        elseif ($GcpOnly) {
            Get-GcpFiles | Out-Null
        }
        else {
            Get-QnapFiles | Out-Null
            Get-SocAutomationFiles | Out-Null  # NEW: Collect ML scorer + automation
            Get-GcpFiles | Out-Null
            Get-ProxmoxFiles | Out-Null
        }
        
        if (-not $DryRun) {
            # Sync to repos
            Sync-ToGitHubRepo | Out-Null
            Sync-ToAstroRepo | Out-Null
        }
        
        # Report
        Show-Summary
        
        if (-not $DryRun) {
            Show-GitStatus
        }
        
        Write-Section "Done!"
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Yellow
        Write-Host "  1. Review: cd $($Config.GitHubRepo); git diff" -ForegroundColor Gray
        Write-Host "  2. Commit: git add -A && git commit -m 'Sync from infrastructure'" -ForegroundColor Gray
        Write-Host "  3. Push:   git push" -ForegroundColor Gray
        Write-Host ""
    }
    finally {
        # Cleanup
        if (Test-Path $Config.StagingDir) {
            Remove-Item -Path $Config.StagingDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Run
Main
