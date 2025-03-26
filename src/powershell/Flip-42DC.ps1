# Flip-42DC.ps1

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# Global Logging Variables
$global:LogDir  = "C:\gh\setupdc2k5\logs"
$global:LogFile = Join-Path $global:LogDir "flip-42dc-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Ensure log directory exists
if (-not (Test-Path $global:LogDir)) {
    New-Item -Path $global:LogDir -ItemType Directory -Force | Out-Null
}

# Dot-source the functions using an absolute path for debugging
$functionsPath = "C:\gh\setupdc2k5\src\powershell\DCFunctions.ps1"
Write-Host "Attempting to dot-source: $functionsPath"
if (-not (Test-Path $functionsPath)) {
    Write-Host "ERROR: DCFunctions.ps1 not found at $functionsPath" -ForegroundColor Red
    exit 1
}
try {
    . $functionsPath
    Write-Host "Dot-sourcing completed successfully."
}
catch {
    Write-Host "ERROR: Failed to dot-source DCFunctions.ps1. Error: $_" -ForegroundColor Red
    Write-Log "ERROR: Failed to dot-source DCFunctions.ps1. Error: $_"
    exit 1
}

# --- Start of Main Script ---
Write-Log "Starting Flip-42DC.ps1..."

function Test-PendingReboot {
    [CmdletBinding()]
    param()

    [bool]$pendingReboot = $false

    try {
        # Check for pending reboot in the registry (Component Based Servicing)
        $cbsReboot = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" -Name "RebootPending" -ErrorAction SilentlyContinue
        if ($cbsReboot) {
            $pendingReboot = $true
        }

        # Check for pending Windows Update reboot
        $wuReboot = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "RebootRequired" -ErrorAction SilentlyContinue
        if ($wuReboot) {
            $pendingReboot = $true
        }

        # Check for pending file rename operations
        $fileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($fileRename) {
            $pendingReboot = $true
        }
    }
    catch {
        Write-Log "ERROR: Failed to check for pending reboot. Error: $_"
        $pendingReboot = $false
    }

    return $pendingReboot
}

function Show-Menu {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory)]
    [bool]$PendingReboot
)

    Write-Host "Grok what is up with his Pending Reboot var?! $PendingReboot" -ForegroundColor Red

    if ($PendingReboot) {
        Write-Host "`n⚠️  SYSTEM REQUIRES REBOOT - Some operations may fail!" -ForegroundColor Red
        Write-Host "    Consider rebooting before proceeding.`n"
    }

    $role = Get-SystemRole
    Write-Host "🖥️  Current System Role: $role"
    Write-Host "1. Install Domain Controller"
    Write-Host "2. Uninstall Domain Controller"
    Write-Host "3. Enable Schema Modifications"
    Write-Host "4. Restore Administrator Profile"
    Write-Host "5. Extend Schema from CSV"
    Write-Host "6. Exit"
    $choice = Read-Host "Enter choice (1-6)"
    return $choice
}


while ($true) {
    # Check for pending reboot at the start of each loop iteration
    $pendingReboot = Test-PendingReboot

    $choice = Show-Menu -PendingReboot $pendingReboot
    switch ($choice) {
        "1" {
            if ($pendingReboot) {
                Write-Host "❌ Cannot install Domain Controller: A reboot is pending." -ForegroundColor Red
                Write-Log "❌ Attempted to install DC, but a reboot is pending."
                continue
            }
            if ((Get-SystemRole) -eq "DomainController") {
                Write-Host "❌ System is already a Domain Controller."
                Write-Log "❌ Attempted to install DC, but system is already a DC."
                continue
            }

            $domainName      = Read-Host "Enter the FQDN for the new domain (e.g., mlb.dev)"
            $safeModePassword = Get-SecurePassword -Prompt "Enter the Safe Mode Administrator Password"
            Install-42DomainController -DomainName $domainName -SafeModePassword $safeModePassword
            break
        }
        "2" {
            if ($pendingReboot) {
                Write-Host "❌ Cannot uninstall Domain Controller: A reboot is pending." -ForegroundColor Red
                Write-Log "❌ Attempted to uninstall DC, but a reboot is pending."
                continue
            }
            if ((Get-SystemRole) -ne "DomainController") {
                Write-Host "❌ System is not a Domain Controller."
                Write-Log "❌ Attempted to uninstall DC, but system is not a DC."
                continue
            }

            $localAdminPassword = Get-SecurePassword -Prompt "Enter the Local Administrator Password"
            Uninstall-42DomainController -LocalAdminPassword $localAdminPassword
            break
        }
        "3" {
            if ($pendingReboot) {
                Write-Host "❌ Cannot enable schema modifications: A reboot is pending." -ForegroundColor Red
                Write-Log "❌ Attempted to enable schema modifications, but a reboot is pending."
                continue
            }
            Enable-SchemaModifications
        }
        "4" {
            if ($pendingReboot) {
                Write-Host "❌ Cannot restore Administrator profile: A reboot is pending." -ForegroundColor Red
                Write-Log "❌ Attempted to restore Administrator profile, but a reboot is pending."
                continue
            }
            Restore-42AdminProfile
        }
        "5" {
            if ($pendingReboot) {
                Write-Host "❌ Cannot extend schema from CSV: A reboot is pending." -ForegroundColor Red
                Write-Log "❌ Attempted to extend schema from CSV, but a reboot is pending."
                continue
            }
            $csvPath = Read-Host "Enter the path to the schema CSV file (e.g., data/schema.csv)"
            Extend-SchemaFromCSV -CsvPath $csvPath
        }
        "6" {
            Write-Log "Exiting Flip-42DC.ps1..."
            exit
        }
        default {
            Write-Host "❌ Invalid choice. Please select 1-6."
            Write-Log "❌ Invalid menu choice: $choice"
        }
    }
}